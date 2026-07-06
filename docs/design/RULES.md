# AI-CodeGuard 规则系统说明

> 本文档描述的是 **当前代码库里已经存在的规则系统**，并明确区分“当前已交付能力”和“仍未实现的语义 / 数据流能力边界”。

## 1. 当前规则系统范围

当前 AI-CodeGuard 的规则系统具备以下事实：

- 规则来源：**18 条 TypeScript 内置规则 + 可选 YAML custom rules**
- custom rules 入口：`rules.custom`
- 命令入口：`rules --list`、`rules validate <path>`、`rules create <file>`、`rules test <rulesPath> [paths...]`
- `rules --list` 当前**只列出 built-in rules**
- `rules validate` 负责校验 YAML 解析、schema 与 duplicate ID
- `rules create` 负责生成最小可用 rule scaffold，支持 `--force`
- `rules test` 复用 `scan()` 主流程，以 **Stage 1-only** 方式验证 custom rules
- 运行方式：`scan()` 中先加载规则，再对 Tree-sitter 归一化 ASTree 执行逐节点检查
- 支持语言：JavaScript / TypeScript（全部 18 条规则）/ Python（17 条，仅缺 `CG-011` DOM XSS）/ Go（12 条）/ Java（14 条）/ PHP（16 条，详见第 9 节）

当前**尚未实现**：

- 污点传播（taint tracking）
- 跨文件符号解析 / CFG / 数据流分析

## 2. 当前执行流程

当前规则执行链路如下：

```text
scan()
  ├─ loadRules({ preset, custom, disable })
  │    ├─ getRules() 选择 built-in rules
  │    ├─ loadCustomRules() 加载 YAML custom rules（可选）
  │    └─ disable 按 rule ID 过滤合并结果
  ├─ parse(source, language)
  ├─ runRules(tree, rules, file)
  │    ├─ 根据 language 过滤适用规则
  │    ├─ walkAST() 深度优先遍历节点
  │    ├─ rule.check(node, ctx)
  │    └─ 按 ruleId + 行列做去重
  └─ SuspiciousNode[] -> Finding[]
```

### 2.1 `loadRules()` 当前行为

- `preset = none`：不加载 built-in rules
- `preset = owasp-top-10`：当前返回全部 18 条 built-in rules
- `preset = all`：当前也返回全部 18 条 built-in rules
- `custom`：可指向 **单个 YAML 文件**或**目录**
- `custom` 指向目录时：递归加载其中的 `*.yml` / `*.yaml`
- `disable = ['CG-050']`：对 **built-in + custom** 合并后的规则统一按 rule ID 过滤
- `preset: none` + `custom`：可作为“只跑 custom rules”的最小工作流

### 2.2 当前 fail-fast 行为

当 custom rules 存在以下问题时，扫描会直接报错，而不是静默跳过：

- `rules.custom` 路径不存在
- YAML 解析失败
- schema 校验失败
- custom rule ID 与 built-in rule ID 重复
- 同一批 custom rules 内部出现重复 ID

## 3. 当前规则运行依赖的节点模型

规则当前运行在 Tree-sitter 解析后生成的归一化节点上。核心节点类型有：

- `function_call`
- `template_string`
- `string_concat`
- `assignment`
- `unknown`（program root）

custom rules 当前也共享这一能力边界，因此它们：

- 更擅长发现**明显的危险调用与危险字符串拼接**
- 不擅长复杂的跨函数、跨文件、跨多行数据流分析

## 4. 规则上下文（RuleCheckContext）

每条规则当前都能使用以下上下文能力：

- `getSnippet(node)`：获取当前节点文本
- `getContext(node, lines)`：取上下文代码片段
- `extractCallInfo(node)`：提取调用名、对象、参数、完整表达式
- `wasAssignedFrom(varName, sourcePattern, node, lines?)`：轻量级同名变量赋值关联 —— 在 `node` 前后若干行的文本里找 `varName = <rhs>`（或 Go 的 `:=`），只把 `sourcePattern` 与该赋值的右侧文本比对（不是整个上下文窗口，避免上下文里无关位置出现同一模式造成误报）。**这不是真正的数据流分析**：解析层产出的是扁平节点列表而非嵌套 AST（见第 2 节），没有函数作用域、没有变量遮蔽处理、也不跨多跳传播 —— 只是把"两步式"模式（先赋值、再在附近调用）的文本相关性检测标准化成一个可复用、可测试的工具，而不是每条规则各写一份临时正则。CG-010（Java 的 `PrintWriter out = response.getWriter(); out.println(...)`）与 CG-031（如 `path := r.URL.Query()...; os.Open(path)`）已经用上它。

当前没有：

- 真正的污点传播（跨函数、跨多跳的数据流追踪）
- 跨文件符号解析
- CFG / 类型系统支持

### 4.1 按语言分支的收敛

`path.ts`（CG-030/CG-031）、`auth.ts`（CG-021/CG-022）、`data.ts`（CG-040）、`redos.ts`（CG-023）已经把原本 `if (ctx.language === 'go') {...} else if (ctx.language === 'java') {...} else {...}` 形态的分支，改成了 `Partial<Record<Language, (call: CallInfo) => boolean>>` 形式的按语言查表：新增一门语言的匹配逻辑只需要在表里加一条 entry，而不是在多处 if/else-if 链里插入分支。`check()` 本身收窄成一次表查找 + 调用匹配函数。`redirect.ts`（CG-025）是直接以这个查表模式实现的，不是后期转换过来的。

`xss.ts`（CG-010）和 `injection.ts`（CG-001/002/003）**有意保留**原本的 if/else 结构：
- CG-010 的 JS/TS 分支和 Python/Java 分支要求的节点类型完全不同（前者是任意文本节点上的子串匹配，后者要求 `function_call` 节点 + `extractCallInfo`），勉强套进同一张查表反而会让两种检测策略的差异变得含糊。
- `injection.ts` 每个语言分支除了"匹配调用"之外还有额外的语义步骤（两步式 `Sprintf`/`String.format` 组装检测、消毒模式排除等），不是单纯的"按语言选一个谓词"，硬套查表收益有限、回归风险更高。

## 5. 当前内置规则清单

| 规则 ID | 名称 | 严重级别 | 语言 | 当前核心检测信号 |
|---------|------|----------|------|------------------|
| `CG-001` | SQL Injection | critical | JS / TS / Python / Go / Java / PHP | `query` / `execute` / `raw` / `exec` / `prepare` 等数据库调用，且参数中存在模板字符串或字符串拼接；Go 侧匹配 `db.Query/Exec/Prepare*` 的拼接或 `fmt.Sprintf` 组装，以及组装 SQL 的 `fmt.Sprintf` 本身；Java 侧匹配 `executeQuery/executeUpdate/prepareStatement` 等的拼接或 `String.format`，以及组装 SQL 的 `String.format` 本身；PHP 侧匹配 `mysqli_query` 等裸函数与 `->query/exec/prepare`（PDO/mysqli 对象）或 `Class::query`（如 Laravel `DB::query`）等方法调用的拼接或插值字符串——要求实际拼接/插值，不靠关键字嗅探，因为 `$pdo->prepare("... WHERE id = ?")` 这种仅含占位符的字面量是 PDO 惯用安全写法 |
| `CG-002` | Command Injection | critical | JS / TS / Python / Go / Java / PHP | `exec` / `spawn` / `system` / `subprocess` 等命令执行调用，且参数带动态拼接；Go 侧匹配 `exec.Command(Context)` 的字符串拼接或 `fmt.Sprintf`；Java 侧匹配 `Runtime.getRuntime().exec` / `new ProcessBuilder` 的拼接或 `String.format`；PHP 侧 `exec`/`system`/`popen` 与其他语言共享的函数名列表天然覆盖，另加 `shell_exec`/`passthru`/`proc_open` |
| `CG-003` | Code Injection (eval) | critical | JS / TS / Python / PHP | `eval` / `Function` / `setTimeout` / `setInterval` 等危险调用；PHP 的 `eval()` 在 tree-sitter-php 语法中就是普通函数调用节点，复用同一份 `EVAL_FUNCTIONS` 列表即可命中 |
| `CG-024` | NoSQL Injection | high | JS / TS / Python / PHP | MongoDB CRUD 方法（`find`/`findOne`/`updateOne`/`deleteOne`/... ；Python 侧对应 pymongo 的 snake_case 命名 `find_one`/`update_one`/...）传入**整个**请求对象作为过滤/更新文档（如 `users.find(req.body)`）——攻击者可以提交查询操作符（`$ne`/`$gt`等）而非普通值，从而绕过如密码校验之类的过滤条件；传入请求对象的某个具体字段（如 `req.body.username`）是普通字符串值，不属于这个风险，因此只有"整个对象被直接传入"（而非其某个属性）才会命中；另外检测用字符串拼接/模板字符串动态构造的 `$where` 子句（在 MongoDB 内部以 JavaScript 求值，等价于 CG-003 的 NoSQL 版本）；Go/Java 未覆盖，因为它们的驱动 API 类型更严格，没有"直接传裸对象"这种清晰对等的调用形态 |
| `CG-010` | Cross-Site Scripting (XSS) | high | JS / TS / Python / Java | `innerHTML` / `outerHTML` / `document.write` / `insertAdjacentHTML`；Python 侧匹配 `mark_safe`/`Markup`/`render_template_string` 传入非纯字面量参数（纯字符串字面量视为安全）；Java 侧匹配 `response.getWriter().write/print/println` 传入非纯字面量参数 |
| `CG-011` | DOM-based XSS | high | JS / TS | 同一节点同时包含 DOM source 与 sink |
| `CG-020` | Hardcoded Credentials | high | JS / TS / Python / Go / Java / PHP | `password` / `secret` / `token` / `api_key` 等敏感赋值模式；Go 侧覆盖 `:=` / `var` / `const` 字面量赋值；Java 侧覆盖字段与局部变量字面量赋值；PHP 的 `assignment_expression` 与 JS/TS 共用同一归一化分支，无需额外代码 |
| `CG-021` | Weak Cryptography | medium | JS / TS / Python / Go / Java / PHP | `md5` / `sha1` / `des` / `rc4` / `md4` 等弱算法；Go 侧匹配 `crypto/md5|sha1|des|rc4` 包本身（包名即信号，不看具体方法）；Java 侧匹配 `MessageDigest`/`Cipher.getInstance(...)` 传入弱算法字符串（`sha256` 等强算法不命中）；PHP 侧匹配裸函数 `md5()`/`sha1()`（无参数即弱信号）或 `hash()` 传入弱算法字符串 |
| `CG-022` | Insecure Randomness | medium | JS / TS / Python / Go / Java / PHP | 非密码学 PRNG（`Math.random`、Python `random` 模块、Go `math/rand`、`java.util.Random`、PHP `rand`/`mt_rand`）用于生成 token/session/password 等安全敏感值；由于 Stage 1 无数据流分析，通过调用点前后 3 行文本中是否出现 `token`/`session`/`password`/`secret`/`otp`/`api_key`/`reset`/`nonce`/`csrf` 等关键词来推断意图（不加 `\b` 边界，因为关键词通常嵌在 camelCase 标识符里，如 `generateSessionID`）；`crypto.randomBytes`/Python `secrets`/`crypto/rand`/`SecureRandom`/PHP `random_bytes`/`random_int` 等安全替代不命中 |
| `CG-023` | Insecure Regular Expression (ReDoS) | medium | JS / TS / Python / Go / Java / PHP | 正则表达式模式中出现嵌套/重叠量词（如 `(a+)+`、`(a*)*`），是灾难性回溯的经典信号；这是对正则文本本身的语法启发式检测，不是完整的 NFA/回溯复杂度分析，只覆盖这一种（现实中很常见的）形态；Python 侧限定 `re.` 接收者（避免与字符串的裸 `.split()`/`.match()` 等同名方法混淆）；Java 侧限定 `Pattern.compile(...)`；Go 侧限定 `regexp.` 接收者；PHP 侧匹配裸函数 `preg_match`/`preg_match_all`/`preg_replace`/`preg_split` |
| `CG-025` | Open Redirect | medium | JS / TS / Python / Go / Java / PHP | 重定向目标由未校验的用户输入构成，可用于钓鱼；JS/TS 侧匹配 `res`/`response`/`reply`/`ctx` 接收者上的 `.redirect(...)`；Python 侧匹配裸函数 `redirect`/`HttpResponseRedirect`/`HttpResponsePermanentRedirect`（Flask/Django）；Go 侧匹配 `http.Redirect(...)`；Java 侧匹配 `response.sendRedirect(...)`（方法名本身信号足够明确，无需限定接收者）；PHP 侧匹配 `header(...)` 调用且参数实际包含 `Location:`（`header()` 用途很广，需要这个额外限定避免误报） |
| `CG-026` | JWT Signature Bypass | critical | JS / TS / Python / PHP | JWT 校验被配置为接受 `"none"` 算法（`algorithms: ['none']`，等价于彻底关闭签名校验——攻击者可任意伪造 token）或显式关闭签名校验（Python PyJWT 的 `verify_signature: False`）；PHP 侧限定 `JWT::decode(...)`（firebase/php-jwt）传入的算法白名单里包含 `'none'`，因为 PHP 的 `algorithms` 是位置参数而非具名选项，需要额外限定调用点避免误报；Go/Java 未覆盖，因为常见 JWT 库的调用形态没有同样清晰、低误报的文本信号 |
| `CG-030` | Path Traversal | high | JS / TS / Python / Go / Java / PHP | 文件路径操作 + 动态路径拼接；Go 侧匹配 `os` / `ioutil` 文件函数的拼接或 `fmt.Sprintf` 路径；Java 侧匹配 `new File/FileInputStream/...` 构造器与 `Files`/`Paths` 静态方法的拼接或 `String.format` 路径，`normalize()`/`getCanonicalPath()` + `startsWith` 视为已消毒；PHP 侧匹配 `file_get_contents`/`file_put_contents`/`fopen`/`readfile` 等全局函数（PHP 无接收者，类似 Python）的拼接或插值路径 |
| `CG-031` | Arbitrary File Read/Write | high | JS / TS / Python / Go / Java / PHP | `readFile` / `writeFile` / `open` 等操作直接引用 `req` / `params` / `query` / `args`；Go 侧匹配 `os.Open/OpenFile/Create/ReadFile/WriteFile` 引用 `r.URL.Query`/`r.FormValue`/`mux.Vars`/`os.Args` 等；Java 侧匹配 `new File(...)` 或 `Files`/`Paths` 静态方法引用 `getParameter`/`getHeader`/`getQueryString`；PHP 侧匹配 `file_get_contents`/`file_put_contents`/`fopen`/`readfile` 引用 `$_GET`/`$_POST`/`$_REQUEST`/`$_COOKIE` |
| `CG-040` | Sensitive Data Exposure | medium | JS / TS / Python / Go / Java / PHP | 日志调用中出现 `password` / `token` / `secret` / PII 模式；Go 侧匹配 `log`/`logrus`/`zap`/`zerolog` 等对象的日志方法；Java 侧匹配 `logger`/`log`/`System.out`/`System.err` 的日志方法；PHP 侧匹配 `error_log`/`syslog` 裸函数或 `log`/`logger` 接收者（如 Laravel `Log::`、Monolog `$logger->`）的日志方法 |
| `CG-041` | Insecure Deserialization | high | JS / TS / Python / Java / PHP | `deserialize` / `unserialize` / `pickle.loads` / `yaml.load`；Java 侧匹配 `readObject()` 方法调用（`ObjectInputStream`/`XMLDecoder` 经典 gadget-chain 入口，方法名本身信号足够明确，无需限定接收者）；PHP 侧裸函数 `unserialize()` 与既有 `DESER_FUNCTIONS_JS` 名单共用同一分支命中（PHP 经典对象注入 gadget-chain 入口）；Go 无清晰对等写法，暂不覆盖 |
| `CG-050` | Security Misconfiguration | medium | JS / TS / Python / Go / Java / PHP | CORS `*`、`secure: false`、`httpOnly: false`、`verify=False` 等配置模式；Go 侧新增 `InsecureSkipVerify: true`（`tls.Config` 结构体字面量，Stage 1 已扩展归一化层专门识别 Go `composite_literal` 节点以支持此匹配）；Java 侧新增 Spring `.csrf().disable()`、`.allowedOrigins("*")`、`setSecure(false)`、`setHttpOnly(false)`；PHP 侧新增 `CURLOPT_SSL_VERIFYPEER/VERIFYHOST` 禁用与 `display_errors` 开启 |
| `CG-060` | Server-Side Request Forgery (SSRF) | high | JS / TS / Python / Go / Java / PHP | HTTP 请求 URL 来自动态拼接或明显用户输入；Go 侧匹配 `http.*` 调用的拼接或 `fmt.Sprintf` URL；Java 侧匹配 `new URL/HttpGet/HttpPost/...`、`URI.create` 与 RestTemplate 风格方法（`getForObject`/`exchange` 等）的拼接或 `String.format` URL；PHP 侧匹配裸函数 `curl_init`（最常见的 PHP SSRF 信号）的拼接或插值 URL |

## 6. 当前 custom rules 运行时形态

### 6.1 配置入口

```yaml
rules:
  preset: none
  custom: ./custom-rules
```

### 6.2 当前支持的文件形态

custom rule 文件当前支持三种 YAML 形态：

1. **单条规则对象**
2. **规则数组**
3. **带 `rules:` 顶层键的对象**

例如：

```yaml
id: CG-CUSTOM-001
name: Dynamic fetch URL
severity: high
category: ssrf
languages: [javascript, typescript]
description: Detect dynamic fetch URLs
patterns:
  - type: function_call
    function:
      match: [fetch]
    arguments:
      - type: template_string
```

### 6.3 当前字段要求

每条 custom rule 当前要求：

- `id`
- `name`
- `severity`
- `category`
- `languages`
- `description`
- `patterns`
- `exclude`（可选）

当前枚举边界：

- `severity`: `critical` / `high` / `medium` / `low`
- `category`: `injection` / `xss` / `auth` / `path` / `data` / `config` / `ssrf`
- `languages`: `javascript` / `typescript` / `python` / `go` / `java` / `php`

## 7. 当前支持的 pattern 子集

当前 custom rules 不是任意 DSL，而是建立在现有归一化 AST 能力上的最小匹配子集。

### 7.1 `pattern.type`

可匹配以下节点类型：

- `function_call`
- `string_concat`
- `template_string`
- `assignment`
- `import`
- `function_def`
- `class_def`
- `binary_op`
- `member_access`
- `identifier`
- `literal`
- `unknown`

### 7.2 `pattern.function`

```yaml
patterns:
  - type: function_call
    function:
      match: [query, execute]
      on: [db, pool]
```

当前语义：

- `match`：按 `extractCallInfo(node).name` 精确匹配调用名
- `on`：按调用对象匹配；当前实现允许**完全匹配**或**包含目标子串**

### 7.3 `pattern.arguments`

```yaml
patterns:
  - function:
      match: [query]
    arguments:
      - type: template_string
      - type: string_concat
```

当前语义：

- 只对 `function_call` 生效
- 每个 argument pattern 都要求在 `node.children` 里找到一个匹配节点
- **不是位置敏感匹配**，更像“调用里至少出现过这些参数形态”

### 7.4 `pattern.operator`

当前只对 `string_concat` 有意义。

```yaml
patterns:
  - type: string_concat
    operator: "+"
```

### 7.5 `pattern.hasExpressions`

当前主要用于区分是否包含动态表达式：

- `template_string`
- `string_concat`
- `function_call`（递归看其子节点）

### 7.6 `exclude`

`exclude` 与 `patterns` 共享同一套匹配语义。

- 命中 `patterns`
- 同时命中 `exclude`
- 则最终**不报**

## 8. 当前规则相关配置

当前真正影响运行时的字段有：

```yaml
rules:
  preset: owasp-top-10
  custom: ./custom-rules
  disable:
    - CG-050
    - CG-CUSTOM-001
```

含义：

- `preset` 控制 built-in rules 是否启用
- `custom` 控制是否加载 YAML custom rules
- `disable` 对 built-in 和 custom 统一按 rule ID 生效

## 9. 当前限制

当前规则系统最重要的限制有：

1. **Go / Java / PHP 覆盖范围**
   - Go 支持 `CG-001` / `CG-002` / `CG-020` / `CG-021` / `CG-022` / `CG-023` / `CG-025` / `CG-030` / `CG-031` / `CG-040` / `CG-050` / `CG-060` 共 12 条；Java 在此基础上再加 `CG-010` / `CG-041` 共 14 条；PHP 在 Go 的基础上再加 `CG-003` / `CG-024` / `CG-026` / `CG-041` 共 16 条。`CG-011`（DOM-based XSS）仍是 JS/TS 独有，因为它需要浏览器 DOM 环境；`CG-024`（NoSQL 注入）与 `CG-026`（JWT 签名绕过）只覆盖 JS/TS/Python/PHP，因为它们针对的分别是 MongoDB 驱动、常见 JWT 库特定的调用形态，Go/Java 没有清晰、低误报的对等模式。
   - Stage 1 无数据流分析：`query := fmt.Sprintf(...)` 两步写法靠 “Sprintf 组装 SQL” 启发式命中。内联嵌套时（如 `db.Query(fmt.Sprintf(...))`、嵌套的 Go struct 字面量 `tls.Config` 嵌在 `http.Transport` 里）同一条规则本会同时命中外层与内层调用；`runRules()` 现在会在同一文件内、同一 ruleId 下，抑制完全被另一条命中"包含"的内层重复项，只保留外层这条更完整的 finding——不影响真正的两步模式（Sprintf 与 Query 是两条独立语句，不构成嵌套）。
2. **`rules test` 是 Stage 1-only smoke path**
   - 用于验证 custom rules 命中情况，不覆盖 Stage 2。
3. **custom rules 仍受限于当前归一化 AST 能力**
   - 不是完整语义分析，也不是污点分析。
4. **`rules.custom` 路径按当前工作目录解析**
   - 当前实现不会自动按配置文件所在目录重写路径。
5. **`preset` 语义仍较粗**
   - `owasp-top-10` 与 `all` 目前等价。

## 10. 后续补强建议

如果继续扩展规则系统，最合理的顺序是：

1. **继续增强 custom rules 的单元 / 集成测试**
2. **继续增强 `rules validate/create/test` 的错误提示与示例**
3. **继续增强 Tree-sitter 归一化层与规则上下文能力**
4. **在规则基础更稳后，再考虑更强的数据流与语义能力**

这样可以先稳住当前已接线 runtime，再继续扩展规则表达与产品化能力。
