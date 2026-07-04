# AI-CodeGuard 规则系统说明

> 本文档描述的是 **当前代码库里已经存在的规则系统**，并明确区分“当前已交付能力”和“仍未实现的语义 / 数据流能力边界”。

## 1. 当前规则系统范围

当前 AI-CodeGuard 的规则系统具备以下事实：

- 规则来源：**13 条 TypeScript 内置规则 + 可选 YAML custom rules**
- custom rules 入口：`rules.custom`
- 命令入口：`rules --list`、`rules validate <path>`、`rules create <file>`、`rules test <rulesPath> [paths...]`
- `rules --list` 当前**只列出 built-in rules**
- `rules validate` 负责校验 YAML 解析、schema 与 duplicate ID
- `rules create` 负责生成最小可用 rule scaffold，支持 `--force`
- `rules test` 复用 `scan()` 主流程，以 **Stage 1-only** 方式验证 custom rules
- 运行方式：`scan()` 中先加载规则，再对 Tree-sitter 归一化 ASTree 执行逐节点检查
- 支持语言：JavaScript / TypeScript / Python

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
- `preset = owasp-top-10`：当前返回全部 13 条 built-in rules
- `preset = all`：当前也返回全部 13 条 built-in rules
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

当前没有：

- 污点传播（taint tracking）
- 跨文件符号解析
- CFG / 数据流 / 类型系统支持

## 5. 当前内置规则清单

| 规则 ID | 名称 | 严重级别 | 语言 | 当前核心检测信号 |
|---------|------|----------|------|------------------|
| `CG-001` | SQL Injection | critical | JS / TS / Python / Go | `query` / `execute` / `raw` / `exec` / `prepare` 等数据库调用，且参数中存在模板字符串或字符串拼接；Go 侧匹配 `db.Query/Exec/Prepare*` 的拼接或 `fmt.Sprintf` 组装，以及组装 SQL 的 `fmt.Sprintf` 本身 |
| `CG-002` | Command Injection | critical | JS / TS / Python / Go | `exec` / `spawn` / `system` / `subprocess` 等命令执行调用，且参数带动态拼接；Go 侧匹配 `exec.Command(Context)` 的字符串拼接或 `fmt.Sprintf` |
| `CG-003` | Code Injection (eval) | critical | JS / TS / Python | `eval` / `Function` / `setTimeout` / `setInterval` 等危险调用 |
| `CG-010` | Cross-Site Scripting (XSS) | high | JS / TS | `innerHTML` / `outerHTML` / `document.write` / `insertAdjacentHTML` |
| `CG-011` | DOM-based XSS | high | JS / TS | 同一节点同时包含 DOM source 与 sink |
| `CG-020` | Hardcoded Credentials | high | JS / TS / Python / Go | `password` / `secret` / `token` / `api_key` 等敏感赋值模式；Go 侧覆盖 `:=` / `var` / `const` 字面量赋值 |
| `CG-021` | Weak Cryptography | medium | JS / TS / Python | `md5` / `sha1` / `des` / `rc4` / `md4` 等弱算法 |
| `CG-030` | Path Traversal | high | JS / TS / Python / Go | 文件路径操作 + 动态路径拼接；Go 侧匹配 `os` / `ioutil` 文件函数的拼接或 `fmt.Sprintf` 路径 |
| `CG-031` | Arbitrary File Read/Write | high | JS / TS / Python | `readFile` / `writeFile` / `open` 等操作直接引用 `req` / `params` / `query` / `args` |
| `CG-040` | Sensitive Data Exposure | medium | JS / TS / Python | 日志调用中出现 `password` / `token` / `secret` / PII 模式 |
| `CG-041` | Insecure Deserialization | high | JS / TS / Python | `deserialize` / `unserialize` / `pickle.loads` / `yaml.load` |
| `CG-050` | Security Misconfiguration | medium | JS / TS / Python | CORS `*`、`secure: false`、`httpOnly: false`、`verify=False` 等配置模式 |
| `CG-060` | Server-Side Request Forgery (SSRF) | high | JS / TS / Python / Go | HTTP 请求 URL 来自动态拼接或明显用户输入；Go 侧匹配 `http.*` 调用的拼接或 `fmt.Sprintf` URL |

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
- `languages`: `javascript` / `typescript` / `python`

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

1. **Go 支持是 MVP 范围**
   - `CG-001` / `CG-002` / `CG-020` / `CG-030` / `CG-060` 共 5 条规则覆盖 Go；其余 8 条不在 `.go` 文件上运行。
   - Stage 1 无数据流分析：`query := fmt.Sprintf(...)` 两步写法靠 “Sprintf 组装 SQL” 启发式命中；内联 `db.Query(fmt.Sprintf(...))` 会同时报外层调用与内层 Sprintf 两条。
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
