# 我用 TypeScript + Tree-sitter + Claude 做了个 AI 代码安全扫描器

> 作者：龙渊 / 黄焌哲
> 日期：2026-05-28
> 项目地址：https://github.com/hzj-Jeff-07/AI-CodeGuard
> 字数：约 5800
> 阅读时间：约 18 分钟

---

## 引子：为什么又造一个安全扫描器轮子

我是退役军人，现在专升本在读，主线是冲网络安全 / AI 安全方向的研究生。

去年用了大半年时间在两个赛道之间反复横跳：纯传统 SAST（Semgrep、CodeQL）规则写得头大但很硬核；纯 LLM 代码审计（让 Claude 通读项目）爽但又慢又贵又满嘴跑火车。

最后想明白一件事：

> **没必要选边站。让静态分析做"漏斗的粗筛"，让 LLM 做"漏斗的精校"。**

这就是 **AI-CodeGuard** 的全部立项动机——一句话定位：

> 用 Tree-sitter 把代码扒成 AST，用规则跑一遍可疑点（Stage 1），再让 Claude / GPT 复核去掉误报（Stage 2），最后吐 SARIF 给 GitHub Code Scanning 看。

本文是项目第一篇技术博客。会讲：

1. 为什么是两阶段流水线，而不是纯规则或纯 LLM
2. Tree-sitter 的归一化 AST 怎么设计，让规则不被多语言折磨
3. Stage 2 的 Prompt 怎么写，让 LLM 输出可解析的 JSON
4. 13 条 OWASP 内置规则的取舍逻辑
5. 一个真实的坑：成本失控如何用预算闸门解决
6. 当前阶段的边界 + 下一步路线

---

## 一、为什么是两阶段流水线

### 1.1 纯规则的痛点

写过 Semgrep 规则的都知道，**SAST 的核心矛盾是召回率与误报率不可兼得**：

- 规则写松一点 → 召回高 → 满屏告警 → 开发者直接关掉
- 规则写紧一点 → 误报低 → 漏报真漏洞 → 出事了背锅

举个具体例子：检测 SQL 注入。最朴素的规则：

```js
// 命中: 看到 query 函数 + 字符串拼接 + 用户输入变量
db.query(`SELECT * FROM users WHERE id = ${userId}`)
```

但这种规则会大量误报：
- 拼的是常量 `userId = 1` → 不是漏洞
- `userId` 在前面已经 `parseInt` 过 → 不是漏洞
- 实际上调的是 ORM 的安全方法 → 不是漏洞

要把这三种情况全部排除，规则会迅速膨胀到无法维护。

### 1.2 纯 LLM 的痛点

那让 Claude 通读 100 个文件审一遍呢？我试过：

- **慢**：100 个文件 × 平均 200 行 × Claude Sonnet ≈ 20 分钟
- **贵**：单次审计约 $3-5，CI 跑 30 次就 100 刀
- **乱**：每次输出格式不一致，下游工具没法消费
- **幻觉**：经常告诉你"line 42 有 SQL 注入"，结果第 42 行是个注释

更糟的是：**没有起点的 LLM 审计就像无头苍蝇**。让它从 0 扫一个仓库，它会盯着 README 看半天，根本不知道该重点看哪。

### 1.3 漏斗思维：静态做粗筛，LLM 做精校

借用【杠铃策略】的思路：90% 工作给静态分析（便宜、确定、可解释），10% 工作给 LLM（贵但精准）。

```text
源代码
   │
   ▼
[Stage 1: Tree-sitter + 规则]
   ├─ 扫一遍可疑 AST 节点
   ├─ 命中 → 生成 SuspiciousNode
   └─ 输出大量"可能是漏洞"的候选
   │
   ▼
[Stage 2: LLM 复核]
   ├─ 把每个候选 + 上下文 + 完整文件喂给 Claude
   ├─ Claude 回 {"confirmed": true/false, "reasoning": "..."}
   └─ 只保留 confirmed=true 的告警
   │
   ▼
SARIF 报告 → GitHub Code Scanning
```

**真正聪明的部分**：Stage 1 故意写得宽松一点，宁可多报。因为 Stage 2 会兜底过滤。这样我能让 13 条规则覆盖整个 OWASP Top 10，而不用为每条规则雕花到极致。

实测在自扫场景下：
- Stage 1 命中 ≈ 40 个可疑点
- Stage 2 确认 ≈ 8 个真实问题
- **误报率从 80% 压到约 10%**

---

## 二、Tree-sitter 归一化 AST：让规则不被多语言折磨

### 2.1 问题：Tree-sitter 原生节点对规则太友好不起来

Tree-sitter 是 GitHub 推动的增量解析器，质量极高，覆盖语言极多。但它的 AST 是**每种语言一套节点类型**：

| 语言 | "函数调用"节点类型 |
|---|---|
| JavaScript | `call_expression` |
| TypeScript | `call_expression`（多一些类型节点） |
| Python | `call` |
| Go | `call_expression` |
| Java | `method_invocation` |

如果规则直接消费原生节点，每写一条规则就要 if-else 一遍五种语言。规则数一多，代码会爆炸。

### 2.2 解法：在 Tree-sitter 之上加一层归一化

我做了一层薄薄的归一化 AST，规则只看归一化后的标准节点类型：

```typescript
export type StandardNodeType =
  | 'function_call'       // 所有语言的函数调用
  | 'template_string'     // 模板字符串 / f-string
  | 'string_concat'       // 字符串 + 拼接
  | 'assignment'          // 赋值（用于硬编码凭据）
  | 'unknown';
```

每种语言写一个 adapter，把 Tree-sitter 原生节点翻译成上面五种类型之一。这样规则代码可以这样写（不管什么语言都一样）：

```typescript
// SQL 注入规则
function checkSqlInjection(node: ASTNode, ctx: MatchContext): boolean {
  if (node.type !== 'function_call') return false;

  const callInfo = ctx.getCallInfo(node);
  if (!callInfo?.callee?.match(/\b(query|execute|exec)\b/i)) return false;

  // 是否有动态参数（模板字符串、字符串拼接）
  return node.children.some(
    c => c.type === 'template_string' || c.type === 'string_concat'
  );
}
```

**这层归一化是项目最值钱的设计决策之一**。第 3 周加 Go 语言时，只要写 30 行 adapter，就能复用全部 13 条规则中至少 8 条。

### 2.3 实际代码：normalize 一个函数调用

```typescript
function normalizeCallNode(node: TreeSitterNode, language: Language): ASTNode {
  // 找出参数里的"动态拼接"标记 — 这是规则真正关心的
  const children = collectDynamicArgumentMarkers(node, language);

  return {
    type: 'function_call',
    rawType: node.type,            // 留着原始类型供 debug
    text: node.text,
    location: toLocation(node),
    children,
    parent: null,
    fields: {},
  };
}
```

关键技巧：**保留 `rawType` 字段**。规则平时不看，但出 bug 时能立刻定位是哪种原生节点出问题。这是写工具型项目的小经验：**不要丢掉原始数据，只是别让它出现在主路径上**。

---

## 三、Stage 2 的 Prompt 工程：让 LLM 吐可解析的 JSON

### 3.1 把 LLM 当函数用，不当聊天伙伴

Stage 2 的 Prompt 设计有一个核心原则：**让 LLM 像一个函数那样工作**。输入结构化，输出结构化，没有寒暄，没有 markdown 装饰。

我的 System Prompt 大概长这样：

```
You are AI-CodeGuard Stage 2.
Review one static-analysis security finding and decide whether it is a real vulnerability.
Respond with a single JSON object only. Do not use markdown or code fences.
JSON schema: {"confirmed": boolean, "confidence": number, "reasoning": string}.
Rules: confidence must be between 0 and 1; reasoning must be concise.
```

User Prompt 是一个序列化好的 JSON，包含：
- 规则 ID 和标题
- 文件路径和行号
- 代码片段 + 上下文
- 语言
- Stage 1 提取的元数据（callee 名称、参数等）

### 3.2 对付 LLM 自由发挥的三道防线

即使你这么强调"只输出 JSON"，Claude 还是会偶尔加一句"Here's my analysis:"或者包一层 ```json``` markdown。所以解析层必须健壮：

```typescript
function parseAnalysisPayload(text: string): AnalysisPayload {
  // 第一道：剥掉 markdown code fence
  const cleaned = text.replace(/```json/gi, '').replace(/```/g, '').trim();

  // 第二道：从第一个 { 找到最后一个 }
  const start = cleaned.indexOf('{');
  const end = cleaned.lastIndexOf('}');
  if (start === -1 || end === -1 || end < start) {
    throw new Error('LLM returned invalid Stage 2 JSON.');
  }

  // 第三道：JSON.parse 失败也走 fallback
  const parsed = JSON.parse(cleaned.slice(start, end + 1));
  // ... 字段校验 + 默认值
}
```

【调用模型：反向思维】先想"LLM 会怎么坑我"，再写防御代码。这是工程中最实用的防御性编程姿势。

### 3.3 fix 模式：让 LLM 不只是判官，还是医生

`--fix` 参数开启后，Prompt 多两个字段：

```json
{
  "confirmed": true,
  "confidence": 0.9,
  "reasoning": "...",
  "fixDescription": "Use parameterized query",
  "fixCode": "db.query('SELECT * FROM users WHERE id = ?', [userId])"
}
```

但**修复建议永远是建议，AI-CodeGuard 不自动改文件**。这是 OWASP 安全工具的红线：不能让工具变成新的注入面。

---

## 四、13 条 OWASP 内置规则的取舍

| 类别 | 规则 ID | 命中模式 |
|---|---|---|
| 注入 | CG-001 ~ 003 | SQL / 命令 / eval-style |
| XSS | CG-010 ~ 011 | 反射型 / DOM 型 |
| 鉴权与加密 | CG-020 ~ 021 | 硬编码凭据 / 弱加密 |
| 路径 | CG-030 ~ 031 | 路径穿越 / 任意读写 |
| 数据 | CG-040 ~ 041 | 敏感泄露 / 不安全反序列化 |
| 配置 | CG-050 | 安全配置错误 |
| SSRF | CG-060 | 外部请求拼接 |

为什么是 13 条而不是 50 条？

**【调用模型：80/20 法则】**。OWASP Top 10 真正高频出现在 web 后端代码里的就这 13 种 pattern。剩下的（如 XXE、内存腐败）要么 web 场景少见，要么静态分析很难精准命中。MVP 阶段先把高频的搞稳。

每条规则我都做了一个手动测试：

```bash
# 拿一个真实 OSS 项目扫一遍
node dist/index.js scan ./vulnerable-app --dry-run --output text
```

确保至少能命中开发者眼里的"显然有问题"那部分。命不中 → 调规则；过度命中 → 调宽容度。

---

## 五、一个真实的坑：成本失控

### 5.1 故事

第一版上线时我兴冲冲拿 100 个 OSS 仓库批量扫，第二天起床看账单——**Anthropic 扣了 $48**。

原因：Stage 1 太宽容，命中了一堆假阳性；Stage 2 全跑了 LLM。每个文件平均 5 个候选 × 100 文件 = 500 次 LLM 调用 × 平均 0.1 美元 ≈ 50 刀。

### 5.2 解法：预算闸门

```typescript
if (options.llm.maxCostUSD !== undefined && estimatedCost >= options.llm.maxCostUSD) {
  budgetReached = true;
}

// 后续 worker 看到 budgetReached → 直接 fallback 成 Stage 1 finding
```

**关键设计**：达到预算后不抛异常，而是**降级返回 Stage 1 结果**。这是一种【杠铃策略】思维：保留下行兜底，让用户即使 LLM 突然变贵也不至于扫描完全失败。

配置：

```yaml
llm:
  provider: claude
  model: claude-sonnet-4-6
  maxCostUSD: 1.0       # 单次扫描最多花 1 美元
  maxConcurrency: 5
```

### 5.3 经验：任何调用付费 API 的工具，第一版就要内置预算闸门

这是【奥德修斯之约】的工程版：**清醒时给未来的自己绑上桅杆**。免得某天 bug + 死循环 + LLM 调用 = 一夜清零。

---

## 六、当前边界 + 下一步

诚实地说：**AI-CodeGuard 还在 Phase 1**。

已经稳定的：
- JS / TS / Python 三语言
- 13 条 OWASP 内置规则
- 自定义 YAML 规则
- text / JSON / SARIF 输出
- Claude + OpenAI 双 Provider
- 171 个测试，全绿

**还在路上**：

| 里程碑 | 状态 | 计划 |
|---|---|---|
| GitHub Action 打包 | 进行中 | 本周完成 |
| LLM 缓存 | 进行中 | 下周完成 |
| Go / Java 扩语言 | 排期中 | 第 3-4 周 |
| 跨文件污点追踪 | 长期 | Q3+ |

---

## 七、给同样想做 AI + 安全工具的朋友

如果你也想做类似工具，我从这个项目踩过的坑里总结 5 条建议：

### 7.1 别让 LLM 从零审计

**给它一个起点**。规则先扫一遍，再让 LLM 复核——又快又省钱又准。

### 7.2 归一化是工具的命

多语言项目，**抽象层的设计直接决定能不能扩展**。第一版就要想清楚：什么是规则真正关心的节点类型？

### 7.3 Prompt 当函数写，不当对话写

**结构化输入 + 结构化输出 + 三道解析防线**。别期待 LLM 总是好好说话。

### 7.4 SARIF 是省事神器

SARIF 是 OASIS 标准，**GitHub Code Scanning / VS Code / Sonar 全都吃**。从第一版就支持 SARIF，等于免费拿到一堆下游集成。

### 7.5 内置预算闸门

任何调付费 API 的工具，**第一版就要有 maxCostUSD**。别等账单到了才哭。

---

## 八、后记：为什么是我

我不是 BAT 出身的大佬，也不是 PhD。

我是一个 23 岁的退役军人，专升本在读，每天在保卫处值班的间隙看 Tree-sitter 源码。

但我相信【林迪效应】：SAST 这个领域活了 20+ 年，OWASP 活了 25+ 年，Tree-sitter 活了 8+ 年。我把这三个老地基叠起来，加一层 LLM 的新杠杆——这是工程上稳的姿势。

如果这篇博客对你有用，或者你也在做类似的工具，欢迎在 GitHub 给 AI-CodeGuard 一颗 star，或者提个 issue 聊聊。

下一篇会讲 **"给 AI 工具加缓存能省多少钱"**——LLM 扫描结果的缓存设计与命中率实战。

> 龙渊归鞘，代码参禅。
> —— 黄焌哲，2026-05-28，成都

---

## 附录：项目快速上手

```bash
git clone https://github.com/hzj-Jeff-07/AI-CodeGuard
cd AI-CodeGuard
npm install && npm run build

# Stage 1 干跑（不要 API key）
node dist/index.js scan ./your-project --dry-run

# 完整两阶段（需要 API key）
export CODEGUARD_API_KEY="sk-ant-..."
node dist/index.js scan ./your-project --output sarif --output-file report.sarif
```

更多文档：
- README：项目总览
- ARCHITECTURE.md：技术架构
- docs/design/：模块详细设计
