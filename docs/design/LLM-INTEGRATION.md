# AI-CodeGuard LLM 集成现状与设计边界

> 本文档说明 **LLM 集成在当前代码中的真实状态**：哪些能力已经接入运行时，哪些仍然是后续演进项。

## 1. 一句话结论

截至 **2026-04-11**：

**AI-CodeGuard 已经把 Stage 2 Analyzer 接入 `scan()` 主流程。**

因此当前 CLI 的真实行为是：

- `--dry-run`：只执行 Stage 1 静态预过滤
- 默认扫描：在存在 suspicious nodes 时进入 Stage 2 LLM 分析
- `--fix`：在 Stage 2 运行时请求修复建议，并在成功时填充 `Finding.fix`

## 2. 当前已经存在并已接线的基础设施

### 2.1 Provider 依赖已安装并已接入

仓库当前已经安装并使用：

- `@anthropic-ai/sdk`
- `openai`

当前运行时会根据 `llm.provider` 选择：

- `claude`
- `openai`

### 2.2 配置模型已定义并被 Stage 2 消费

当前配置类型包含：

```typescript
interface LLMConfig {
  provider: 'claude' | 'openai';
  model: string;
  apiKey?: string;
  maxConcurrency: number;
  maxCostUSD?: number;
}
```

默认配置中给出：

```yaml
llm:
  provider: claude
  model: claude-sonnet-4-6
  maxConcurrency: 5
```

当前 Stage 2 会实际消费：
- `provider`
- `model`
- `apiKey`
- `maxConcurrency`
- `maxCostUSD`

### 2.3 环境变量覆盖已生效

当前配置加载器支持：

- `CODEGUARD_API_KEY`
- `ANTHROPIC_API_KEY`
- `OPENAI_API_KEY`
- `CODEGUARD_MODEL`
- `CODEGUARD_MAX_COST`

也就是说：
- API key 可以注入 `config.llm.apiKey`
- model 可以被环境变量覆盖
- max cost 可以被环境变量覆盖

### 2.4 CLI 参数已具备真实语义

当前 `scan` 命令暴露：

- `--fix`
- `--dry-run`

而且现在这两个参数都已参与真实运行时分叉：

- `--dry-run` 会阻止 Stage 2
- `--fix` 会让 Stage 2 请求修复建议

### 2.5 输出数据结构已被真实填充

当前类型系统中的字段：

```typescript
interface Finding {
  ...
  fix?: FixSuggestion;
  llmAnalysis?: LLMAnalysis;
}

interface LLMAnalysis {
  confirmed: boolean;
  confidence: number;
  reasoning: string;
}

interface ScanResult {
  ...
  llmCalls: number;
  estimatedCost: number;
}
```

现在已不再只是占位：
- Stage 2 确认后的 findings 会带 `llmAnalysis`
- `--fix` 成功时会带 `fix`
- `llmCalls` / `estimatedCost` 会反映真实 Stage 2 执行情况

## 3. 当前运行时怎么接入 Stage 2

当前 `scan()` 的实际流程是：

1. 发现文件
2. 识别语言
3. Tree-sitter 归一化 parser 提取节点
4. 运行 built-in rules
5. 生成 Stage 1 findings
6. 如果 `dryRun === false` 且存在 suspicious nodes，则调用 `analyzeFindings()`
7. Analyzer 选择 provider、构造 prompt、解析 JSON 响应
8. Reporter 输出结果

其中关键行为包括：

- 没有 API key 时，Stage 2 直接报错并提示改用 `--dry-run`
- Stage 2 只保留被确认的 finding
- 如果开启 `--fix`，会额外解析 `fixDescription` / `fixCode`
- 如果达到 `llm.maxCostUSD`，新的 LLM 调用会停止；剩余未分析项保留为 Stage 1 findings

## 4. 当前 Reporter 对 LLM 字段的支持

三个 formatter 都已经被当前运行时真实喂到 LLM 字段。

### 4.1 Text Reporter

如果 `finding.fix` 存在：
- 会显示修复说明
- 会显示建议代码片段

如果 `finding.llmAnalysis` 存在：
- 会显示置信度
- 会显示推理说明

如果 `llmCalls > 0`：
- summary 会显示 `LLM calls` 与 `Estimated cost`

### 4.2 JSON Reporter

当前会输出：
- `findings[].fix`
- `findings[].llmAnalysis`
- `scan.llmCalls`
- `scan.estimatedCost`

### 4.3 SARIF Reporter

当前也支持：
- 将 `llmAnalysis` 放进 `message.markdown`
- 将 `fix` 映射到 SARIF `fixes`

因此当前缺口已不在 Reporter，而是在更高层次的能力完善上，例如 pricing 覆盖、cache 与更健壮的 provider 行为。

## 5. 当前并发与成本控制

### 5.1 并发控制

当前 Analyzer 已支持：

- `llm.maxConcurrency`

实现方式是 worker 池调度，确保同一时间内的活跃请求数不超过配置上限。

### 5.2 成本控制

当前 Analyzer 已支持：

- `llm.maxCostUSD`

实现方式是：
- 根据 provider + model pattern 匹配内置 pricing
- 按输入/输出 token 估算累计成本
- 达到预算后停止启动新的 LLM 请求

### 5.3 当前限制

成本控制仍有明确边界：
- pricing 是内置映射，不是动态查询
- 如果设置了 `llm.maxCostUSD`，但 model 无法匹配内置 pricing，则会直接报错
- 并发场景下只能阻止“新请求”，不能回滚已在飞行中的请求

## 6. 当前最准确的数据流表述

### 6.1 今天真实存在的数据流

```text
Stage 1
source code
  └─ Tree-sitter-backed normalized parser
       └─ built-in rules
            └─ suspicious nodes
                 ├─ --dry-run → findings → text/json/sarif
                 └─ Stage 2 Analyzer
                      ├─ llmAnalysis
                      ├─ optional fix
                      └─ cost / call metrics
```

### 6.2 当前行为边界

- Stage 2 只在非 `dryRun` 路径运行
- Stage 2 不是“扫描全部代码”，而是只分析 Stage 1 候选
- 修复建议只作为输出字段返回，不会自动改写源码

## 7. Provider 抽象当前应如何理解

当前 Provider 抽象已经不是纯设计，而是已落地运行时能力：

- 可以配置 Claude / OpenAI
- 单测可通过依赖注入替换 provider
- 运行时按 provider 分发请求

但仍不能夸大为：
- 已实现 provider fallback
- 已实现统一重试策略
- 已支持任意模型的精确定价

## 8. 文档与对外表述建议

对外介绍当前项目时，关于 LLM 集成最准确的表达应是：

> AI-CodeGuard 已将 Stage 2 LLM 分析接入 `scan()` 主流程，支持在 Stage 1 预过滤后调用 Claude 或 OpenAI 对可疑结果做二次确认，并可选生成修复建议；当前仍存在 parser 精度、pricing 覆盖、cache 与产品化集成方面的后续工作。

## 9. 当前已经满足的验收项

现在已经满足：

1. `scan()` 在非 `dryRun` 下能实际调用 Provider
2. `llmCalls` 与 `estimatedCost` 反映真实执行结果
3. `Finding.llmAnalysis` 在 JSON / Text / SARIF 中可见
4. `--fix` 能生成结构化修复建议
5. `maxConcurrency` / `maxCostUSD` 已参与运行时控制

## 10. 当前结论

AI-CodeGuard 的 LLM 集成现在已经从“接口预留”进入“运行时已接线”阶段。

接下来最重要的工作不再是把 Analyzer 接回主链路，而是：
- 扩大 Stage 2 的稳健性边界
- 提升 parser 精度
- 补齐 cache / custom rules / GitHub 集成等后续能力
