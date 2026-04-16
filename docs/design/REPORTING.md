# AI-CodeGuard 报告输出说明

> 本文档描述 **当前已经实现的报告输出能力**，包括 `text`、`json`、`sarif` 三种格式，以及它们在当前运行时下的真实表现。

## 1. 当前支持的输出格式

AI-CodeGuard 当前支持三种输出格式：

- `text`
- `json`
- `sarif`

它们都由统一的 `generateReport()` 入口生成。

## 2. 输出生成流程

当前报告生成流程如下：

```text
scan()
  └─ ScanResult
       └─ generateReport(result, format, outputFile)
            ├─ formatText()
            ├─ formatJSON()
            └─ formatSARIF()
```

如果传了 `outputFile`，当前实现会：

- 把内容写入指定文件
- 仍返回生成后的字符串给调用方

在 CLI 场景下：

- 如果没有 `--output-file`，结果会写到 stdout
- 如果有 `--output-file`，CLI 不再把报告主体打印到 stdout

## 3. 当前 ScanResult 中实际会出现什么

当前运行时会根据是否进入 Stage 2 呈现不同数据特征。

### 3.1 `--dry-run` 或无 suspicious nodes

报告中最真实的数据特征是：

- `files`：真实扫描文件数
- `suspicious`：Stage 1 命中的可疑节点数
- `findings`：Stage 1 findings
- `skipped`：跳过的文件与原因
- `duration`：扫描耗时
- `llmCalls = 0`
- `estimatedCost = 0`

### 3.2 进入 Stage 2

报告中还会出现：

- `llmCalls`：真实 LLM 调用次数
- `estimatedCost`：真实估算成本
- `findings[].llmAnalysis`
- `findings[].fix`（仅当 `--fix` 且模型返回修复建议）

也就是说，输出格式不再只是预留 LLM 字段，而是已经被当前运行时真实填充。

## 4. Text 输出

### 4.1 当前内容结构

当前 text formatter 会输出：

- 顶部标题
- 每条 finding 的严重级别、规则 ID、标题
- 文件路径与行号范围
- 代码片段
- 可选 fix suggestion
- 可选 LLM confidence / reasoning
- 汇总统计

### 4.2 示例结构

```text
AI-CodeGuard Scan Results
==================================================

✗ CRITICAL  CG-001  SQL Injection
  src/db.ts:10-10

  │ pool.query(`SELECT * FROM users WHERE id = ${id}`)

  LLM Confidence: 92% — User-controlled input reaches a dangerous sink.

==================================================
Summary: 1 findings (1 critical)
Files scanned: 3  |  Suspicious: 1  |  Duration: 1.2s
LLM calls: 1  |  Estimated cost: $0.12
```

### 4.3 当前额外字段支持

如果 `finding.fix` 存在：
- 会显示修复说明
- 会显示建议代码片段

如果 `finding.llmAnalysis` 存在：
- 会显示置信度
- 会显示推理说明

### 4.4 当前限制

- `llmCalls` / `estimatedCost` 只有在 Stage 2 实际运行时才会显示
- fix 建议不会自动写回文件

## 5. JSON 输出

### 5.1 当前结构

JSON formatter 当前输出如下顶层结构：

```json
{
  "version": "0.1.0",
  "scan": {
    "files": 0,
    "suspicious": 0,
    "duration": 0,
    "llmCalls": 0,
    "estimatedCost": 0
  },
  "findings": [],
  "skipped": []
}
```

### 5.2 `findings[]` 当前字段

每个 finding 当前会输出：

- `id`
- `ruleId`
- `severity`
- `title`
- `description`
- `file`
- `location`
- `snippet`
- `fix`
- `llmAnalysis`

当前运行时下：
- `fix` 在未请求或未返回时为 `null`
- `llmAnalysis` 在未进入 Stage 2 或未确认时为 `null`

### 5.3 适用场景

当前 JSON 输出最适合：

- 脚本消费
- 测试断言
- 二次处理
- 后续接其他系统

## 6. SARIF 输出

### 6.1 当前实现状态

SARIF formatter 已经实现，输出版本为：

- `SARIF v2.1.0`

### 6.2 当前 SARIF 内容

当前会生成：

- `$schema`
- `version`
- `runs[0].tool.driver`
- `rules`
- `results`
- 位置区域 `region`
- snippet 文本
- severity 到 SARIF level 的映射
- 可选 `fixes`
- 可选 `message.markdown` 中的 LLM 分析

### 6.3 当前 severity 映射

当前映射关系为：

- `critical` -> `error`
- `high` -> `error`
- `medium` -> `warning`
- `low` -> `note`

### 6.4 fix 与 LLM 扩展支持

当前 SARIF formatter 已能：

- 把 `fix` 映射到 SARIF `fixes`
- 把 `llmAnalysis` 拼进 `message.markdown`

### 6.5 当前限制

- 仓库中还没有 GitHub Action 封装与自动上传链路
- `informationUri` 当前仍是占位式链接：`https://github.com/user/ai-codeguard`
- SARIF 已能导出，但还不是“完整 GitHub 集成产品”

## 7. 输出到文件

当前 CLI 支持：

```bash
node dist/index.js scan ./src --output json --output-file report.json
node dist/index.js scan ./src --output sarif --output-file report.sarif
```

报告写文件时的当前行为：

- 由 `generateReport()` 直接调用 `writeFile()` 写出 UTF-8 内容
- 不额外创建目录
- 如果父目录不存在，会由底层写文件过程报错

因此在脚本里使用时，最好先确保目标目录已存在。

## 8. 当前输出与 CLI 的关系

### 8.1 默认格式

`scan` 命令当前默认使用：

- `text`

即使 `config.output.format` 已在配置里定义，当前 CLI 仍因为参数默认值而更偏向 text。

### 8.2 显式指定格式

如果你要稳定获得机器可消费结果，建议总是显式指定：

```bash
--output json
```

如果你要进入 SARIF 工具链，建议显式指定：

```bash
--output sarif --output-file report.sarif
```

## 9. 当前测试覆盖到哪些输出行为

当前测试已经覆盖：

- JSON 输出是合法 JSON
- JSON 包含 version、scan metadata、findings、skipped、llmAnalysis
- SARIF 输出是合法 JSON
- SARIF 版本与 schema 正确
- SARIF severity 映射正确
- SARIF 包含 locations、rules、fix、llmAnalysis markdown
- text 输出包含标题、规则 ID、文件路径、代码片段、summary、LLM summary
- `outputFile` 可正确写出文件

这说明当前 reporter 模块属于 **已稳定实现** 的部分。

## 10. 当前使用建议

### 文本查看

适合本地人工阅读：

```bash
node dist/index.js scan ./src
```

### 脚本消费

适合自动化处理：

```bash
node dist/index.js scan ./src --output json
```

### 安全工具链对接

适合导出标准化结果：

```bash
node dist/index.js scan ./src --output sarif --output-file report.sarif
```

## 11. 当前限制汇总

1. **输出层已稳定支持 fix / LLM 字段**
2. **SARIF 导出已完成，但 GitHub Action/上传链路未完成**
3. **默认 CLI 输出仍偏向 text**
4. **写文件时不会自动创建父目录**

## 12. 结论

AI-CodeGuard 当前的报告输出层已经是一个比较完整、稳定的模块：

- text 适合人读
- json 适合脚本
- sarif 适合后续安全工具链

真正的主要缺口已经不在 formatter，而在更上游的后续演进项：parser 精度、pricing 覆盖、cache、自定义规则与 GitHub 集成。
