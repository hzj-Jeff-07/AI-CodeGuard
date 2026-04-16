# AI-CodeGuard CLI 使用示例

> 本文档基于当前实现编写，示例优先使用仓库内可直接运行的方式：`node dist/index.js`。

## 1. 前置准备

```bash
npm install
npm run build
```

构建完成后，可以通过以下两种方式运行：

- 仓库内直接运行：`node dist/index.js ...`
- 若已作为可执行包安装：`ai-codeguard ...`

下文统一使用第一种方式示例。

## 2. 初始化配置

在当前项目目录生成 `.codeguard.yml`：

```bash
node dist/index.js init
```

如果文件已存在，默认不会覆盖。强制覆盖：

```bash
node dist/index.js init --force
```

生成后的 starter config 默认包含：

- `scan.include`
- `scan.exclude`
- `rules.preset`
- `llm.provider`
- `llm.model`
- `llm.maxConcurrency`
- `output.format`

## 3. 最基本的扫描命令

扫描当前目录：

```bash
node dist/index.js scan
```

扫描指定目录：

```bash
node dist/index.js scan ./src
```

同时扫描多个路径：

```bash
node dist/index.js scan ./src ./lib ./scripts
```

扫描单个文件：

```bash
node dist/index.js scan ./src/app.ts
```

## 4. 输出格式示例

### 4.1 终端文本输出（默认）

```bash
node dist/index.js scan ./src
```

当前默认输出格式是 `text`。

### 4.2 输出 JSON 到终端

```bash
node dist/index.js scan ./src --output json
```

当前 JSON 结构包含：

- `version`
- `scan.files`
- `scan.suspicious`
- `scan.duration`
- `scan.llmCalls`
- `scan.estimatedCost`
- `findings`
- `skipped`

### 4.3 输出 SARIF 到终端

```bash
node dist/index.js scan ./src --output sarif
```

### 4.4 写入输出文件

写入 JSON 文件：

```bash
node dist/index.js scan ./src --output json --output-file report.json
```

写入 SARIF 文件：

```bash
node dist/index.js scan ./src --output sarif --output-file report.sarif
```

如果传了 `--output-file`，报告会写入文件，不再把主体内容打印到 stdout。

## 5. 配置文件示例

### 5.1 使用默认搜索逻辑

如果当前目录存在以下任一文件，CLI 会自动搜索并加载：

- `.codeguard.yml`
- `.codeguard.yaml`
- `.codeguard.json`
- `codeguard.config.js`
- `codeguard.config.ts`

直接运行：

```bash
node dist/index.js scan ./src
```

### 5.2 指定配置文件路径

```bash
node dist/index.js scan ./src --config ./configs/codeguard.yml
```

## 6. 规则相关命令

列出当前内置规则：

```bash
node dist/index.js rules --list
```

创建 custom rule scaffold：

```bash
node dist/index.js rules create ./custom-rules/example.yml
```

如果目标文件已存在，默认不会覆盖。强制覆盖：

```bash
node dist/index.js rules create ./custom-rules/example.yml --force
```

校验 custom rules 文件或目录：

```bash
node dist/index.js rules validate ./custom-rules
```

用 custom rules 对目标路径执行 Stage 1-only smoke test：

```bash
node dist/index.js rules test ./custom-rules ./src --output json
```

### 6.1 使用 custom rules 运行扫描

示例配置：

```yaml
rules:
  preset: none
  custom: ./custom-rules
```

然后运行：

```bash
node dist/index.js scan ./src --config ./.codeguard.yml --dry-run
```

当前边界：
- `rules.custom` 可指向 YAML 文件或目录
- 指向目录时会递归加载 `*.yml` / `*.yaml`
- 路径按当前工作目录解析
- `rules --list` 仍不会显示已加载 custom rules
- `rules test` 强制只跑 Stage 1，因此不需要 API key

## 7. 常见组合用法

### 7.1 Stage 1-only 扫描

```bash
node dist/index.js scan ./src --dry-run
```

适用场景：
- 不想发起任何 LLM 调用
- 想先看 Stage 1 预过滤结果
- 尚未配置 API key

### 7.2 Stage 1-only + custom rules

```bash
node dist/index.js scan ./src --dry-run --config ./configs/custom-rules.yml
```

适用场景：
- 只验证 built-in / custom rules 的 Stage 1 命中情况
- 调试 custom rule YAML
- 不希望进入 Stage 2

### 7.3 Full scan with Stage 2

```bash
export CODEGUARD_API_KEY="..."
node dist/index.js scan ./src
```

适用场景：
- 需要让 Stage 2 过滤误报
- 希望在输出中看到 `llmAnalysis`
- 希望统计 `llmCalls` 与 `estimatedCost`

### 7.4 Full scan + fix suggestions

```bash
export CODEGUARD_API_KEY="..."
node dist/index.js scan ./src --fix
```

当 Stage 2 确认 finding 且返回修复建议时，结果中会出现：
- `findings[].fix.description`
- `findings[].fix.code`

### 7.5 扫描后导出 SARIF 供后续工具消费

```bash
node dist/index.js scan ./src --output sarif --output-file ./artifacts/codeguard.sarif
```

### 7.6 扫描多个业务目录并输出 JSON

```bash
node dist/index.js scan ./src ./server ./worker --output json --output-file ./tmp/report.json
```

### 7.7 用 verbose 观察执行过程

```bash
node dist/index.js scan ./src --verbose
```

当前 `verbose` 参数已经存在，但当前主流程日志输出仍较轻量。

## 8. Exit Code 说明

当前 `scan` 命令的退出码语义如下：

- `0`：扫描成功，且未发现 `critical` / `high` 级问题
- `1`：扫描成功，但存在 `critical` 或 `high` 级 findings
- `2`：扫描执行失败

因此在 CI 里可以直接把它当成一个基础 gate 使用。

## 9. 与 LLM 相关的命令行为

### 9.1 `--fix`

CLI 参数：

```bash
node dist/index.js scan ./src --fix
```

当前真实行为：
- 只有在 Stage 2 实际运行时才会有意义
- 需要可用的 API key
- 会要求 LLM 返回 `fixDescription` / `fixCode`
- fix 只作为输出建议，不会自动写回源码

### 9.2 `--dry-run`

CLI 参数：

```bash
node dist/index.js scan ./src --dry-run
```

当前真实行为：
- 只执行 Stage 1
- 不进入 Stage 2
- `llmCalls = 0`
- `estimatedCost = 0`

## 10. 环境变量示例

配置加载器当前支持以下环境变量覆盖：

```bash
export ANTHROPIC_API_KEY="..."
export OPENAI_API_KEY="..."
export CODEGUARD_API_KEY="..."
export CODEGUARD_MODEL="claude-sonnet-4-6"
export CODEGUARD_MAX_COST="1.00"
```

说明：
- `CODEGUARD_API_KEY` / `ANTHROPIC_API_KEY` / `OPENAI_API_KEY` 会写入 `llm.apiKey`
- `CODEGUARD_MODEL` 会覆盖 `llm.model`
- `CODEGUARD_MAX_COST` 会覆盖 `llm.maxCostUSD`

## 11. 当前最实用的开发工作流

### 11.1 只做本地静态预过滤

```bash
npm install
npm run build
node dist/index.js init
node dist/index.js scan ./src --dry-run --output text
```

### 11.2 用 custom rules 做本地规则验证

```bash
npm install
npm run build
node dist/index.js rules create ./tmp/example-rule.yml
node dist/index.js rules validate ./tmp/example-rule.yml
node dist/index.js rules test ./tmp/example-rule.yml ./tests/fixtures/vulnerable --output json
```

### 11.3 做完整扫描并导出机器可读结果

```bash
npm install
npm run build
export CODEGUARD_API_KEY="..."
node dist/index.js scan ./src --output json --output-file report.json
```

### 11.4 对接安全工具链

```bash
npm install
npm run build
export CODEGUARD_API_KEY="..."
node dist/index.js scan ./src --output sarif --output-file report.sarif
```

## 12. 当前已知使用边界

在使用当前 CLI 时，应默认理解以下边界：

1. `--dry-run` 是 Stage 1-only 路径
2. 默认扫描会在命中 suspicious nodes 时尝试进入 Stage 2
3. Stage 2 缺少 API key 时会失败，并提示使用 `--dry-run`
4. `llmCalls` / `estimatedCost` 只有在 Stage 2 实际运行时才会大于 `0`
5. fix 建议是 advisory output，不是自动修复
6. `config.output.format` 已定义，但 `scan` 命令默认参数仍优先落到 `text`
7. `rules --list` 仍只显示 built-in rules，不显示 custom rules
8. `rules test` 是 custom-rule 的 Stage 1-only 验证命令，不覆盖 Stage 2 路径

这意味着当前 CLI 已经不只是静态扫描工具，但也还不应被描述为“已完成完整语义规则平台、GitHub Action 集成”的完整工具链。
