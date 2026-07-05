# AI-CodeGuard 技术方案汇总

> ⚠️ **状态更新（2026-07-05）**：本文正文写于 2026-04-12，其中关于 “cache 未接入 / GitHub Action 未完成 / 171 个测试 / 仅支持 JS-TS-Python” 的描述已过时。当前事实：Stage 2 磁盘缓存已接入 `scan()`、composite Action 与 CI / SARIF 上传 workflow 已交付且全绿、Go 已支持 8 条规则、Java 已支持 9 条规则（CG-001/002/020/021/030/040/041(仅Java)/050/060）、默认模型为 `claude-sonnet-5`、测试为 297 个（11 个文件，另有 1 个 opt-in 真实 provider E2E 默认跳过）。以 `README.md` 与 `CHANGELOG.md` 为准，本文正文保留作历史快照。

> 本文档汇总 **当前已实现能力、验证状态、已修正文档偏差**，并明确区分“已交付”和“后续规划”。

> 术语约定：**Phase 1** 指当前已交付的产品阶段；**Stage 1** 指当前运行时中的静态预过滤；**Stage 2** 指当前运行时中的 LLM 深度分析阶段。

## 1. 项目概述

**AI-CodeGuard** 当前是一个 TypeScript 编写的本地 CLI 安全扫描器，已经实现：

- JavaScript / TypeScript / Python 文件扫描
- Tree-sitter 解析 + 兼容归一化 AST
- built-in rules + 可选 YAML custom rules 运行时加载
- Stage 2 LLM 二次确认与结果增强
- 可选修复建议生成
- Text / JSON / SARIF 三种报告输出
- 配置加载与环境变量覆盖
- 单元测试与集成测试闭环

### 当前定位

项目当前最准确的状态是：

> **Phase 1 本地 CLI 基线已完成并稳定，Stage 2 已接入运行时，`rules.custom` 也已接入 `scan()` 主流程；后续重点转向 custom-rule 工作流、测试补强、cache 与产品化集成。**

## 2. 当前技术栈总览

| 层次 | 当前状态 | 技术选型 |
|------|----------|---------|
| 语言 | 已实现 | TypeScript 5.x |
| 运行时 | 已实现 | Node.js ≥ 18 |
| CLI | 已实现 | Commander.js |
| 文件发现 | 已实现 | fast-glob |
| 配置加载 | 已实现 | cosmiconfig + Zod |
| 规则系统 | 已实现 | TypeScript built-in rules + YAML custom runtime loading |
| 输出格式 | 已实现 | text / json / sarif |
| 构建 | 已实现 | tsup |
| 测试 | 已实现 | Vitest |
| LLM SDK 依赖 | 已接线 | @anthropic-ai/sdk / openai |
| Tree-sitter 依赖 | 已接线 | web-tree-sitter + JS / TSX / Python grammars |
| 日志 | 依赖已安装，未形成主流程日志体系 | pino |

## 3. 当前代码库已实现的能力

### 3.1 CLI 命令

当前已实现命令：
- `scan`
- `init`
- `rules --list`
- `rules validate`
- `rules create`
- `rules test`

### 3.2 支持语言

| 语言 | 扩展名 |
|------|--------|
| JavaScript | `.js`, `.jsx`, `.mjs`, `.cjs` |
| TypeScript | `.ts`, `.tsx` |
| Python | `.py` |

### 3.3 已实现规则

当前内置规则共 **13 条**：

| 类别 | 规则 |
|------|------|
| Injection | `CG-001`, `CG-002`, `CG-003` |
| XSS | `CG-010`, `CG-011` |
| Auth / Crypto | `CG-020`, `CG-021` |
| Path | `CG-030`, `CG-031` |
| Data | `CG-040`, `CG-041` |
| Config | `CG-050` |
| SSRF | `CG-060` |

同时，当前运行时还支持通过 `rules.custom` 加载 YAML custom rules。

### 3.4 已实现输出格式

- `text`
- `json`
- `sarif`

### 3.5 当前主流程的关键事实

当前 `scan()` 已支持两级管道：
- Stage 1 静态预过滤
- built-in + optional custom rules
- Stage 2 LLM 二次确认
- 可选 fix 建议生成
- `--dry-run` 时 `llmCalls = 0`
- 非 dry-run 且进入 Stage 2 时 `llmCalls` / `estimatedCost` 反映真实调用

## 4. 当前开发完成度评估

从“能否作为可运行的安全扫描 CLI 工具”来看：

| 模块 | 完成度 | 说明 |
|------|--------|------|
| CLI 基础命令 | 高 | 已可用 |
| Config | 高 | 已可用 |
| Scanner 主流程 | 高 | 已可用 |
| Parser（Tree-sitter 版） | 高 | 主流程已接入兼容归一化 AST |
| Built-in Rules | 高 | 13 条规则可运行 |
| Custom Rules Runtime | 高 | `rules.custom` 与 `rules validate/create/test` 已可用 |
| Reporter | 高 | 三种格式均可用 |
| 测试体系 | 高 | 171 tests passing |
| LLM Analyzer | 中高 | 已接入主流程，仍需补 pricing / cache / live validation |
| Fix generation | 中 | 可输出建议，但不自动改写文件 |
| GitHub Action | 低 | 未实现 |

### 综合判断

- **作为当前可运行 CLI：约 90% 完成**
- **作为最初“完整产品愿景”：约 75%~80% 完成**

## 5. 当前与旧文档/旧规划的主要偏差

本轮文档整理继续修正了以下偏差：

### 5.1 Parser 偏差

旧文档曾将当前 parser 描述为未来目标。

当前实际情况：
- 主流程 parser 已切换到 Tree-sitter
- 规则层仍消费兼容归一化 AST，而不是直接操作原生 Tree-sitter 节点
- 构建产物需要一并携带 core wasm 与 grammar wasm 资产

### 5.2 Analyzer 偏差

旧文档曾把 LLM 分析写成“依赖和字段已准备，但主流程未接线”。

实际情况：
- Provider、Analyzer、并发控制、成本估算已接入 `scan()`
- `--fix` 已能请求并输出结构化建议
- 仍需继续补强 pricing 覆盖、cache 与健壮性

### 5.3 Rules 偏差

旧文档曾在两个方向上都出现过偏差：

- 一部分文档把 YAML 规则 DSL、`rules validate/create/test` 等写成已实现能力
- 另一部分文档又把 `rules.custom` 仍写成完全未接线

实际情况：
- 当前规则系统以 **TypeScript built-in rules** 为主
- `rules.custom` 已接入 `scan()` 运行时
- `rules --list` 继续只列出内置规则
- `rules validate/create/test` 已实现，其中 `rules test` 是 Stage 1-only custom-rule smoke path

### 5.4 GitHub 集成偏差

旧文档曾展示 GitHub Action 作为当前能力。

实际情况：
- 仓库里没有 `action.yml`
- SARIF 输出已实现，但 GitHub Action 产品化尚未完成

### 5.5 语言支持偏差

旧文档部分位置曾提到 Java / Go / Rust 已纳入运行时支持。

实际情况：
- 当前源码仅支持 JS / TS / Python

## 6. 测试修复与验证总结（2026-04-12）

### 6.1 本轮验证目标

本轮工作的重点是：
- 接通 Stage 2 Analyzer
- 保持 Stage 1 行为可控
- 验证 fix / llmAnalysis / cost metrics 能进入输出
- 重新对齐文档

### 6.2 已验证事项

- Scanner 主流程可运行
- Stage 2 provider 选择生效
- `maxConcurrency` 调度生效
- `maxCostUSD` 截断行为生效
- Reporter 三种格式可显示 `llmAnalysis` / `fix`
- 配置加载逻辑可用

### 6.3 测试执行结果

执行命令：

```bash
npm run build
npm run test:run
```

结果：
- build 通过
- `9` 个测试文件通过
- `171` 个测试通过

关键结论：
- 当前两级扫描主流程可构建、可测试、可运行
- Tree-sitter parser 已成为当前实现，而不是后续目标
- custom rules runtime 与 CLI workflow 都已接线
- 当前文档应以“Tree-sitter / Stage 2 / custom-rule runtime 与 CLI workflow 已接线，但 cache / GitHub 集成 仍有缺口”为准

## 7. 当前建议的对外表述

如果要向他人介绍 AI-CodeGuard，当前最准确的说法是：

> AI-CodeGuard 已实现一个可运行的 TypeScript CLI 安全扫描器，支持 JS / TS / Python、13 条内置安全规则，以及 text / json / sarif 输出；当前扫描流程会先做静态预过滤，再可选调用 Claude 或 OpenAI 做 Stage 2 二次确认，并可输出修复建议。Tree-sitter 解析、`rules.custom` 运行时，以及 `rules validate/create/test` custom-rule workflow 已接线，但缓存复用和 GitHub Action 集成仍在后续阶段。

## 8. 推荐下一阶段开发优先级

### P0：强化当前两级主流程

1. 扩大 pricing 映射覆盖并校准成本估算
2. 给 Stage 2 补充 cache / retry / provider 稳定性策略
3. 增加真实 provider 的受控验收路径

### P1：补齐可扩展性与产品化能力

4. 补 custom rules 更复杂 pattern / 失败路径 / 集成扫描测试
5. 继续增强 `rules validate/create/test` 的模板、示例与错误提示
6. 补 GitHub Action / CI 集成
7. 扩展 Java / Go 等语言支持

## 9. 当前结论

截至 2026-04-12：

- 技术文档已重新对齐当前源码
- Stage 2 从“规划项”变成了“已接入运行时的能力”
- `rules.custom` 也已从“预留字段”变成了“已接入 scan runtime 的能力”
- 当前项目最稳固、最真实的能力边界已经明确

这意味着后续开发可以在**可运行的两级扫描基线 + custom-rule runtime**之上继续推进，而不会再被过时文档误导。
