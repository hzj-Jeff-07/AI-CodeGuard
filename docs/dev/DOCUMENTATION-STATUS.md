# AI-CodeGuard 文档状态与最终一致性报告

> ⚠️ **状态更新（2026-07-05）**：本文正文写于 2026-04-12，其中关于 “cache 未接入 / GitHub Action 未完成 / 171 个测试 / 仅支持 JS-TS-Python” 的描述已过时。当前事实：Stage 2 磁盘缓存已接入 `scan()`、composite Action 与 CI / SARIF 上传 workflow 已交付且全绿、Go 已支持 8 条规则、Java 已支持 9 条规则（CG-001/002/020/021/030/040/041(仅Java)/050/060）、PHP 已支持 6 条规则 MVP（CG-001/002/003/020/030/060）、默认模型为 `claude-sonnet-5`、测试为 329 个（11 个文件，另有 1 个 opt-in 真实 provider E2E 默认跳过）。以 `README.md` 与 `CHANGELOG.md` 为准，本文正文保留作历史快照。

> 本文档记录 **2026-04-12** 对 AI-CodeGuard 核心文档做的最终一致性清查结果，用于快速回答两个问题：
>
> 1. **当前文档是否已经和源码对齐？**
> 2. **现在对外应该如何准确描述项目能力边界？**

## 1. 清查范围

本轮清查覆盖以下文档层级：

- `README.md`
- `ARCHITECTURE.md`
- `docs/README.md`
- `docs/design/*.md`
- `docs/dev/*.md`
- `docs/adr/decisions.md`

清查重点包括：

- 术语是否一致：`Phase 1` / `Stage 1` / `Stage 2`
- 运行时事实是否一致：`scan()`、`rules.custom`、`--dry-run`、`--fix`
- custom-rule CLI workflow 是否被错误写成“未实现”
- 测试统计是否统一为当前结果
- 未完成项是否仍被准确标注为规划/缺口

## 2. 最终结论

截至 **2026-04-12**，AI-CodeGuard 当前核心文档已经完成这一轮对齐，主要结论如下：

1. **项目当前仍处于 Phase 1**
   - 表示它已经是一个可运行、可测试的本地 CLI 基线；并不表示运行时只能停留在 Stage 1。

2. **`scan()` 当前支持两级管道**
   - Stage 1：静态预过滤
   - Stage 2：可选 LLM 二次确认与结果增强

3. **`--dry-run` 的语义已经统一**
   - 当前所有核心文档都把它描述为 **Stage 1-only** 路径。

4. **custom rules 的运行时与 CLI workflow 都已经接线**
   - `rules.custom` 已接入 `scan()` 主流程
   - `rules validate/create/test` 已实现
   - `rules test` 是 **Stage 1-only smoke path**，不覆盖 Stage 2

5. **当前验证状态已经统一**
   - `npm run build` 通过
   - `npm run test:run` 通过
   - 当前统计为 **9 个测试文件、171 个测试通过**

6. **未完成项的边界已经明确**
   - cache 仍未接入主流程
   - GitHub Action / CI 产品化链路未完成
   - 语言支持仍限于 JS / TS / Python
   - custom rules 仍不是完整语义 / 数据流规则平台

## 3. 本轮最终清查发现与修正

本轮最终一致性清查中，发现的最后一个实质性残留冲突是：

- `ARCHITECTURE.md` 仍有一处旧表述，把 custom-rule CLI workflow 写成“仍未补齐”

该处现已修正，当前统一为：

- custom rules 已接入运行时
- `rules validate/create/test` 已提供当前 CLI 工作流
- 后续重点不再是“先把 workflow 做出来”，而是继续增强示例、错误提示、复杂 pattern 测试与产品化能力

除这处外，本轮清查未再发现新的核心矛盾项。

## 4. 当前应统一采用的项目事实

下面这些表述现在可以作为仓库级统一事实使用：

### 4.1 当前已实现

- `scan`
- `init`
- `rules --list`
- `rules validate`
- `rules create`
- `rules test`
- JS / TS / Python 扫描
- 13 条 built-in rules
- YAML custom rules runtime loading
- Tree-sitter 归一化 parser
- text / json / sarif 输出
- Claude / OpenAI Stage 2 provider 选择
- 可选 fix suggestion 输出
- 成本估算、并发控制、预算截断

### 4.2 当前未实现 / 未完成

- cache 主流程集成
- GitHub Action 打包 / 上传 / 发布链路
- Java / Go / Rust 等扩展语言支持
- 完整语义分析、跨文件分析、CFG、taint tracking
- 未知模型自动定价发现
- 更完整的 live-provider 验收体系

## 5. 当前对外推荐表述

如果现在需要向团队成员、评审或外部读者介绍 AI-CodeGuard，推荐使用下面这段话：

> AI-CodeGuard 当前是一个可运行的 TypeScript 本地 CLI 安全扫描器，支持 JavaScript、TypeScript、Python，具备 13 条内置安全规则、YAML custom rules、text/json/sarif 输出，以及 Stage 1 静态预过滤 + 可选 Stage 2 LLM 二次确认的两级扫描主流程。当前 `rules validate/create/test` 已可用，其中 `rules test` 为 Stage 1-only smoke path；缓存复用、GitHub Action 产品化和更强语义 / 数据流能力仍属于后续阶段。

## 6. 当前不应再出现的错误表述

后续维护文档时，应避免再次出现以下说法：

1. **“Stage 2 还没接入主流程”**
2. **“`rules.custom` 仍只是预留字段”**
3. **“`rules validate/create/test` 还未实现”**
4. **“GitHub Action 已集成完成”**
5. **“当前已经支持 Java / Go / Rust 运行时扫描”**
6. **“custom rules 已经是完整语义 / 数据流规则平台”**
7. **“`rules test` 会覆盖 Stage 2”**

## 7. 后续文档维护建议

为了避免文档再次领先于实现，后续如果发生功能变更，建议至少同步检查以下文档：

- `README.md`
- `ARCHITECTURE.md`
- `docs/README.md`
- 受影响模块对应的 `docs/design/*.md`
- `docs/dev/ROADMAP.md`
- `docs/dev/TESTING.md`

最小同步原则：

1. **先改实现，再改文档**
2. **先写“当前事实”，再写“后续计划”**
3. **涉及测试数量变化时，同步更新全部统计口径**
4. **涉及 CLI 行为变化时，同时更新 README、CLI 示例、架构说明**

## 8. 本轮清查结论摘要

一句话总结：

> **AI-CodeGuard 当前文档已经基本完成这一轮最终对齐；现在剩下的重点不是修正文档事实错误，而是随着后续功能演进继续维护这套已对齐的事实基线。**
