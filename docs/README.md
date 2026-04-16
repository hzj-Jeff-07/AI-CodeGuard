# AI-CodeGuard 文档导航

> 本页是 AI-CodeGuard 当前文档集的入口，帮助你快速找到“总览、设计细节、开发说明、决策记录”四类信息。

## 1. 先记住这三个术语

为了避免文档阅读时把“产品阶段”和“运行时阶段”混在一起，当前统一使用下面的术语：

- **Phase 1**：当前已交付的产品阶段，指一个可运行、可测试的本地 CLI 基线
- **Stage 1**：扫描管道中的第一阶段，指静态预过滤（Tree-sitter 归一化解析 + 规则执行）
- **Stage 2**：扫描管道中的第二阶段，指 LLM 二次确认 / 结果增强 / 可选修复建议生成

当前最准确的状态是：

> **仓库当前仍处于 Phase 1，但运行时 `scan()` 已支持 Stage 1 + Stage 2，且 `rules.custom` 已接入运行时；`--dry-run` 会明确停在 Stage 1。**

## 2. 推荐阅读顺序

如果你第一次接触这个仓库，推荐按下面顺序阅读：

1. [README.md](../README.md) — 项目总览与当前能力边界
2. [ARCHITECTURE.md](../ARCHITECTURE.md) — 当前运行时架构与数据流
3. [docs/design/TECHNICAL-SUMMARY.md](./design/TECHNICAL-SUMMARY.md) — 实现状态、验证结论与剩余缺口
4. 按需进入 design / dev / adr 子文档

## 3. 文档地图

### 3.1 总览文档

- [README.md](../README.md) — 对外/对内都可使用的当前项目概览
- [ARCHITECTURE.md](../ARCHITECTURE.md) — 当前架构、模块关系、数据流与实现边界
- [docs/design/TECHNICAL-SUMMARY.md](./design/TECHNICAL-SUMMARY.md) — 当前实现完成度、验证状态与下一阶段优先级

### 3.2 设计文档（design）

- [docs/design/core-modules.md](./design/core-modules.md) — 按模块解释当前代码边界与运行行为
- [docs/design/CONFIGURATION.md](./design/CONFIGURATION.md) — 配置结构、默认值、环境变量覆盖、实际生效边界
- [docs/design/RULES.md](./design/RULES.md) — 当前 built-in + custom rules 的运行方式、检测信号与限制
- [docs/design/REPORTING.md](./design/REPORTING.md) — text / json / sarif 报告格式与当前输出边界
- [docs/design/LLM-INTEGRATION.md](./design/LLM-INTEGRATION.md) — 当前 Stage 2 行为、provider、成本控制与限制

### 3.3 开发文档（dev）

- [docs/dev/CLI-EXAMPLES.md](./dev/CLI-EXAMPLES.md) — 当前 CLI 命令示例与推荐用法
- [docs/dev/ROADMAP.md](./dev/ROADMAP.md) — 以当前基线为起点的推荐开发路线图
- [docs/dev/TESTING.md](./dev/TESTING.md) — 测试命令、覆盖范围与当前测试空白

### 3.4 决策记录（adr）

- [docs/adr/decisions.md](./adr/decisions.md) — 已接受的架构决策，以及每项决策当前是否真正落地

## 4. 按问题找文档

### 想知道“项目现在到底实现了什么？”

优先看：

- [README.md](../README.md)
- [docs/design/TECHNICAL-SUMMARY.md](./design/TECHNICAL-SUMMARY.md)

### 想知道“`scan()` 现在真实怎么跑？”

优先看：

- [ARCHITECTURE.md](../ARCHITECTURE.md)
- [docs/design/core-modules.md](./design/core-modules.md)

### 想知道“某个配置字段到底有没有生效？”

优先看：

- [docs/design/CONFIGURATION.md](./design/CONFIGURATION.md)

### 想知道“规则系统现在是不是支持 YAML custom rules？”

优先看：

- [docs/design/RULES.md](./design/RULES.md)
- [docs/adr/decisions.md](./adr/decisions.md)

### 想知道“LLM / fix / dryRun 现在到了哪一步？”

优先看：

- [docs/design/LLM-INTEGRATION.md](./design/LLM-INTEGRATION.md)
- [docs/dev/CLI-EXAMPLES.md](./dev/CLI-EXAMPLES.md)
- [docs/dev/TESTING.md](./dev/TESTING.md)

### 想知道“怎么跑命令、怎么验证结果？”

优先看：

- [docs/dev/CLI-EXAMPLES.md](./dev/CLI-EXAMPLES.md)
- [docs/dev/TESTING.md](./dev/TESTING.md)

## 5. 当前文档使用原则

阅读本仓库文档时，请默认遵循以下原则：

1. **当前源码优先于旧规划**
2. **已实现能力与设计目标必须分开理解**
3. **看到 Tree-sitter / custom rules / GitHub Action 时，先确认文档写的是“已接线运行时能力”还是“未完成工作流/产品化能力”**
4. **如果某个说法和源码冲突，以源码与测试结果为准，并回头修正文档**

## 6. 当前结论

AI-CodeGuard 的文档集现在已经可以支持三件事：

- 快速理解当前已交付能力
- 准确区分 Stage 1 / Stage 2 / 已接线 custom rules / 后续规划项
- 为下一步推进规则精度、custom rules 示例 / 错误提示补强与 CI 集成提供清晰基线

如果后续继续扩展文档，建议优先保持这页导航与 README 的链接同步更新。
