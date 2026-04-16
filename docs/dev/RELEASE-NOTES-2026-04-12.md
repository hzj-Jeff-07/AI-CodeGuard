# AI-CodeGuard 发布说明（2026-04-12）

> AI-CodeGuard 当前已经形成一个可运行、可测试的 **Phase 1 本地 CLI 安全扫描基线**。这一版本的重点，不再是验证“能不能跑起来”，而是明确：**两级扫描主流程、Tree-sitter 解析、自定义规则运行时与 CLI workflow 都已经接线。**

## 本次可对外确认的能力

### 1. 两级扫描主流程已可运行

当前 `scan()` 已支持：

- **Stage 1**：静态预过滤
- **Stage 2**：可选 LLM 二次确认与结果增强

其中：

- `--dry-run` 会明确停在 **Stage 1-only**
- 非 dry-run 路径可调用 **Claude** 或 **OpenAI**
- `--fix` 可在 Stage 2 确认 finding 时返回修复建议

### 2. Tree-sitter 已成为当前 parser 基线

当前主流程已经不是旧的轻量 parser 方案，而是：

- 使用 Tree-sitter 解析源码
- 向规则层暴露兼容归一化 AST
- 在不破坏现有规则契约的前提下提升解析准确性

当前支持语言仍为：

- JavaScript
- TypeScript
- Python

### 3. Custom rules 已进入可用状态

当前 custom rules 不再只是设计目标，而是已经具备：

- `rules.custom` 运行时加载
- YAML 文件或目录加载
- schema 校验
- duplicate ID 校验
- `rules validate`
- `rules create`
- `rules test`

其中：

- `rules --list` 仍只列 built-in rules
- `rules test` 是 **Stage 1-only smoke path**
- custom rules 仍受当前归一化 AST 能力边界限制

### 4. 输出层已具备实际接入价值

当前输出格式包括：

- `text`
- `json`
- `sarif`

这意味着 AI-CodeGuard 已具备：

- 本地人工阅读的文本输出
- 供脚本消费的 JSON 输出
- 面向安全工具链的 SARIF 导出能力

## 当前验证状态

截至 **2026-04-12**，当前仓库已验证：

```bash
npm run build
npm run test:run
```

结果：

- build 通过
- **9 个测试文件通过**
- **171 个测试通过**

这说明当前版本已经不是“只有概念设计”，而是一个可构建、可测试、可运行的本地安全扫描 CLI。

## 当前最适合如何介绍 AI-CodeGuard

推荐使用下面这段表述：

> AI-CodeGuard 当前是一个可运行的 TypeScript 本地 CLI 安全扫描器，支持 JavaScript、TypeScript、Python，具备 13 条内置安全规则、YAML custom rules、text/json/sarif 输出，以及 Stage 1 静态预过滤 + 可选 Stage 2 LLM 二次确认的两级扫描主流程。当前 `rules validate/create/test` 已可用，其中 `rules test` 为 Stage 1-only smoke path；缓存复用、GitHub Action 产品化和更强语义 / 数据流能力仍属于后续阶段。

## 当前仍需明确说明的边界

为了避免过度宣传，当前仍应明确写清：

- 项目当前仍处于 **Phase 1**
- cache 尚未接入主流程
- GitHub Action / CI 产品化链路尚未完成
- 语言支持目前仅限 **JS / TS / Python**
- custom rules 还不是完整的语义 / 数据流规则平台
- `rules test` 不覆盖 Stage 2
- CLI 不会自动改写源码，fix 仍是 advisory output

## 当前最合理的下一步

在当前基线上，最合理的下一阶段工作是：

1. 补 GitHub / CI 集成
2. 继续增强 custom rules 示例、错误提示与复杂 pattern 测试
3. 继续补强 pricing、cache 与 live-provider 验收
4. 再评估 Java / Go / Rust 等语言扩展

## 一句话总结

> **AI-CodeGuard 已经完成“可运行的两级扫描 CLI 基线”这一步，当前工作的重点已经从“证明能力存在”转向“补产品化集成、提升精度与扩大可用范围”。**
