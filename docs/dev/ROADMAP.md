# AI-CodeGuard 开发路线图

> ⚠️ **状态更新（2026-07-06）**：本文正文写于 2026-04-12，其中关于 “cache 未接入 / GitHub Action 未完成 / 171 个测试 / 仅支持 JS-TS-Python” 的描述已过时。当前事实：Stage 2 磁盘缓存已接入 `scan()`、composite Action 与 CI / SARIF 上传 workflow 已交付且全绿、新增 `CG-022`（不安全随机数，全部 6 门语言）、`CG-023`（不安全正则/ReDoS，全部 6 门语言）、`CG-024`（NoSQL 注入，JS/TS/Python/PHP）三条规则（内置规则总数 16 条）、Go 已支持 11 条规则、Java 已支持 13 条规则（Go 基础上再加 CG-010/041）、PHP 已支持 14 条规则（Go 基础上再加 CG-003/024/041）、Python 已支持 15 条规则（仅缺 CG-011 DOM XSS）、默认模型为 `claude-sonnet-5`、新增 `RuleCheckContext.wasAssignedFrom()` 轻量赋值关联工具（非真正数据流,详见 RULES.md §4）、`LanguageAdapter.mapNodeType()` 死代码已随对应单测一并删除、测试为 390 个（11 个文件，另有 1 个 opt-in 真实 provider E2E 默认跳过）。以 `README.md` 与 `CHANGELOG.md` 为准，本文正文保留作历史快照。

> 本路线图以当前源码为基线，截至 **2026-04-12**。它用于说明“下一步做什么”，**不是**对已上线能力的宣称。

## 1. 当前基线（已交付）

当前仓库已经稳定交付的是一个 **Phase 1 两级扫描 CLI 基线**：

- 可执行命令：`scan`、`init`、`rules --list`、`rules validate`、`rules create`、`rules test`
- 支持语言：JavaScript / TypeScript / Python
- 内置规则：13 条 OWASP 导向规则
- 输出格式：`text` / `json` / `sarif`
- 配置加载：配置文件 + 环境变量覆盖
- 运行时路径：Stage 1 静态预过滤 + 可选 Stage 2 LLM 深度分析
- custom rules：`rules.custom` 已接入 `scan()` 运行时
- custom-rule workflow：`rules validate/create/test` 已可用
- `--dry-run`：明确停在 Stage 1
- `--fix`：在 Stage 2 确认 finding 时返回修复建议
- 测试状态：`171` 个测试通过（`npm run test:run`，2026-04-12）

这意味着当前开发不应再围绕“Stage 2 是否存在”或“custom rules 是否完全未接线”展开，而应围绕**继续提升精度、补测试、补 CLI 工作流与产品化链路**展开。

## 2. 路线图原则

1. **先保持主链路稳定，再扩展宣传面**
   - Stage 1 + Stage 2 + custom-rule runtime 已接入运行时，后续优先保证回归稳定，而不是继续堆叠未落地愿景。
2. **文档必须区分已实现与规划项**
   - LLM、Tree-sitter、自定义规则 runtime、GitHub Action 只有在接入主流程后，才能写成当前能力。
3. **保持 Phase 1 回归稳定**
   - 任何后续功能都不能破坏当前静态扫描、输出格式与测试基线。
4. **先提升可信度，再扩大范围**
   - 先解决精度、成本、运行链路与 custom-rule 测试，再考虑更多语言和产品化封装。

## 3. 里程碑总览

| 里程碑 | 目标 | 当前状态 | 完成标志 |
|--------|------|----------|----------|
| M0 | Phase 1 扫描基线 | 已完成 | `scan`/`init`/`rules` 可用，测试通过 |
| M1 | Stage 2 Analyzer 接线 | 已完成 | 非 `dryRun` 时可执行 LLM 深度分析 |
| M2 | `--fix` 修复建议 | 已完成 | `Finding.fix` 可在运行时生成并进入报告 |
| M3 | 用 Tree-sitter 替换轻量 parser | 已完成 | 主流程 parser 已改为 Tree-sitter 兼容归一化实现 |
| M4 | Custom rules runtime | 已完成 | `rules.custom` 可加载，且 `rules validate/create/test` 已提供工作流 |
| M5 | GitHub / CI 产品化集成 | 已完成（2026-05-28） | composite `action.yml` + `ci.yml` + `security-scan.yml`（SARIF 上传 Code Scanning） |
| M6 | 扩展语言支持 | 已完成（2026-07-05） | Go 支持 8 条规则，Java 支持 9 条规则（在 CG-001/002/020/030/060 基础上深化了 CG-021/040/050，Java 额外覆盖 CG-041）；PHP 作为第 6 门语言以 6 条规则 MVP 接入（CG-001/002/003/020/030/060） |

## 4. 推荐优先级

### P0：稳住现有两级管道

当前最重要的工作已不再是“把 Stage 2 接回主流程”，而是确保这条链路稳定、可验证、可继续扩展。

1. **补齐 Stage 2 真实 provider 的受控验收路径**
   - 当前单测与集成测试通过依赖注入隔离外网调用
   - 下一步应增加最小可控的真实 provider 验收策略

2. **继续收紧成本与模型边界**
   - 当前已支持并发控制、预算截断
   - 下一步应补 pricing 校准、unknown model 行为与 budget overshoot 测试

3. **保持 `dryRun` / `--fix` 契约稳定**
   - `--dry-run` 必须持续保持 Stage 1-only
   - `--fix` 必须只在 Stage 2 确认 finding 时返回建议

### P1：提升检测精度与规则可信度

4. **继续增强基于 Tree-sitter 的规则精度**
   - 当前 parser 已完成主流程替换，但规则上下文、跨行结构识别和语义覆盖仍可继续增强
   - 后续应保持现有规则测试基线，并逐步扩大语义覆盖

5. **继续增强 custom rules 测试与失败路径保护**
   - 当前已经覆盖单文件 / 目录加载、invalid YAML / invalid schema / duplicate ID
   - 下一步可继续扩大复杂 pattern 语义与 CLI 失败提示覆盖

### P2：补齐产品化能力

6. **继续增强 custom rules 工作流**
   - 当前已实现 `validate/create/test`，后续可以补更丰富模板、更多示例与更细错误提示

7. **补 GitHub Action / CI 集成**
   - 当前 SARIF 已可生成，但没有 Action 封装、上传链路与示例

8. **扩展语言支持**
   - 在 JS / TS / Python 基础上，再评估 Java / Go / Rust 等语言
   - 新语言必须伴随 parser、rules、fixtures 与回归测试一起交付

## 5. 每个里程碑的最小完成标准

### M1：Stage 2 Analyzer

当前已满足：

- `scan()` 可区分 Stage 1 与 Stage 2
- `--dry-run` 只跑 Stage 1
- 非 `dryRun` 时可调用选定 Provider
- `Finding.llmAnalysis` 有真实内容
- `llmCalls` / `estimatedCost` 不再恒为 `0`

后续补强方向：
- 增加真实 provider 的受控验收测试
- 为 pricing / unknown model / budget overshoot 增加更细粒度测试

### M2：Fix Suggestions

当前已满足：

- `--fix` 能触发 fix 生成分支
- `json` / `sarif` / `text` 输出均能看到 fix 信息
- fix 至少包含：
  - 修复说明
  - 建议代码片段

后续补强方向：
- 评估修复建议质量
- 增加更复杂漏洞场景下的 fix 回归样例

### M3：Tree-sitter Parser

当前已满足：

- 主流程 parser 改为 Tree-sitter
- 保留当前语言支持不回退
- 现有规则回归测试继续通过
- 文档同步更新，不再把轻量 parser 误写成当前实现

### M4：Custom Rules Runtime / Workflow

当前已满足：

- `rules.custom` 可加载
- 规则格式可在运行时校验
- 单文件 / 目录 YAML 都有明确语义
- `rules validate/create/test` 已可用
- 文档已清楚区分 built-in rules 与 custom rules runtime

后续补强方向：
- 继续补更丰富的 custom rule 示例
- 扩大 CLI 失败提示与复杂 pattern 场景测试

### M5：GitHub / CI 集成

最低需要满足：

- 给出可复用的 CI 示例
- 能将 SARIF 结果写出并接入消费方
- 文档说明输入、输出和限制条件

## 6. 当前不建议优先做的事

以下事项当前不应优先：

- 过早宣传“已完成 GitHub Action 集成”或“支持任意模型自动定价”
- 扩展过多语言但没有稳定 parser、rules 和测试
- 在真实验收与精度问题未补齐前，先做复杂缓存体系
- 把当前 custom rules 能力误写成完整语义 / 数据流规则平台

## 7. 路线图结论

对当前项目来说，最合理的推进顺序是：

**先稳住已接线的 Stage 2、fix 与 custom-rule runtime / CLI workflow，继续增强 Tree-sitter 规则精度并补测试，再补真实 provider 验收与 GitHub 集成。**

如果按照这个顺序推进，AI-CodeGuard 会从“已经可运行的两级安全扫描工具”继续演进为“精度更高、扩展性更强、集成更完整的安全工具链”，同时避免文档再次领先于实现。
