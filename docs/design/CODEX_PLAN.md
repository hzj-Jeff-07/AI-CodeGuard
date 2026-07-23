# AI-CodeGuard 剩余工作技术方案（供 Codex 执行）

> 状态：任务书（2026-07-23）。本文档写给编码代理（Codex）执行：把 M8「托管 GitHub App」从设计稿推进到可部署的 MVP，并补齐相关文档。阅读本文后按 §4 的任务顺序实施，每个任务都有明确的验收标准。

## 0. 项目现状（已验证）

- 里程碑 M0–M7 已完成：CLI（`scan`/`init`/`rules`）、6 语言 19 规则、Tree-sitter 解析、Stage 2 LLM 确认（Claude/OpenAI）、text/JSON/SARIF/GitHub 四种输出、baseline / inline suppression / `--fail-on` / `--diff` 等 CI 工具链。
- 质量基线：572 个测试全部通过（`npm run test:run`），精度 ratchet 为 precision ≥ 95.8% / recall ≥ 92.0%（`npm run precision`）。**任何改动不得使这两项回退。**
- 唯一未完成的开发项是 M8：`docs/design/GITHUB_APP.md` 只有设计稿，且文档在 §5 中途截断（§5 评论格式不完整，被引用的 §6 不存在）。
- 另有两项**人工运维动作**不属于 Codex 范围（见 §6）：npm 发布、打 `v0.4.0` tag。

## 1. 目标与非目标

**目标**：交付 GITHUB_APP.md 定义的 MVP——一个无状态、可容器化部署的 GitHub App 服务，在 PR opened/synchronize 时扫描变更文件，把确认的问题以内联评论贴回 PR，并产出 Check Run 结论。

**非目标**（保持与设计稿一致，不要做）：全仓扫描调度、仪表盘、托管 key/计费、App 侧规则管理 UI、autofix commit、多租户 key 加密存储（MVP 为单租户自部署，key 走环境变量）。

## 2. 可复用资产（App 层只做薄编排，核心新增代码目标 < 1000 行）

| 资产 | 位置 | 用途 |
|------|------|------|
| `scan(options, deps)` 库入口 | `src/scanner/orchestrator.ts`（经 `src/scanner/index.ts` 导出） | 完整两阶段扫描；`ScanOptions` 已含 `diffPath`（按 PR 变更行过滤）、`baselinePath`、`dryRun` |
| PR review 载荷生成 | `src/reporter/github.ts` | 已能生成 summary + 内联评论的 GitHub review JSON |
| diff 解析/行过滤 | `src/scanner/diff.ts` | 已针对伪装成 diff 的内容做过加固 |
| baseline / suppression / fingerprint | `src/scanner/baseline.ts`、`src/scanner/suppression.ts` | 幂等去重用 `codeguardFingerprint/v1` |
| 配置加载 | `src/config/loader.ts`（cosmiconfig，`.codeguard.yml`） | App 需读取目标仓库内的配置 |
| 成本封顶 | 配置项 `llm.maxCostUSD` | 每 PR LLM 成本上限 |
| 参考工作流 | `docs/examples/pr-review.yml` | BYO-key Actions 版本的行为基准，App 行为应与其对齐 |

## 3. 技术约束

- TypeScript 严格模式、ESM、Node ≥ 18，测试用 vitest，风格与现有代码一致（eslint 配置已存在）。
- App 框架选型：**Hono + `@octokit/app` + `@octokit/webhooks`**（轻量、无状态、便于容器化）。若实施中发现集成成本明显更低，可换 Probot，但需在 PR 描述里说明理由。
- 服务必须无状态：不持久化代码内容，只在评论隐藏标记中存 fingerprint。
- 不得改变现有 CLI 行为、公开配置格式和输出格式；`npm run test:run`、`npm run precision`、`npm run typecheck`、`npm run lint` 全程保持绿色。

## 4. 任务分解（按序执行，每个任务单独 commit）

### T0 — 库入口与 workspace 改造

现状：`package.json` 只有 CLI bin 入口（tsup entry 为 `src/cli/index.ts`），没有可供外部 import 的库导出。

- 新增 `src/lib.ts`，导出 App 需要的最小面：`scan`、`ScanOptions`、`ScanResult`、配置加载函数、`src/reporter/github.ts` 的载荷生成函数、fingerprint 计算函数。
- `tsup.config.ts` 增加第二个 entry（`src/lib.ts`），`package.json` 增加 `exports` 映射（`"."` → lib，保留 bin）。
- 注意 tsup 的 `onSuccess` 会把 tree-sitter 的 `.wasm` 复制进 `dist/tree-sitter/`；库模式下解析器定位 wasm 的逻辑（`src/parser/tree-sitter/runtime.ts`）必须仍然工作，如有路径假设需以最小改动解除。
- 根 `package.json` 加 `"workspaces": ["app"]`；新建 `app/` 子包 `@ai-codeguard/github-app`，依赖根包。
- 验收：根包所有既有脚本绿色；`app/` 内可以 `import { scan } from 'ai-codeguard'` 并通过一个冒烟测试实际扫描 `tests/fixtures/` 中的文件。

### T1 — Webhook 服务骨架

- `app/src/server.ts`：Hono HTTP 服务，`POST /webhook` 校验 `X-Hub-Signature-256`（`@octokit/webhooks`），`GET /healthz` 健康检查。
- `app/src/auth.ts`：App JWT → installation token（`@octokit/app`），凭据来自环境变量 `APP_ID`、`PRIVATE_KEY`、`WEBHOOK_SECRET`。
- 只订阅 `pull_request` 的 `opened`/`synchronize`/`reopened`；其余事件 202 忽略。
- 验收：单元测试覆盖签名校验（错误签名 401）、事件过滤；不依赖真实 GitHub。

### T2 — PR 扫描流水线

`app/src/pipeline.ts`，编排一次 PR 处理：

1. 通过 API 取 PR 变更文件列表与统一 diff（`Accept: application/vnd.github.diff`）。
2. 只把变更中受支持语言的文件按 head SHA 下载到临时目录（contents API，不 clone 全仓）；同时若仓库根存在 `.codeguard.yml` 和 `.codeguard-baseline.json` 也一并取下。
3. diff 文本写入临时文件，调用 `scan({ paths: 变更文件, diffPath, baselinePath?, dryRun: 无 LLM key, ... })`。
4. 全程 try/finally 清理临时目录；单文件与总量设上限（如单文件 1 MB、总量 20 MB，超限跳过并在汇总评论标注）。
- 验收：用 mock 的 octokit + `tests/fixtures/` 文件跑通端到端单测：给定构造的 PR 事件与 diff，产出 findings，且 diff 行过滤生效（触碰文件中未变更行的历史 finding 不出现）。

### T3 — 评论、幂等与 Check Run

`app/src/review.ts`：

- 复用 `src/reporter/github.ts` 生成 review 载荷提交内联评论；每条内联评论 body 末尾加隐藏标记 `<!-- codeguard-fp: <codeguardFingerprint/v1> -->`。
- 幂等：提交前列出 PR 既有评论，按隐藏标记去重——同一 fingerprint 不重复评论；`synchronize` 后已修复的 finding 不删除旧评论（保留讨论），只在汇总中更新计数。
- 汇总评论：一条可更新的评论（按固定隐藏标记定位并编辑而非新增），含严重度统计、baseline 吸收数、Stage 2 dismissed 折叠区（`<details>`）、无 key 时的「未经 AI 分诊」标注。
- Check Run：`--fail-on` 语义映射——按配置阈值有确认 finding 则 `failure`，否则 `success`；`neutral` 用于扫描本身出错。
- 验收：单测覆盖「重复事件零新评论」「新增 finding 只补差量」「汇总评论是编辑而非新增」「check 结论映射」。

### T4 — BYO-key 与降级模式

- LLM key 从部署环境变量读取（`CODEGUARD_API_KEY` 等，与 CLI 一致的解析逻辑复用 `src/config/`）；无 key 时 `dryRun: true`，评论明确标注 Stage-1-only。
- 尊重目标仓库 `.codeguard.yml` 的 `llm.maxCostUSD`；达到上限时停止 Stage 2，剩余候选按 dismissed-by-budget 记入汇总。
- 验收：两种模式各有单测；不存在把 key 写入日志/评论的路径（测试断言日志脱敏）。

### T5 — 测试与 CI

- `app/tests/`：上述各任务的单测 + 一个 fixture 驱动的集成测试（伪造完整 webhook → 断言最终的 octokit 调用序列）。
- `.github/workflows/ci.yml` 增加 app workspace 的 build + test job；不动现有 job。
- 验收：根包 + app 包在 CI 全绿；根包测试数量不减少。

### T6 — 部署物与文档收尾

- `app/Dockerfile`（多阶段构建，运行时仅含 dist + wasm 资产）+ `app/README.md`（环境变量清单、App 权限/事件清单：`pull_requests: write`、`checks: write`、`contents: read`，订阅 `pull_request`）。
- 补全 `docs/design/GITHUB_APP.md`：写完 §5 评论格式（与实际实现一致），补上被引用的 §6（Actions 复用备选方案），状态从「设计稿」改为「MVP 已实现」。
- 更新根 `README.md` 的 M8 行与 Current Status。
- 验收：文档与实现一致，无悬空引用。

## 5. 总体完成定义（DoD）

1. 根包 `test:run` / `precision` / `typecheck` / `lint` 全绿，测试数 ≥ 572。
2. app 包测试全绿，覆盖幂等、降级、行过滤、check 映射四个关键行为。
3. `docker build` 成功，容器内 `GET /healthz` 返回 200。
4. GITHUB_APP.md、README.md 与实现一致。
5. 每个任务一个独立 commit，信息清晰；全部推送到工作分支。

## 6. 范围外（人工动作，Codex 不做）

- npm registry 发布（`npm publish`，`prepublishOnly` 已配置）。
- 合并到 main 后手动触发 `release` workflow 打 `v0.4.0` tag。
- 在 GitHub 上实际注册 GitHub App、配置 webhook URL 与私钥、部署容器。

## 7. 风险提示

- **wasm 资产定位**是 T0 最可能踩坑的点：CLI 模式下 wasm 相对 `dist/index.js` 定位，库被 `app/` import 后路径基准会变，先写一个失败测试再修。
- GitHub review API 对已过期 diff 位置的评论会 422：提交 review 前用 diff 校验每条评论的 `line/side` 仍在有效 hunk 内，无效的降级进汇总评论。
- 大 PR：变更文件超过阈值（如 300 个）时降级为仅汇总评论 + check，不逐条内联，避免 API 限流。
