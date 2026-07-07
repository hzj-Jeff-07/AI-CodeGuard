# AI-CodeGuard GitHub App（PR 机器人）设计

> 状态：设计稿（2026-07-06）。商用路径第二步：以 BYO-key 免费公测形态落地 PR 评论机器人，积累案例与精度数据；数据成立后再上托管付费层。本文只描述设计，不宣称已实现。

## 1. 定位与差异化

不做"又一个 SAST"。定位是 **PR 内的 AI 告警分诊层**：

- Stage 1 静态预筛只扫 **PR 变更的文件**（秒级、零 LLM 成本）
- Stage 2 用**客户自己的 API key**（BYO-key）对候选做 confirm/dismiss 分诊，只把确认的真问题以内联评论贴回 PR，附解释与修复建议
- 已被 dismiss 的候选折叠进一条汇总评论（可展开），保持可审计而不刷屏

价值主张一句话：**"告警从 N 条降到确认的几条，每条带理由"**——这依赖已建成的分诊准确率 harness 提供数字背书。

## 2. MVP 范围（公测版）

| 包含 | 不包含（后续） |
|------|----------------|
| PR opened / synchronize 触发，扫 diff 涉及文件 | 全仓扫描调度、定时任务 |
| 内联评论（finding 行）+ 一条汇总评论（严重度统计、dismissed 折叠区、baseline 吸收数） | 仪表盘、组织级视图 |
| BYO-key：installation 级配置 `ANTHROPIC_API_KEY`（或 OpenAI） | 托管 key / 计费 |
| 尊重仓库内 `.codeguard.yml`、baseline 文件、inline suppression | App 侧规则管理 UI |
| Check Run 结论（`--fail-on` 语义映射到 check 状态） | 自动修复 PR（--fix 建议已有，autofix commit 后续） |
| 幂等：同一 commit 重复事件不重复评论（按 `codeguardFingerprint/v1` 去重） | |

## 3. 架构

```text
GitHub webhook (pull_request events)
   │
   ▼
App 服务（Probot / Hono + octokit，无状态，容器化）
   ├─ 校验 webhook 签名 → 获取 installation token
   ├─ 拉取 PR diff 文件列表 → checkout 变更文件（浅、稀疏）
   ├─ 调用现有 scan() 库入口（非 CLI 子进程）：
   │    paths = 变更文件；baseline = 仓库根 .codeguard-baseline.json（若存在）
   │    dryRun = 无客户 key 时 true（纯 Stage 1 降级模式）
   ├─ findings → 按 diff hunk 过滤（只评论 PR 实际触碰的行）
   ├─ 幂等去重：对比已有评论中的 fingerprint 隐藏标记
   └─ 输出：内联 review comments + 汇总评论 + Check Run
```

关键复用：`scan()`、baseline、suppression、fingerprint、成本控制（`llm.maxCostUSD` 每 PR 封顶）全部已存在——App 层只是薄的编排 + GitHub API 适配。**核心新增代码估计 < 1000 行。**

## 4. BYO-key 与隐私

- key 存储：installation 级 secret（App 后端加密存储，或 MVP 期直接读仓库 Actions secret 由复用 composite Action 的变体承载——见 §6 备选）
- 发送给 LLM 的内容 = 现有 Stage 2 payload（snippet + ±3 行 context + 元数据），**不发送整个文件/仓库**；文档中明示字段清单
- 无 key 降级：纯 Stage 1 模式照常工作（评论标注"未经 AI 分诊"），保证免费路径可用
- 数据保留：App 侧不持久化代码内容，只存 fingerprint 与统计计数

## 5. 评论格式（草案）

内联评论：

```
