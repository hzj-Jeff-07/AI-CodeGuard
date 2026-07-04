# Stage 2 缓存设计（CACHING）

> 本文描述当前已实现的 Stage 2 LLM 结果磁盘缓存。对应实现：`src/cache/index.ts`，接线点：`src/scanner/orchestrator.ts` → `src/analyzer/index.ts`。

## 1. 目标

Stage 2 会对每个 Stage 1 候选 finding 发起一次 LLM 调用。同一仓库反复扫描时，绝大多数代码片段没有变化，重复调用是纯浪费。缓存的目标是：

- 重复扫描时，未变化的 finding **不再产生 LLM 调用**
- 第二次扫描的验收状态：`llmCalls = 0`、`estimatedCost = 0`、findings 与第一次完全一致

## 2. 缓存键

缓存键是以下六元组的 SHA-256 哈希（见 `hashCacheKey`）：

| 字段 | 说明 |
|---|---|
| `ruleId` | 命中的规则 ID |
| `provider` | LLM 提供方（claude / openai） |
| `model` | 模型 ID |
| `snippet` | 可疑代码片段 |
| `context` | 片段上下文 |
| `includeFix` | 是否要求修复建议（`--fix`） |

任何一项变化（换模型、换规则、代码修改、开关 `--fix`）都会产生新的键，不会读到过期结论。键内还包含 `schemaVersion`，缓存记录结构升级时旧记录自动失效。

## 3. 存储布局

`FileCacheStore` 将每条记录存为一个 JSON 文件，按哈希前两位分片：

```text
.codeguard-cache/
├── 3f/
│   └── 3fa8c1…e2.json
└── a0/
    └── a0517b…9d.json
```

记录内容（`CachedAnalysis`）：`confirmed`、`llmAnalysis`（confidence / reasoning）、可选 `fix`、原始 token 用量、`cachedAt` 时间戳、`schemaVersion`。

序列化只用 `JSON.parse` / `JSON.stringify`，不存在反序列化执行风险。

## 4. TTL 与清理

- `cache.ttl`（秒，默认 86400）：读取时超龄记录视为 miss；`ttl <= 0` 表示永不过期
- `prune()` 遍历分片目录，删除过期或损坏的记录并清掉空分片目录
- `.codeguard-cache/` 已加入 `.gitignore` 默认忽略

## 5. 运行时行为

`analyzeFindings()` 中的处理顺序（每个候选）：

1. 查缓存 → 命中：`cacheHits += 1`，**不计入 `llmCalls` 也不累加 `estimatedCost`**；`confirmed` 记录还原为带 `llmAnalysis` 的 finding（描述标注 “cached”），未确认记录照常从报告中过滤
2. 未命中 → 正常调用 LLM，结果写回缓存（写失败静默忽略，不影响扫描）
3. 缓存读失败同样静默降级为未命中 —— 缓存永远不会让扫描失败

预算交互：缓存命中不消耗 `llm.maxCostUSD` 预算；预算耗尽后剩余候选保留为 Stage 1 finding（与无缓存时一致）。

## 6. 配置

```yaml
cache:
  enabled: true          # 代码默认 false；init 生成的模板默认 true
  directory: .codeguard-cache
  ttl: 86400
```

`--dry-run`（Stage 1 only）不触碰缓存。

## 7. 已知边界

- 缓存键基于片段文本而非文件哈希：同一段代码移动位置仍命中（预期行为），但文件级别的“未变化直接跳过”尚未实现
- `MemoryCacheStore` 仅用于测试注入
- 没有跨机共享机制；CI 中可通过 `actions/cache` 缓存 `.codeguard-cache/` 目录实现复用
