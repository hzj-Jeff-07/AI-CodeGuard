# AI-CodeGuard 架构设计

> 本文档描述 **当前代码库已实现的架构**、数据流、模块职责与已知边界。

> 术语约定：**Phase 1** 指当前已交付的产品阶段；**Stage 1** 指当前运行时中的静态预过滤；**Stage 2** 指当前运行时中的 LLM 深度分析阶段。

## 1. 当前系统概览

AI-CodeGuard 当前是一个 **Node.js + TypeScript CLI 安全扫描器**，核心能力是：

- 扫描 JavaScript / TypeScript / Python 文件
- 通过 Tree-sitter 归一化解析提取可疑结构
- 使用 built-in rules + 可选 custom rules 执行静态预过滤
- 在非 `dryRun` 情况下对可疑结果执行 Stage 2 LLM 二次确认
- 生成 text / json / sarif 报告

### 1.1 当前运行时数据流

```text
CLI (Commander.js)
  └─ scan / init / rules
       │
       ▼
Config Loader (cosmiconfig + Zod)
       │
       ▼
Scanner Orchestrator
  ├─ File discovery (fast-glob)
  ├─ Language detection by extension
  ├─ Tree-sitter-backed normalized parser
  ├─ Rule loading
  │   ├─ built-in rules
  │   └─ optional custom YAML rules
  ├─ Stage 1 rule execution
  ├─ Analyzer (Stage 2, optional)
  │   ├─ Claude provider
  │   └─ OpenAI provider
  └─ Reporter (text / json / sarif)
```

### 1.2 与更大设计目标的差异

项目原始设计目标除了两级管道外，还包括更完整的 parser、custom rules 能力、cache 与 GitHub 集成。当前实际状态是：

- **两级管道已接入运行时**
- parser 已升级为 Tree-sitter，并继续向规则层暴露兼容的归一化 AST
- custom rules 已接入 `scan()` 运行时，且 `rules validate/create/test` 已提供当前 CLI 工作流
- cache / GitHub Action 仍未落地

## 2. 当前目录结构

```text
ai-codeguard/
├── src/
│   ├── analyzer/
│   │   ├── index.ts
│   │   └── providers/
│   │       ├── claude.ts
│   │       └── openai.ts
│   ├── cli/
│   │   ├── index.ts
│   │   └── commands/
│   │       ├── scan.ts
│   │       ├── init.ts
│   │       └── rules.ts
│   ├── scanner/
│   │   ├── index.ts
│   │   └── orchestrator.ts
│   ├── parser/
│   │   ├── index.ts
│   │   ├── ast-walker.ts
│   │   └── languages/
│   │       ├── javascript.ts
│   │       ├── python.ts
│   │       └── index.ts
│   ├── rules/
│   │   ├── custom.ts
│   │   ├── engine.ts
│   │   ├── index.ts
│   │   └── built-in/
│   │       ├── injection.ts
│   │       ├── xss.ts
│   │       ├── auth.ts
│   │       ├── path.ts
│   │       ├── data.ts
│   │       ├── config.ts
│   │       ├── ssrf.ts
│   │       └── index.ts
│   ├── reporter/
│   │   ├── index.ts
│   │   ├── text.ts
│   │   ├── json.ts
│   │   └── sarif.ts
│   ├── config/
│   │   ├── loader.ts
│   │   ├── schema.ts
│   │   ├── defaults.ts
│   │   └── index.ts
│   └── types/
│       ├── ast.ts
│       ├── config.ts
│       ├── finding.ts
│       ├── rule.ts
│       └── index.ts
├── docs/
├── tests/
├── README.md
├── ARCHITECTURE.md
├── package.json
├── tsconfig.json
├── tsup.config.ts
└── vitest.config.ts
```

## 3. 当前完整扫描流程

### 3.1 运行流程

```text
用户执行: ai-codeguard scan ./src

1. Commander 解析命令
2. loadConfig() 加载配置
3. discoverFiles() 生成目标文件列表
4. loadRules() 合并 built-in + optional custom rules
5. detectLanguage() 按扩展名识别语言
6. parse() 执行 Tree-sitter 归一化解析
7. runRules() 对 ASTree 执行规则匹配
8. createStage1Findings() 生成基础 findings
9. 若 dryRun=false 且存在 suspicious nodes，则 analyzeFindings() 执行 Stage 2
10. generateReport() 输出 text / json / sarif
```

### 3.2 关键事实

- 文件发现使用 `fast-glob`
- 当前支持扩展名：`.js` `.jsx` `.mjs` `.cjs` `.ts` `.tsx` `.py`
- 当前 parser 通过 Tree-sitter 构建归一化 AST，并保留 `function_call` / `template_string` / `string_concat` / `assignment` 等规则依赖节点
- `--dry-run` 会强制停在 Stage 1
- 非 `dryRun` 路径会根据 `llm.provider` 选择 Claude 或 OpenAI
- Stage 2 会把确认结果写入 `Finding.llmAnalysis`
- `--fix` 打开时，Stage 2 还会尝试生成 `Finding.fix`
- 未被 Stage 2 确认的 findings 会从最终结果中过滤掉
- 达到 `llm.maxCostUSD` 后，不再启动新的 LLM 请求；剩余未分析项保留为 Stage 1 findings
- `rules.custom` 当前可指向 YAML 文件或目录；路径错误和规则格式错误会 fail fast

## 4. 关键数据结构

### 4.1 AST / 节点模型

```typescript
export type Language = 'javascript' | 'typescript' | 'python';

export interface ASTNode {
  type: StandardNodeType;
  rawType: string;
  text: string;
  location: SourceLocation;
  children: ASTNode[];
  parent: ASTNode | null;
  fields: Record<string, ASTNode | ASTNode[] | undefined>;
}

export interface ASTree {
  root: ASTNode;
  language: Language;
  source: string;
}
```

### 4.2 扫描结果

```typescript
export interface ScanResult {
  files: number;
  suspicious: number;
  findings: Finding[];
  skipped: SkippedFile[];
  duration: number;
  llmCalls: number;
  estimatedCost: number;
}
```

当前实现下：
- `suspicious` = Stage 1 命中的可疑节点数
- `findings` = Stage 2 确认后的 findings + 预算触发时保留的 Stage 1 findings
- `llmCalls` / `estimatedCost` = Stage 2 实际调用指标；`--dry-run` 时为 `0`

## 5. 模块详细设计

### 5.1 CLI 模块

当前 CLI 注册了 3 个顶层命令：

- `scan`：执行扫描
- `init`：生成 `.codeguard.yml`
- `rules`：列出内置规则，并提供 custom-rule workflow 子命令

当前没有实现的 CLI 能力：
- `report` 命令

### 5.2 Scanner Orchestrator

`src/scanner/orchestrator.ts` 是运行入口，负责：

1. 文件发现
2. 规则加载（built-in + optional custom）
3. 遍历文件并执行解析
4. 运行规则
5. 构建 Stage 1 findings
6. 视参数决定是否进入 Stage 2
7. 调用 Reporter

当前行为特点：
- 遇到不支持的扩展名会跳过
- 解析失败会记录到 `skipped`
- Windows 路径已做 `/` 标准化，避免 `fast-glob` 匹配异常
- Analyzer 依赖支持注入，便于单元测试和集成测试隔离真实网络调用
- custom rule 加载失败会直接中止扫描并返回清晰错误

### 5.3 Analyzer 模块

`src/analyzer/index.ts` 负责 Stage 2 编排，当前已实现：

- provider 选择（`claude` / `openai`）
- Prompt 构建
- JSON 响应解析
- 并发控制（`llm.maxConcurrency`）
- 成本估算与预算截断（`llm.maxCostUSD`）
- `llmAnalysis` / `fix` 回填

当前限制：
- 成本估算依赖内置 pricing pattern，不是动态拉取
- 未实现 cache 复用
- 未实现 provider fallback / retry 策略
- `maxCostUSD` 仅在已知定价模型上可用；未知模型会直接报错

### 5.4 Parser 模块

当前 parser 已切换为 **Tree-sitter 驱动的归一化实现**。

它会：
- 通过 `web-tree-sitter` + JS / TSX / Python grammars 解析源码
- 向规则层继续暴露兼容的归一化节点
- 保留当前规则依赖的动态参数标记子节点

当前规则层仍主要消费这些节点：
- `function_call`
- `template_string`
- `string_concat`
- `assignment`

并通过语言适配器解析调用信息：
- callee name
- object
- arguments
- full expression

#### 当前实现边界

- 仍只支持 JS / TS / Python
- 仍未实现跨文件符号解析、CFG 或 taint tracking
- 为兼容现有规则，解析层输出的是归一化 AST，而不是直接暴露 Tree-sitter 原生节点
- 构建产物需要同时携带 `web-tree-sitter` 与 grammar wasm 资产

### 5.5 Rule Engine

当前规则系统由 **TypeScript built-in rules + 运行时编译的 YAML custom rules** 组成。

当前共有 13 条 built-in rules，覆盖：
- SQL Injection
- Command Injection
- Code Injection
- XSS / DOM XSS
- Hardcoded Credentials
- Weak Cryptography
- Path Traversal
- Arbitrary File Read/Write
- Sensitive Data Exposure
- Insecure Deserialization
- Security Misconfiguration
- SSRF

当前 custom rules 的实现边界：
- 通过 `rules.custom` 加载 YAML 文件或目录
- 编译成与 built-in rules 相同的 `check(node, ctx)` 契约
- 共享当前归一化 AST 与 `RuleCheckContext` 能力边界
- 已实现 `rules validate/create/test` CLI，其中 `rules test` 复用 `scan()` 并强制停在 Stage 1

### 5.6 Reporter 模块

当前 Reporter 已完整支持三种输出：

- `text`
- `json`
- `sarif`

当前输出层已能承载：
- Stage 1 findings
- `Finding.llmAnalysis`
- `Finding.fix`
- `llmCalls`
- `estimatedCost`

当前限制：
- 仓库内尚未提供 GitHub Action 打包或上传工作流
- SARIF 已能生成，但还未形成完整 CI 产品链路

### 5.7 Config 模块

当前配置加载优先级为：

```text
CLI 参数 > 环境变量 > 配置文件 > Zod 默认值
```

### 支持的配置文件位置

- `.codeguard.yml`
- `.codeguard.yaml`
- `.codeguard.json`
- `codeguard.config.js`
- `codeguard.config.ts`

### 当前已定义配置域

- `scan`
- `rules`
- `llm`
- `output`
- `cache`

### 当前实际生效情况

已实际参与扫描流程的配置：
- `scan.include`
- `scan.exclude`
- `rules.preset`
- `rules.custom`
- `rules.disable`
- `llm.provider`
- `llm.model`
- `llm.apiKey`
- `llm.maxConcurrency`
- `llm.maxCostUSD`
- `output.file`

已定义但尚未真正驱动扫描行为的配置：
- `cache.*`

## 6. 技术选型（当前代码库视角）

| 组件 | 当前状态 | 说明 |
|------|----------|------|
| 语言 | 已实现 | TypeScript 5.x |
| 运行时 | 已实现 | Node.js ≥ 18 |
| CLI | 已实现 | Commander.js |
| 配置加载 | 已实现 | cosmiconfig + Zod |
| 文件发现 | 已实现 | fast-glob |
| 构建 | 已实现 | tsup |
| 测试 | 已实现 | Vitest |
| 报告输出 | 已实现 | text / json / sarif |
| LLM SDK 依赖 | 已接入主流程 | `@anthropic-ai/sdk`, `openai` |
| Tree-sitter 依赖 | 已接入主流程 | `web-tree-sitter` |
| 日志 | 依赖已安装但未形成统一日志管线 | `pino` |

## 7. 测试与验证状态

截至 2026-04-12，仓库测试状态为：

```bash
npm run build
npm run test:run
```

结果：
- build 通过
- 9 个测试文件通过
- 171 个测试通过

覆盖范围包括：
- parser
- analyzer
- built-in rules
- rules engine
- config
- reporter
- scanner integration

## 8. 已知限制与后续实现缺口

### 当前已知限制

1. 默认非 `dryRun` 扫描在进入 Stage 2 时需要 API key
2. custom rules 已接线，且 `rules validate/create/test` 已提供当前 CLI 工作流
3. 语言支持仅限 JS / TS / Python
4. 没有正式的 GitHub Action 打包与发布产物
5. 成本估算依赖内置模型定价映射，不覆盖所有模型名
6. cache 结构已定义，但当前主流程未使用

### 推荐下一步

1. 强化 Stage 2 的 pricing / cache / live-provider 验证
2. 补 custom rules 更复杂 pattern / 失败路径 / 集成扫描测试，并继续增强 `rules validate/create/test` 的示例与错误提示
3. 补齐 GitHub Action 与 CI 集成文档
4. 评估并扩展更多语言支持
