# AI-CodeGuard 核心模块设计文档

> 本文档聚焦 **当前代码库中的实际模块边界与接口**，并在每个模块中明确区分“已实现”和“计划中”。

> 术语约定：**Phase 1** 指当前已交付的产品阶段；**Stage 1** 指当前运行时中的静态预过滤；**Stage 2** 指当前运行时中的 LLM 深度分析阶段。

## 1. Scanner Orchestrator（扫描协调器）

### 1.1 职责

当前扫描协调器负责：
- 根据用户输入路径和配置发现目标文件
- 识别语言并调用 Tree-sitter 归一化 parser
- 加载 built-in rules 与可选 custom rules
- 生成 Stage 1 findings
- 在需要时调用 Stage 2 analyzer
- 调用 reporter 输出结果

### 1.2 当前接口

```typescript
interface ScanOptions {
  paths: string[];
  config: CodeGuardConfig;
  fix: boolean;
  dryRun: boolean;
  output: OutputFormat;
  outputFile?: string;
  verbose: boolean;
}

interface ScanResult {
  files: number;
  suspicious: number;
  findings: Finding[];
  skipped: SkippedFile[];
  duration: number;
  llmCalls: number;
  estimatedCost: number;
}
```

### 1.3 当前行为说明

`scan()` 当前真实执行逻辑：

1. `discoverFiles()` 找出待扫描文件
2. `loadRules()` 加载 built-in + optional custom rules
3. 逐个文件执行：
   - `detectLanguage()`
   - `readFile()`
   - `parse()`
   - `runRules()`
4. `createStage1Findings()` 生成基础 findings
5. 若 `dryRun === false` 且存在 suspicious nodes，则调用 `analyzeFindings()`
6. `generateReport()` 生成输出

### 1.4 当前实现边界

尚未实现：
- 缓存复用
- `.gitignore` 联动过滤

## 2. File Discovery

### 2.1 当前实现

文件发现使用 `fast-glob`，并结合：
- CLI 输入路径
- `config.scan.include`
- `config.scan.exclude`
- 支持扩展名过滤

### 2.2 当前优先级

1. 若传入的是带扩展名的路径，则直接作为目标文件
2. 若传入的是目录，则拼接 include patterns
3. 使用 `exclude` 过滤
4. 仅保留支持的扩展名

### 2.3 已修复问题

当前实现已处理 Windows 下路径分隔符兼容问题：
- 在构造 glob pattern 前统一转为 `/`
- 避免 `fast-glob` 在 Windows 绝对路径模式下匹配失败

### 2.4 未实现项

以下设计想法尚未落地：
- `.gitignore` 联动过滤
- 增量扫描
- 文件级缓存跳过

## 3. Parser 模块（Tree-sitter 归一化解析器）

### 3.1 当前架构

当前 parser 已升级为 **Tree-sitter 驱动的归一化提取器**：

```text
source code
  └─ Tree-sitter parse
      └─ normalize selected nodes into ASTree
          └─ preserve compatibility for current rules
```

### 3.2 当前提取的节点类型

- `function_call`
- `template_string`
- `string_concat`
- `assignment`
- `unknown`（program root）

### 3.3 当前支持语言

| 语言 | 适配器 |
|------|--------|
| JavaScript | `javascriptAdapter` |
| TypeScript | `typescriptAdapter` |
| Python | `pythonAdapter` |
| Go | `goAdapter` |
| Java | `javaAdapter` |
| PHP | `phpAdapter` |

### 3.4 当前限制

当前 parser 仍然不提供：
- Rust / C++ 等其余语言解析
- 跨文件语义分析
- 污点传播或 CFG
- 直接向规则层暴露 Tree-sitter 原生节点

## 4. AST Walker

### 4.1 当前接口

```typescript
interface ASTVisitor {
  enter?(node: ASTNode, parent: ASTNode | null): boolean | void;
  leave?(node: ASTNode, parent: ASTNode | null): void;
}
```

### 4.2 当前行为

`walkAST()` 会深度优先遍历根节点及其 children，用于让所有规则逐节点检查。

## 5. Rule Engine（规则引擎）

### 5.1 当前职责

当前规则引擎负责：
- 聚合 built-in rules
- 加载并编译 custom rules
- 按语言过滤适用规则
- 遍历 AST 节点并执行规则
- 对重复命中位置做去重
- 对同一 ruleId 下、位置完全被另一条命中"包含"的嵌套重复项做抑制（如 `db.Query(fmt.Sprintf(...))` 内联嵌套只保留外层一条）

### 5.2 当前规则集合

当前共有 13 条 built-in rules：
- CG-001 SQL Injection
- CG-002 Command Injection
- CG-003 Code Injection (eval)
- CG-010 Cross-Site Scripting (XSS)
- CG-011 DOM-based XSS
- CG-020 Hardcoded Credentials
- CG-021 Weak Cryptography
- CG-030 Path Traversal
- CG-031 Arbitrary File Read/Write
- CG-040 Sensitive Data Exposure
- CG-041 Insecure Deserialization
- CG-050 Security Misconfiguration
- CG-060 SSRF

### 5.3 当前限制

当前没有实现：
- 更强的语义 / 数据流规则系统

## 6. Analyzer 模块

### 6.1 当前仓库状态

Analyzer 已经是当前运行时的一部分，而不是仅停留在接口预留：
- `src/analyzer/index.ts` 负责 Stage 2 编排
- `src/analyzer/providers/claude.ts` / `openai.ts` 负责 SDK 差异隔离
- `scan()` 会在非 dry-run 路径调用 Analyzer

### 6.2 当前运行时能力

当前已实现：
- provider 选择
- API key 校验
- Prompt 构建
- JSON 响应解析
- `llmAnalysis` 写回
- 可选 `fix` 写回
- 并发控制
- 预算截断
- 依赖注入测试替身

### 6.3 当前限制

当前仍未实现：
- cache
- fallback / retry 策略
- 未知模型的自动定价发现
- 自动修改源码

## 7. Reporter 模块（报告生成）

### 7.1 当前支持格式

当前 Reporter 已实现：
- `text`
- `json`
- `sarif`

### 7.2 当前输出能力

当前输出层可以真实承载：
- Stage 1 findings
- `llmAnalysis`
- `fix`
- `llmCalls`
- `estimatedCost`

### 7.3 当前限制

当前未实现：
- GitHub Action 封装
- 自动上传 SARIF
- 版本发布与 CI 分发链路

## 8. Config 模块（配置管理）

### 8.1 当前职责

配置模块负责：
- 搜索配置文件
- 解析配置
- 用 Zod 校验
- 应用环境变量覆盖
- 输出结构化 `CodeGuardConfig`

### 8.2 当前真实生效与未生效项

当前真实用于 `scan()` 的主要是：
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

当前尚未真正参与运行时控制的包括：
- 全部 `cache.*`

## 9. CLI 命令状态表

| 命令 | 当前状态 | 说明 |
|------|----------|------|
| `scan` | 已实现 | 当前执行 Stage 1，并可选进入 Stage 2 |
| `init` | 已实现 | 生成 `.codeguard.yml` |
| `rules --list` | 已实现 | 当前列出 built-in rules |
| `--output-file` | 已实现 | 写出报告文件 |
| `--output sarif/json/text` | 已实现 | 选择输出格式 |
| `--fix` | 已实现 | 仅在 Stage 2 路径请求修复建议 |
| `--dry-run` | 已实现 | 强制停在 Stage 1 |
| `rules validate` | 已实现 | 校验 YAML 解析、schema 与 duplicate ID |
| `rules create` | 已实现 | 生成 custom-rule scaffold，支持 `--force` |
| `rules test` | 已实现 | 复用 `scan()` 路径执行 Stage 1-only custom-rule smoke test |
| `report` | 未实现 | 文档中旧提法，应视为规划项 |

## 10. 测试与稳定性

### 10.1 当前测试覆盖范围

当前测试覆盖：
- parser
- analyzer
- reporter
- config
- rules engine
- built-in rules
- scanner integration

### 10.2 当前验证结果

2026-04-12 运行结果：
- 9 个测试文件通过
- 171 个测试通过

### 10.3 当前结论

对当前范围而言，代码库已经具备：
- 可构建
- 可测试
- 可运行的两级扫描主流程
- 可运行的 Tree-sitter 归一化 parser
- 可运行的 custom rules runtime wiring

## 11. 当前文档使用建议

- 本文档描述的是 **已实现的模块边界**
- 如果某项能力只存在于 ADR 或旧设计里，但当前源码没有它，应视为“待实现”
- 任何对外技术说明，都应优先以本文档和当前源码行为为准
