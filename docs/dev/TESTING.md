# AI-CodeGuard 测试说明

> 本文档描述 **当前测试体系已经覆盖的内容、执行方式与已知空白**。它反映的是当前仓库事实，而不是理想化测试目标。

## 1. 当前测试状态

截至 **2026-04-12**，当前项目测试结果为：

```bash
npm run build
npm run test:run
```

结果：

- build 通过
- `9` 个测试文件通过
- `171` 个测试通过

这说明当前 **两级扫描基线是稳定的**。

## 2. 当前测试工具链

项目当前使用：

- `Vitest`

相关脚本来自 `package.json`：

- `npm test` -> `vitest`
- `npm run test:run` -> `vitest run`

`vitest.config.ts` 当前配置了：

- 测试文件匹配：`tests/**/*.test.ts`
- coverage include：`src/**/*.ts`
- coverage exclude：`src/types/**`

注意：当前仓库虽然配置了 coverage include/exclude，但本轮验证主要依据是**测试通过状态**，不是覆盖率百分比报告。

## 3. 当前测试目录结构

当前测试目录如下：

```text
tests/
├── fixtures/
├── integration/
│   ├── rules-command.test.ts
│   └── scanner.test.ts
└── unit/
    ├── analyzer.test.ts
    ├── config.test.ts
    ├── parser.test.ts
    ├── reporter.test.ts
    ├── rules-builtin.test.ts
    ├── rules-command.test.ts
    └── rules-engine.test.ts
```

这意味着当前测试结构非常清晰：

- `unit/` 负责模块级验证
- `integration/` 负责扫描主流程验证
- `fixtures/` 提供安全/漏洞样例

## 4. 当前 unit tests 覆盖范围

### 4.1 `tests/unit/config.test.ts`

覆盖内容：

- `ConfigSchema` 默认值
- 枚举校验
- `maxConcurrency` 边界
- 可选字段解析
- `DEFAULT_CONFIG` 与 schema 默认值一致性
- `loadConfig()` 的环境变量覆盖行为
- `rules.custom` 配置字段可被 schema 接受

### 4.2 `tests/unit/parser.test.ts`

覆盖内容：

- `detectLanguage()` 扩展名映射
- `getAdapter()` 返回正确适配器
- `getSupportedExtensions()` 返回支持扩展名
- `parse()` 产出 ASTree root
- Tree-sitter 归一化 parser 对 function call / template string / string concat / hardcoded credential / Python f-string 的识别
- 多行动态调用参数与 Python f-string 的识别
- `walkAST()` 的 enter / leave / parent 行为
- JS / TS / Python 适配器的调用信息抽取

### 4.3 `tests/unit/rules-engine.test.ts`

覆盖内容：

- `createRuleContext()`
- `getRules()`
- `getAllRuleIds()`
- `getRuleById()`
- `runRules()`
- `loadRules()` 的 custom-rule 加载 / 目录递归 / duplicate ID / invalid YAML / invalid schema
- preset / disable 行为
- 去重逻辑
- language filtering

### 4.4 `tests/unit/rules-command.test.ts`

覆盖内容：

- `rules --list` 默认输出
- `rules validate` 成功 / 失败路径
- `rules create` scaffold 生成
- `rules create --force` 覆盖行为

### 4.5 `tests/unit/rules-builtin.test.ts`

覆盖内容：

- 全部 13 条 built-in rules 的命中与忽略场景
- fixture 级 TypeScript 样例扫描

### 4.5 `tests/unit/reporter.test.ts`

覆盖内容：

- JSON 输出合法性与字段完整性
- SARIF 输出合法性、schema/version、severity 映射、location、rules、fix、llmAnalysis markdown
- text 输出中的标题、规则 ID、路径、代码片段、summary、LLM summary、estimated cost

### 4.6 `tests/unit/analyzer.test.ts`

覆盖内容：

- provider 选择
- 缺少 API key 的错误路径
- `maxConcurrency` 调度上限
- `maxCostUSD` 达到预算后的截断行为

这部分说明 Stage 2 核心编排逻辑已经进入直接单元测试保护范围。

## 5. 当前 integration tests 覆盖范围

### `tests/integration/scanner.test.ts`

当前集成测试覆盖：

- 扫描 vulnerable fixtures 能发现问题
- 扫描 safe fixtures 不应报问题
- findings ID 连续编号
- severity 从规则定义继承
- 输出路径是相对路径且统一使用 `/`
- `outputFile` 可写出报告文件
- 不支持的扩展名会被跳过
- `sarif` 输出可生成并解析
- custom rules finding 可进入最终 `findings`
- `dryRun: true` 时 `llmCalls = 0` / `estimatedCost = 0`
- 非 dry-run 时会进入 Stage 2
- `fix: true` 时会产生 `Finding.fix`
- 缺少 API key 时会报错

### `tests/integration/rules-command.test.ts`

当前集成测试覆盖：

- `rules test` 会复用 `scan()` 主流程命中 custom finding
- `rules test` 强制停在 Stage 1，因此 `llmCalls = 0`
- `rules test` 不需要 API key

## 6. 当前 fixtures 的作用

`tests/fixtures/` 当前承担两类作用：

1. **vulnerable fixtures**
   - 证明扫描器能在已知危险样例中报出 findings
2. **safe fixtures**
   - 证明扫描器不会对基础安全样例无差别误报

它们仍然是当前扫描主流程可信度的重要组成部分。

## 7. 当前测试明确验证了哪些现实边界

当前测试除了验证“能工作”，还锁定了这些边界：

- 支持语言就是 JS / TS / Python
- 当前扫描结果路径应是相对路径
- 当前 reporter version 是 `0.1.0`
- 当前 SARIF version 是 `2.1.0`
- `--dry-run` 会停在 Stage 1
- Stage 2 通过依赖注入可避免真实外网调用
- 达到预算后，剩余未分析项保留为 Stage 1 findings

## 8. 当前未覆盖或覆盖较弱的地方

下面这些仍然是当前测试体系的空白或弱覆盖区：

1. **没有真实外部 Provider 的端到端验收测试**
   - 当前 Stage 2 测试通过依赖注入隔离网络调用。
2. **没有 pricing table 的独立校准测试**
   - 目前主要通过行为测试覆盖预算截断分支。
3. **没有 cache 行为测试**
   - 因为当前扫描主流程未使用 cache。
4. **没有 GitHub Action / CI 集成测试**
   - 因为仓库没有对应产品化链路。
5. **没有性能基准测试**
   - 当前测试重心是正确性，不是吞吐或耗时基准。
6. **没有跨平台端到端 CLI 冒烟矩阵**
   - 当前主要确认了 Windows 路径兼容与基础行为。

## 9. 当前最推荐的验证命令

### 本地完整回归

```bash
npm run build
npm run test:run
```

### 开发中交互式跑测

```bash
npm test
```

### 修改 scanner / analyzer / parser / rules / reporter 后的最低验证要求

至少应重新执行：

```bash
npm run build
npm run test:run
```

如果改动影响主流程输出，建议额外手动跑：

```bash
node dist/index.js scan ./src --dry-run --output text
node dist/index.js scan ./src --output json
node dist/index.js scan ./src --output sarif
```

## 10. 后续演进建议

如果下一阶段继续开发，测试体系应按以下顺序补强：

1. **补真实 provider 的受控验收路径**
2. **为 pricing / unknown-model / budget overshoot 行为补更多测试**
3. **为 Tree-sitter 归一化 AST 继续补精度与兼容性测试**
4. **补 custom rules 的加载 / 校验 / 失败路径 / 集成扫描测试**
5. **GitHub Action 上线后，新增最小 CI 集成测试**

## 11. 结论

AI-CodeGuard 当前测试体系的特点是：

- 覆盖面不算“全产品级”
- 但对当前两级扫描基线来说，已经足够扎实
- analyzer、parser、rules、reporter、scanner 主流程几层，已经有明确回归保护
- custom rules runtime 已落地，但测试保护仍是下一步要补的缺口
