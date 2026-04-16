# AI-CodeGuard 配置说明

> 本文档描述 **当前代码库已经实现的配置模型、默认值、加载方式与实际生效边界**。

## 1. 一句话结论

当前 AI-CodeGuard 已经具备一套完整的配置结构：

- 配置文件搜索
- Zod 校验与默认值
- 环境变量覆盖
- 结构化 `CodeGuardConfig`

当前真正作用于 `scan()` 主流程的，已经包括：

- `scan.*`
- `rules.preset`
- `rules.custom`
- `rules.disable`
- `llm.*`
- `output.file`
- CLI 传入的输出格式 / 输出文件参数

当前仍未接线的主要是 `cache.*`。

## 2. 配置加载顺序

当前加载流程由 `loadConfig()` 执行，基本顺序是：

```text
配置文件 -> 环境变量覆盖 -> Zod 校验与默认值 -> 返回结构化配置对象
```

在 CLI 调用中，还会叠加命令行参数覆盖，例如：

- `--output`
- `--output-file`
- `--config`

因此从实际效果看，当前优先级可以理解为：

```text
CLI 参数 > 环境变量 > 配置文件 > Schema 默认值
```

## 3. 支持的配置文件位置

当前配置加载器会搜索以下位置：

- `.codeguard.yml`
- `.codeguard.yaml`
- `.codeguard.json`
- `codeguard.config.js`
- `codeguard.config.ts`

也可以显式指定配置路径：

```bash
node dist/index.js scan ./src --config ./configs/codeguard.yml
```

## 4. 配置结构总览

当前顶层配置结构如下：

```typescript
interface CodeGuardConfig {
  scan: ScanConfig;
  rules: RulesConfig;
  llm: LLMConfig;
  output: OutputConfig;
  cache: CacheConfig;
}
```

## 5. Schema 默认值

### 5.1 `scan`

```yaml
scan:
  include:
    - "**/*.{ts,js,py}"
  exclude:
    - "node_modules"
    - "**/*.test.*"
    - "**/*.spec.*"
    - "dist"
    - "build"
```

### 5.2 `rules`

```yaml
rules:
  preset: owasp-top-10
  disable: []
```

补充：

- `custom` 字段在 schema 中已定义，但默认是可选项
- 不配置 `rules.custom` 时，只运行 built-in rules

### 5.3 `llm`

```yaml
llm:
  provider: claude
  model: claude-sonnet-4-6
  maxConcurrency: 5
```

补充：

- `apiKey` 可选
- `maxCostUSD` 可选

### 5.4 `output`

```yaml
output:
  format: text
```

### 5.5 `cache`

```yaml
cache:
  enabled: true
  directory: .codeguard-cache
  ttl: 86400
```

注意：虽然 cache 默认值已经存在，但当前扫描主流程**还没有真正使用缓存**。

## 6. `init` 命令生成的 starter config

`init` 命令生成的 `.codeguard.yml` 更偏向真实项目起步场景：

```yaml
scan:
  include:
    - "src/**/*.{ts,js,py}"
    - "lib/**/*.{ts,js,py}"
  exclude:
    - "node_modules"
    - "dist"
    - "build"
    - "**/*.test.*"
    - "**/*.spec.*"

rules:
  preset: owasp-top-10

llm:
  provider: claude
  model: claude-sonnet-4-6
  maxConcurrency: 5

output:
  format: text
```

说明：starter config 默认不写 `rules.custom`，因为 custom rules 属于按需开启能力。

## 7. 环境变量覆盖

当前配置加载器支持以下环境变量：

- `CODEGUARD_API_KEY`
- `ANTHROPIC_API_KEY`
- `OPENAI_API_KEY`
- `CODEGUARD_MODEL`
- `CODEGUARD_MAX_COST`

覆盖逻辑如下：

### 7.1 API Key

优先从以下任一变量读取，并写入 `config.llm.apiKey`：

- `CODEGUARD_API_KEY`
- `ANTHROPIC_API_KEY`
- `OPENAI_API_KEY`

### 7.2 Model

如果存在：

- `CODEGUARD_MODEL`

则覆盖 `config.llm.model`。

### 7.3 Max Cost

如果存在：

- `CODEGUARD_MAX_COST`

则覆盖 `config.llm.maxCostUSD`。

## 8. 各配置域当前的真实生效情况

### 8.1 `scan`

当前已真实生效：

- `scan.include`
- `scan.exclude`

### 8.2 `rules`

当前已真实生效：

- `rules.preset`
- `rules.custom`
- `rules.disable`

其中 `rules.custom` 的当前语义是：

- 可指向**单个 YAML 文件**或**目录**
- 指向目录时递归加载 `*.yml` / `*.yaml`
- 当前按**当前工作目录**解析路径，而不是按配置文件所在目录重写
- 路径不存在、YAML 非法、schema 非法、rule ID 重复时会 fail fast

### 8.3 `llm`

当前已真实驱动扫描主流程：

- `llm.provider`
- `llm.model`
- `llm.apiKey`
- `llm.maxConcurrency`
- `llm.maxCostUSD`

这些字段的作用分别是：

- 选择 provider
- 选择模型名
- 为 Stage 2 提供认证
- 控制最大并发
- 控制预算截断

### 8.4 `output`

当前已真实生效：

- `output.file`

当前需要注意的边界：

- `output.format` 虽然已定义在配置类型中
- 但 `scan` 命令本身带有 CLI 默认值 `text`
- 因此如果没有显式传 `--output`，当前命令行为会优先落到 `text`

### 8.5 `cache`

当前整个 `cache.*` 都属于：

- 类型已定义
- 默认值已存在
- 运行时未接线

## 9. `rules.preset` 当前含义

当前支持三个取值：

- `owasp-top-10`
- `all`
- `none`

当前运行时行为：

- `none`：禁用全部 built-in rules
- `owasp-top-10`：返回全部 13 条 built-in rules
- `all`：当前也返回全部 13 条 built-in rules

因此今天的实现里，`owasp-top-10` 与 `all` 还没有行为差异。

## 10. 示例配置

### 10.1 最小可用配置

```yaml
rules:
  preset: owasp-top-10
```

### 10.2 排除部分规则

```yaml
scan:
  include:
    - "src/**/*.{ts,js,py}"
  exclude:
    - "node_modules"

rules:
  preset: owasp-top-10
  disable:
    - CG-050
    - CG-021

output:
  file: report.json
```

### 10.3 只运行 custom rules

```yaml
rules:
  preset: none
  custom: ./custom-rules
```

### 10.4 built-in + custom 一起运行

```yaml
rules:
  preset: owasp-top-10
  custom: ./custom-rules
  disable:
    - CG-050
    - CG-CUSTOM-001
```

### 10.5 启用 Stage 2 相关配置

```yaml
llm:
  provider: claude
  model: claude-sonnet-4-6
  maxConcurrency: 5
  maxCostUSD: 1.00
```

注意：这类配置今天会真实影响非 dry-run 的扫描行为。

## 11. 配置校验边界

当前 schema 会校验：

- `rules.preset` 枚举值是否合法
- `llm.provider` 是否是 `claude` 或 `openai`
- `output.format` 是否是 `sarif` / `json` / `text`
- `llm.maxConcurrency` 是否在 `1..20`

而 `rules.custom` 的更细粒度校验会发生在运行时加载阶段，例如：

- 文件是否存在
- YAML 是否可解析
- rule schema 是否合法
- ID 是否重复

这意味着配置错误会在加载阶段被直接拒绝，而不是拖到扫描中途静默失败。

## 12. 当前限制

1. **并非所有字段都接线完成**
   - `cache.*` 当前仍主要是设计占位。
2. **`output.format` 存在 CLI 默认值干预**
   - 仅改配置文件，不一定能改变实际默认输出行为。
3. **没有独立配置检查命令**
   - 当前也没有类似 `config validate` 的 CLI。
4. **`rules.custom` 当前是 CWD-relative 语义**
   - 如果通过 `--config` 指定了其他目录下的配置文件，custom path 也不会自动跟随配置文件目录解析。
