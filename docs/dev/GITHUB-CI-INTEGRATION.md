# AI-CodeGuard GitHub / CI 集成说明

> 本文档描述 **当前仓库在 GitHub / CI 方向上的真实状态、最小可行集成方案，以及下一步推荐落地顺序**。

## 1. 当前仓库状态

截至 **2026-04-12**，当前仓库已经具备：

- `npm run build`
- `npm run test:run`
- `node dist/index.js scan ...`
- `text` / `json` / `sarif` 输出
- `--dry-run` Stage 1-only 扫描能力

但仓库当前**还没有**：

- `.github/workflows/*.yml` 工作流文件
- `action.yml` 或 `action.yaml`
- 已封装的 GitHub Action
- 自动上传 SARIF 的产品化链路

这意味着：

- **CI 所需的本地命令基础已经具备**
- **GitHub 侧封装与自动化链路尚未落地**

## 2. 推荐先做什么

对于当前阶段，最合理的 GitHub / CI 集成顺序是：

### Step 1：先补最小 CI 回归工作流

目标：保证每次变更至少执行：

- 安装依赖
- build
- test

推荐命令：

```bash
npm ci
npm run build
npm run test:run
```

这是最小、最稳定、最不依赖外部密钥的集成起点。

### Step 2：再补 Stage 1-only 扫描产物导出

目标：在 CI 中生成可审阅的扫描结果，而不依赖外部 API key。

推荐命令：

```bash
node dist/index.js scan ./src --dry-run --output sarif --output-file artifacts/ai-codeguard.sarif
```

这样做的优点：

- 不依赖 Claude / OpenAI API key
- 不触发 Stage 2 外部调用
- 仍可生成标准化 SARIF 结果
- 可先作为 artifact 保存，后续再接入上传链路

### Step 3：最后再做 GitHub Code Scanning / Action 产品化

在前两步稳定后，再考虑：

- 上传 SARIF 到 GitHub code scanning
- 封装 `action.yml`
- 提供对外可复用 Action 接入方式
- 再评估 release / publish 链路

## 3. 最小 CI 工作流示例

下面是一个推荐的最小 GitHub Actions 工作流示例：

```yaml
name: ci

on:
  push:
    branches:
      - main
  pull_request:

jobs:
  build-and-test:
    runs-on: ubuntu-latest

    steps:
      - name: Checkout
        uses: actions/checkout@v4

      - name: Setup Node.js
        uses: actions/setup-node@v4
        with:
          node-version: 20
          cache: npm

      - name: Install dependencies
        run: npm ci

      - name: Build
        run: npm run build

      - name: Run tests
        run: npm run test:run
```

这个工作流当前最适合作为：

- 仓库最小回归门禁
- 后续所有 GitHub / CI 集成的基础

## 4. Stage 1-only SARIF 工作流示例

如果要继续向安全工具链接近，可以在 CI 里增加一个 Stage 1-only SARIF 导出流程：

```yaml
name: security-scan

on:
  pull_request:
  workflow_dispatch:

jobs:
  sarif:
    runs-on: ubuntu-latest

    steps:
      - name: Checkout
        uses: actions/checkout@v4

      - name: Setup Node.js
        uses: actions/setup-node@v4
        with:
          node-version: 20
          cache: npm

      - name: Install dependencies
        run: npm ci

      - name: Build
        run: npm run build

      - name: Run Stage 1 scan
        run: node dist/index.js scan ./src --dry-run --output sarif --output-file artifacts/ai-codeguard.sarif

      - name: Upload SARIF artifact
        uses: actions/upload-artifact@v4
        with:
          name: ai-codeguard-sarif
          path: artifacts/ai-codeguard.sarif
```

### 为什么先推荐 Stage 1-only

因为它当前最稳：

- 不需要 API key
- 不依赖 provider 可用性
- 不引入成本问题
- 能复用当前已经稳定的扫描与 reporter 输出

## 5. 如果后续接 GitHub code scanning

后续如果要把 SARIF 直接上传到 GitHub code scanning，通常还需要：

- `security-events: write` 权限
- 稳定的 SARIF 生成路径
- 对上传时机（push / PR / main）做明确约束

在真正落地这一步前，需要先接受当前边界：

- SARIF 已能导出
- 但当前仓库还没有现成上传工作流
- `informationUri` 仍是占位式链接

因此更合理的顺序仍然是：

1. 先 build/test CI
2. 再 Stage 1-only SARIF artifact
3. 最后才是 code scanning 上传与 Action 封装

## 6. 当前实现时需要注意的约束

### 6.1 Node 版本

仓库 `package.json` 当前要求：

- `node >= 18`

GitHub Actions 建议先固定：

- Node 20

### 6.2 包管理器

当前仓库存在：

- `package-lock.json`

因此当前 CI 示例以 `npm ci` 为准。

### 6.3 Stage 2 不适合作为第一版 CI 默认路径

虽然运行时已经支持 Stage 2，但它会引入：

- API key 管理
- provider 稳定性问题
- 成本控制
- 更复杂的失败路径

所以第一版 GitHub / CI 集成不建议默认走 Stage 2。

### 6.4 输出目录要显式准备

当前 reporter 写 `--output-file` 时：

- 不会自动创建父目录

这意味着如果 CI 工作流写出到 `artifacts/...`，应先确保目录存在，例如：

```bash
mkdir -p artifacts
node dist/index.js scan ./src --dry-run --output sarif --output-file artifacts/ai-codeguard.sarif
```

## 7. 推荐的落地范围定义

如果下一步要真正开始实现 GitHub / CI 集成，建议把第一批范围控制在：

- `.github/workflows/ci.yml`
- 可选的 `.github/workflows/security-scan.yml`
- 文档补充：输入、输出、限制条件

先不要在第一批里同时做：

- `action.yml` 封装
- npm package 发布链路
- 多平台矩阵
- Stage 2 默认联网扫描
- 自动发布 / release automation

## 8. 结论

当前 GitHub / CI 集成的真实结论是：

- **基础命令已经具备**
- **产品化 GitHub 集成尚未落地**
- **最合理的下一步是先实现最小 CI，再补 Stage 1-only SARIF，再考虑上传与 Action 封装**

如果按这个顺序推进，就能在不提前引入外部依赖和复杂失败路径的前提下，把 AI-CodeGuard 从“本地可运行 CLI”推进到“具备基础 GitHub / CI 集成能力的工具”。
