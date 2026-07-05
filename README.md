# AI-CodeGuard

> A TypeScript-based code security CLI that combines Stage 1 static pre-filtering with optional Stage 2 LLM confirmation.

## Current Status

AI-CodeGuard is currently in a **Phase 1** state, but the runtime pipeline is no longer Stage-1-only.

What is implemented today:
- CLI commands: `scan`, `init`, `rules` (`--list`, `validate`, `create`, `test`)
- Local scanning for **JavaScript, TypeScript, Python, Go, and Java**
- **13 built-in OWASP-oriented rules**
- Optional YAML custom rule loading through `rules.custom`
- Custom rule CLI workflow through **`rules validate/create/test`**
- Report output in **text, JSON, SARIF**
- Stage 2 LLM analysis via **Claude** or **OpenAI** when `scan` runs without `--dry-run`
- Optional fix suggestions through `--fix`
- Config loading via `.codeguard.yml` / environment variables
- Disk cache for Stage 2 LLM results (`cache.enabled`), wired into the scan pipeline
- GitHub composite Action (`action.yml`) plus CI / SARIF-upload workflows
- Automated validation with **277 passing tests across 11 test files** (`npm run test:run` on 2026-07-05), plus an opt-in real-provider E2E test (skipped without `CODEGUARD_E2E=1` + API key) and a CI smoke job exercising the composite Action against the fixtures

What is **not** complete yet:
- npm registry publish (`v0.2.0` is tagged on GitHub, but the package is not on npm yet)

### Completion Snapshot

| Milestone | Status | Meaning |
|----------|--------|---------|
| M0 Phase 1 CLI baseline | Done | `scan` / `init` / `rules --list` are usable |
| M1 Stage 2 Analyzer | Done | non-`--dry-run` scans can run LLM confirmation |
| M2 `--fix` suggestions | Done | confirmed Stage 2 findings can include `fix` |
| M3 Tree-sitter parser | Done | main parser now uses Tree-sitter-backed normalized AST |
| M4 Custom rules runtime | Done | `rules.custom` is wired into `scan()`, and `rules validate/create/test` are available |
| M5 GitHub / CI integration | Done | composite `action.yml`, `ci.yml`, and `security-scan.yml` (SARIF upload to Code Scanning) exist and pass |
| M6 More languages | Done | Go: 5 rules; Java: 5 rules (`CG-001`/`CG-002`/`CG-020`/`CG-030`/`CG-060`) |

### Terminology

To keep the docs consistent:

- **Phase 1** = the current shipped product stage: a usable local CLI baseline
- **Stage 1** = the runtime pipeline’s static pre-filtering stage
- **Stage 2** = the runtime pipeline’s LLM confirmation / enrichment stage

Current truth: the repository is still in **Phase 1**, and `scan()` now supports **Stage 1 + Stage 2**. Use `--dry-run` to stop after Stage 1.

## What Works Today

### CLI Commands

```bash
# Build the CLI
npm install
npm run build

# Initialize config in the current project
node dist/index.js init

# Stage 1 only
node dist/index.js scan ./src --dry-run

# Full scan with Stage 2
export CODEGUARD_API_KEY="..."
node dist/index.js scan ./src

# Ask for fix suggestions during Stage 2
node dist/index.js scan ./src --fix

# Output JSON or SARIF
node dist/index.js scan ./src --output json
node dist/index.js scan ./src --output sarif --output-file report.sarif

# List built-in rules
node dist/index.js rules --list

# Create a starter custom rule file
node dist/index.js rules create ./custom-rules/example.yml

# Validate custom rule YAML
node dist/index.js rules validate ./custom-rules

# Run Stage 1-only custom rule smoke test
node dist/index.js rules test ./custom-rules ./src --output json
```

### Use as GitHub Action

Add a workflow that scans every pull request and uploads results to GitHub Code Scanning (Security tab):

```yaml
name: security-scan
on: [pull_request]

permissions:
  contents: read
  security-events: write

jobs:
  codeguard:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: AI-CodeGuard scan
        id: scan
        uses: hzj-Jeff-07/AI-CodeGuard@main
        with:
          paths: ./src
          output-file: ai-codeguard.sarif
          # dry-run: 'false'            # enable Stage 2 LLM confirmation
          # api-key: ${{ secrets.CODEGUARD_API_KEY }}

      - name: Upload SARIF to Code Scanning
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: ai-codeguard.sarif
          category: ai-codeguard
```

Defaults: Stage 1 only (no API key needed), fails the job on critical/high findings. All inputs and more recipes: [docs/dev/GITHUB-ACTION.md](./docs/dev/GITHUB-ACTION.md).

### Supported Languages

| Language | Extensions | Rule coverage |
|----------|------------|---------------|
| JavaScript | `.js`, `.jsx`, `.mjs`, `.cjs` | all 13 built-in rules |
| TypeScript | `.ts`, `.tsx` | all 13 built-in rules |
| Python | `.py` | all 13 built-in rules |
| Go | `.go` | `CG-001` SQL injection, `CG-002` command injection, `CG-020` hardcoded credentials, `CG-030` path traversal, `CG-060` SSRF |
| Java | `.java` | `CG-001` SQL injection (incl. `String.format`), `CG-002` command injection (`Runtime.exec`, `ProcessBuilder`), `CG-020` hardcoded credentials, `CG-030` path traversal (`File`/`Files`/`Paths`), `CG-060` SSRF (`URL`, RestTemplate) |

### Built-in Rule Set

| Category | Rule IDs | Notes |
|----------|----------|-------|
| Injection | `CG-001`, `CG-002`, `CG-003` | SQL injection, command injection, eval/code injection; `CG-001`/`CG-002` also cover Go and Java |
| XSS | `CG-010`, `CG-011` | Reflected/DOM-based XSS |
| Auth / Crypto | `CG-020`, `CG-021` | Hardcoded credentials (also Go and Java), weak cryptography |
| Path | `CG-030`, `CG-031` | Path traversal (also Go and Java), arbitrary file read/write |
| Data | `CG-040`, `CG-041` | Sensitive data exposure, insecure deserialization |
| Config | `CG-050` | Security misconfiguration |
| SSRF | `CG-060` | Server-side request forgery (also Go and Java) |

Total: **13 built-in rules**.

### Custom Rules Runtime

The current runtime also supports optional YAML custom rules via config:

```yaml
rules:
  preset: none
  custom: ./custom-rules
```

Current boundary:
- `rules.custom` can point to a YAML file or directory
- directories load `*.yml` / `*.yaml` recursively
- `disable` applies to built-in and custom rules by rule ID
- `rules --list` shows built-in rules plus custom rules from config (`--config` supported)
- `rules create` writes a minimal YAML scaffold and supports `--force`
- `rules validate` checks YAML parsing, schema validity, and duplicate rule IDs
- `rules test` is a **Stage 1-only** custom-rule smoke path, so it does not require an API key

## How Scanning Works Today

The current runtime pipeline is:

1. Discover files with `fast-glob`
2. Detect language from file extension
3. Parse each file with a **Tree-sitter-backed normalized parser**
4. Load built-in rules plus optional custom YAML rules
5. Run rules to produce suspicious nodes
6. Convert suspicious nodes into Stage 1 findings
7. If `--dry-run` is **not** enabled, run Stage 2 LLM analysis on those candidates
8. Render output as text / JSON / SARIF

Important runtime behavior:
- `--dry-run` means **Stage 1 only**, so `llmCalls = 0` and `estimatedCost = 0`
- non-dry-run scans that reach Stage 2 require `llm.apiKey` or a supported env var
- confirmed Stage 2 findings get `llmAnalysis`, and `--fix` can add `fix`
- findings the LLM does not confirm are moved to `dismissedFindings` (JSON output) with the LLM's reasoning, and the text summary shows a dismissed count — Stage 2 suppressions stay auditable
- the Stage 2 prompt treats scanned code as untrusted data, so comments in scanned code that try to talk the LLM into dismissing a finding are instructed against (prompt-injection hardening)
- when `llm.maxCostUSD` is reached, new LLM calls stop and remaining unanalyzed findings stay as Stage 1 findings
- when `cache.enabled` is `true`, Stage 2 results are persisted to `cache.directory` (default `.codeguard-cache/`); repeat scans reuse them with `llmCalls = 0` and `estimatedCost = 0` for cached entries

## Configuration

Run `init` to generate a starter config:

```yaml
scan:
  include:
    - "src/**/*.{ts,js,py,go,java}"
    - "lib/**/*.{ts,js,py,go,java}"
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
  model: claude-sonnet-5
  maxConcurrency: 5

output:
  format: text
```

### Config and Environment Variables

The loader supports:
- `.codeguard.yml`
- `.codeguard.yaml`
- `.codeguard.json`
- `codeguard.config.js`
- `codeguard.config.ts`

Environment variable overrides currently supported by the config loader:
- `CODEGUARD_API_KEY`
- `ANTHROPIC_API_KEY`
- `OPENAI_API_KEY`
- `CODEGUARD_MODEL`
- `CODEGUARD_MAX_COST`

Stage 2 currently consumes:
- `llm.provider`
- `llm.model`
- `llm.apiKey`
- `llm.maxConcurrency`
- `llm.maxCostUSD`

Stage 2 disk caching is controlled by (disabled by default):

```yaml
cache:
  enabled: true
  directory: .codeguard-cache
  ttl: 86400
```

Note: provider selection is configured in the config file, not through a dedicated environment variable.

## Output Formats

### Text
Human-readable terminal summary with severity, location, snippets, optional fix suggestions, optional LLM reasoning, and summary counts.

### JSON
Structured machine-readable output containing:
- scan metadata
- findings
- skipped files
- optional `fix` and `llmAnalysis`

### SARIF
SARIF v2.1.0 output suitable for downstream tooling, including optional SARIF fixes and LLM markdown context.

SARIF output integrates with GitHub Code Scanning: the repository ships a composite Action (`action.yml`) and a `security-scan.yml` workflow that runs a Stage 1 scan and uploads the SARIF report via `github/codeql-action/upload-sarif`.

## Repository Structure

```text
ai-codeguard/
├── src/
│   ├── analyzer/            # Stage 2 orchestration and provider adapters
│   ├── cli/                 # Commander.js entry and commands
│   ├── config/              # Config schema, defaults, loader
│   ├── parser/              # Tree-sitter runtime, normalization, and adapters
│   ├── reporter/            # text / json / sarif formatters
│   ├── rules/               # Built-in + custom rule loading and execution
│   ├── scanner/             # File discovery and orchestration
│   └── types/               # Shared TypeScript types
├── docs/
│   ├── README.md            # Documentation entrypoint and reading guide
│   ├── adr/
│   │   └── decisions.md
│   ├── design/
│   │   ├── TECHNICAL-SUMMARY.md
│   │   ├── core-modules.md
│   │   ├── CONFIGURATION.md
│   │   ├── RULES.md
│   │   ├── REPORTING.md
│   │   └── LLM-INTEGRATION.md
│   └── dev/
│       ├── CLI-EXAMPLES.md
│       ├── ROADMAP.md
│       └── TESTING.md
├── tests/
│   ├── fixtures/
│   ├── integration/
│   └── unit/
├── ARCHITECTURE.md
├── package.json
├── tsconfig.json
├── tsup.config.ts
└── vitest.config.ts
```

## Verification

Verified on 2026-07-04:

```bash
npm run build
npm run test:run
```

Result:
- build passed
- `10` test files passed
- `277` tests passed (plus 1 opt-in E2E skipped without an API key)

## Limitations

Current known limitations:
- default non-dry-run scans need an API key if Stage 2 is reached
- parser uses Tree-sitter with a compatibility-preserving normalized AST layer
- model-cost enforcement depends on a built-in pricing table; if `llm.maxCostUSD` is set for an unknown model, the scan fails fast
- `rules test` is intentionally Stage 1-only and does not exercise Stage 2
- Go and Java support covers 5 rules each (`CG-001`/`CG-002`/`CG-020`/`CG-030`/`CG-060`). Stage 1 has no dataflow analysis, so inline `db.Query(fmt.Sprintf(...))` / `Files.readString(Paths.get(...))` may report both the outer call and the inner call
- `config.output.format` is defined, but the scan command’s CLI default still prefers text unless `--output` is explicitly provided
- fix suggestions are advisory only; the CLI does not rewrite files automatically

## Documentation

- [docs/README.md](./docs/README.md) — documentation entrypoint, terminology guide, and recommended reading order
- [ARCHITECTURE.md](./ARCHITECTURE.md) — current implementation architecture
- [docs/design/core-modules.md](./docs/design/core-modules.md) — module-by-module breakdown of the current codebase
- [docs/design/TECHNICAL-SUMMARY.md](./docs/design/TECHNICAL-SUMMARY.md) — implementation status, verification state, and next priorities
- [docs/design/CONFIGURATION.md](./docs/design/CONFIGURATION.md) — configuration model, defaults, env overrides, and runtime consumption boundaries
- [docs/design/RULES.md](./docs/design/RULES.md) — current built-in + custom rule loading behavior, rule behaviors, and known limits
- [docs/design/REPORTING.md](./docs/design/REPORTING.md) — text / JSON / SARIF output behavior and current output constraints
