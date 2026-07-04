# AI-CodeGuard

> A TypeScript-based code security CLI that combines Stage 1 static pre-filtering with optional Stage 2 LLM confirmation.

## Current Status

AI-CodeGuard is currently in a **Phase 1** state, but the runtime pipeline is no longer Stage-1-only.

What is implemented today:
- CLI commands: `scan`, `init`, `rules` (`--list`, `validate`, `create`, `test`)
- Local scanning for **JavaScript, TypeScript, Python**
- **13 built-in OWASP-oriented rules**
- Optional YAML custom rule loading through `rules.custom`
- Custom rule CLI workflow through **`rules validate/create/test`**
- Report output in **text, JSON, SARIF**
- Stage 2 LLM analysis via **Claude** or **OpenAI** when `scan` runs without `--dry-run`
- Optional fix suggestions through `--fix`
- Config loading via `.codeguard.yml` / environment variables
- Disk cache for Stage 2 LLM results (`cache.enabled`), wired into the scan pipeline
- GitHub composite Action (`action.yml`) plus CI / SARIF-upload workflows
- Automated validation with **190 passing tests across 10 test files** (`npm run test:run` on 2026-07-04)

What is **not** complete yet:
- Expanded language support beyond JS / TS / Python (Go / Java planned)
- npm publish / versioned releases (no `v0.2.0` tag yet)

### Completion Snapshot

| Milestone | Status | Meaning |
|----------|--------|---------|
| M0 Phase 1 CLI baseline | Done | `scan` / `init` / `rules --list` are usable |
| M1 Stage 2 Analyzer | Done | non-`--dry-run` scans can run LLM confirmation |
| M2 `--fix` suggestions | Done | confirmed Stage 2 findings can include `fix` |
| M3 Tree-sitter parser | Done | main parser now uses Tree-sitter-backed normalized AST |
| M4 Custom rules runtime | Done | `rules.custom` is wired into `scan()`, and `rules validate/create/test` are available |
| M5 GitHub / CI integration | Done | composite `action.yml`, `ci.yml`, and `security-scan.yml` (SARIF upload to Code Scanning) exist and pass |
| M6 More languages | Not done | runtime still supports JS / TS / Python only |

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

### Supported Languages

| Language | Extensions |
|----------|------------|
| JavaScript | `.js`, `.jsx`, `.mjs`, `.cjs` |
| TypeScript | `.ts`, `.tsx` |
| Python | `.py` |

### Built-in Rule Set

| Category | Rule IDs | Notes |
|----------|----------|-------|
| Injection | `CG-001`, `CG-002`, `CG-003` | SQL injection, command injection, eval/code injection |
| XSS | `CG-010`, `CG-011` | Reflected/DOM-based XSS |
| Auth / Crypto | `CG-020`, `CG-021` | Hardcoded credentials, weak cryptography |
| Path | `CG-030`, `CG-031` | Path traversal, arbitrary file read/write |
| Data | `CG-040`, `CG-041` | Sensitive data exposure, insecure deserialization |
| Config | `CG-050` | Security misconfiguration |
| SSRF | `CG-060` | Server-side request forgery |

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
- unconfirmed Stage 2 findings are filtered out of the final report
- when `llm.maxCostUSD` is reached, new LLM calls stop and remaining unanalyzed findings stay as Stage 1 findings
- when `cache.enabled` is `true`, Stage 2 results are persisted to `cache.directory` (default `.codeguard-cache/`); repeat scans reuse them with `llmCalls = 0` and `estimatedCost = 0` for cached entries

## Configuration

Run `init` to generate a starter config:

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
- `190` tests passed

## Limitations

Current known limitations:
- default non-dry-run scans need an API key if Stage 2 is reached
- parser uses Tree-sitter with a compatibility-preserving normalized AST layer
- model-cost enforcement depends on a built-in pricing table; if `llm.maxCostUSD` is set for an unknown model, the scan fails fast
- `rules test` is intentionally Stage 1-only and does not exercise Stage 2
- only JavaScript / TypeScript / Python are supported in code
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
