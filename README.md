# AI-CodeGuard

> A TypeScript-based code security CLI that combines Stage 1 static pre-filtering with optional Stage 2 LLM confirmation.

## Current Status

AI-CodeGuard is currently in a **Phase 1** state, but the runtime pipeline is no longer Stage-1-only.

What is implemented today:
- CLI commands: `scan`, `init`, `rules` (`--list`, `validate`, `create`, `test`)
- Local scanning for **JavaScript, TypeScript, Python, Go, Java, and PHP**
- **19 built-in OWASP-oriented rules** (see the rule table below for per-language coverage)
- Optional YAML custom rule loading through `rules.custom`
- Custom rule CLI workflow through **`rules validate/create/test`**
- Report output in **text, JSON, SARIF, and GitHub PR review** (`--output github`); SARIF rules carry CWE tags, `security-severity`, a MITRE `helpUri`, and stable `partialFingerprints`, so GitHub Code Scanning shows CWE labels, ranks alerts, and keeps alert identity across line shifts
- Stage 2 LLM analysis via **Claude** or **OpenAI** when `scan` runs without `--dry-run`
- Optional fix suggestions through `--fix`
- **CI-friendly controls**: `--fail-on <level>` exit-code gate, machine-readable `severityCounts` in JSON, inline `codeguard-ignore` suppression (auditable), baseline files (`--write-baseline` / `--baseline`) to adopt on an existing codebase and gate on new findings only, and `--diff <file>` to restrict findings to a PR's added/modified lines (the PR bot only speaks about the change under review)
- **Measurable quality**: a Stage 1 precision harness with a labeled corpus and a metric ratchet (`npm run precision`; measured baseline 95.8% precision / 92.0% recall), a Stage 2 triage-accuracy harness (`npm run triage`, opt-in) that measures how well the LLM confirms real vulnerabilities and dismisses false positives, and a hand-assessed **real-world validation run** against fastify, flask, and OWASP Juice Shop (`docs/dev/REALWORLD.md`) whose false-positive classes are pinned as corpus regression tests
- Config loading via `.codeguard.yml` / environment variables
- Disk cache for Stage 2 LLM results (`cache.enabled`), wired into the scan pipeline
- GitHub composite Action (`action.yml`), CI / SARIF-upload workflows, and a BYO-key PR-review workflow example (`docs/examples/pr-review.yml`; design in `docs/design/GITHUB_APP.md`)
- Automated validation with **571 passing tests across 18 test files** (`npm run test:run`), plus two opt-in real-provider tests (an E2E acceptance test and the triage measurement, both skipped without `CODEGUARD_E2E=1` + API key) and a CI smoke job exercising the composite Action against the fixtures

What is **not** complete yet:
- npm registry publish (GitHub tags exist via the release workflow, but the package is not on npm yet)
- `v0.4.0` tag — code and CHANGELOG are release-ready; trigger the manual `release` workflow with tag `v0.4.0` after merging to `main`

### Completion Snapshot

| Milestone | Status | Meaning |
|----------|--------|---------|
| M0 Phase 1 CLI baseline | Done | `scan` / `init` / `rules --list` are usable |
| M1 Stage 2 Analyzer | Done | non-`--dry-run` scans can run LLM confirmation |
| M2 `--fix` suggestions | Done | confirmed Stage 2 findings can include `fix` |
| M3 Tree-sitter parser | Done | main parser now uses Tree-sitter-backed normalized AST |
| M4 Custom rules runtime | Done | `rules.custom` is wired into `scan()`, and `rules validate/create/test` are available |
| M5 GitHub / CI integration | Done | composite `action.yml`, `ci.yml`, and `security-scan.yml` (SARIF upload to Code Scanning) exist and pass |
| M6 More languages | Done | Go: 12 rules; Java: 15 rules (adds `CG-010`, `CG-041`, `CG-070` over the Go set); PHP: 17 rules (adds `CG-021`/`CG-022`/`CG-023`/`CG-024`/`CG-025`/`CG-026`/`CG-031`/`CG-040`/`CG-041`/`CG-050`/`CG-070` over the original MVP set) |
| M7 Quality & adoption tooling | Done | Stage 1 precision harness + ratchet, Stage 2 triage-accuracy harness, baseline files, inline suppression, `--fail-on`, stable SARIF fingerprints |
| M8 Commercialization step 1 | In progress | `--output github` PR-review reporter + BYO-key workflow example; hosted GitHub App designed (`docs/design/GITHUB_APP.md`), not yet built |

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

# Output a GitHub PR review payload (inline comments) — see docs/examples/pr-review.yml
node dist/index.js scan ./src --output github --output-file review.json

# Control the CI exit code: fail only on critical findings (default is `high`;
# `--fail-on none` always exits 0, for report-only scans)
node dist/index.js scan ./src --fail-on critical

# List built-in rules
node dist/index.js rules --list

# Create a starter custom rule file
node dist/index.js rules create ./custom-rules/example.yml

# Validate custom rule YAML
node dist/index.js rules validate ./custom-rules

# Run Stage 1-only custom rule smoke test
node dist/index.js rules test ./custom-rules ./src --output json
```

### PR review bot (BYO-key)

`--output github` produces a [GitHub PR review payload](https://docs.github.com/en/rest/pulls/reviews#create-a-review-for-a-pull-request) — a summary plus one inline comment per finding (rule, CWE link, Stage 2 reasoning, suggested fix, and a copy-paste suppression hint). It carries no credentials; a thin workflow step submits it with the repo's built-in `GITHUB_TOKEN`, and you bring your own LLM key as a secret (nothing goes to a hosted service). See [`docs/examples/pr-review.yml`](docs/examples/pr-review.yml) — it scans only the PR's changed files and passes the PR diff via `--diff`, so comments land only on changed *lines* (pre-existing findings in touched files are dropped before Stage 2, costing no LLM calls), and it falls back to a Stage-1-only advisory pass when no key is set.

### Measuring precision

Unit tests assert single-pattern behavior; the **precision corpus** (`tests/corpus/`) measures the scanner on realistic mixed code. Vulnerable lines carry ground-truth `codeguard-expect CG-XXX` annotations (including cases the flat-node model is known to miss, kept honest as FNs), and tricky-but-safe code is asserted clean — including the false-positive classes discovered by scanning fastify, flask, and OWASP Juice Shop (see `docs/dev/REALWORLD.md`). `npm run precision` prints TP/FN/FP with precision/recall, and a ratchet test fails CI if either metric drops below the current baseline (precision ≥ 95.8%, recall ≥ 92%).

### Adopting on an existing codebase (baseline)

On a legacy codebase the first scan can produce dozens of historical findings, drowning out anything new. Snapshot them once, then ratchet on "no *new* findings":

```bash
# Acknowledge the current findings (writes .codeguard-baseline.json; exits 0)
node dist/index.js scan ./src --dry-run --write-baseline

# From now on, only findings NOT in the baseline are reported / fail the build
node dist/index.js scan ./src --dry-run --baseline .codeguard-baseline.json
```

Baseline fingerprints hash the rule + file + normalized snippet — **no line numbers** — so unrelated edits that shift code up or down don't resurrect acknowledged findings, while any genuinely new finding (or an extra copy of an acknowledged one) still surfaces. The scan reports how many findings the baseline absorbed (`scan.baselined` in JSON, a summary line in text). Commit the baseline file and shrink it over time as findings get fixed.

Two rules of thumb: **always run scans from the repository root** (fingerprints embed cwd-relative paths, so a different working directory silently mismatches the whole baseline), and write baselines from *unfiltered* scans (`--write-baseline` rejects `--severity` for this reason; Stage 2 dismissals are included in the snapshot so later runs don't re-pay to re-triage them).

### Measuring Stage 2 triage accuracy

The two-stage design's core claim — the LLM confirms real vulnerabilities and dismisses Stage 1 false positives — is measured, not assumed. `tests/corpus-triage/` labels every Stage 1 finding with a ground-truth verdict (`codeguard-real` should be confirmed, `codeguard-fp` should be dismissed — including planted FP bait like `eval('2 + 2')`, `setInterval(fn, ...)`, and timing-jitter `Math.random`). The harness runs the full production `scan()` pipeline and reports **confirm-recall**, **fp-dismiss-rate**, and **triage accuracy**:

```bash
CODEGUARD_E2E=1 ANTHROPIC_API_KEY=sk-... npm run triage
```

Offline runs validate the harness arithmetic with scripted providers; the real-model measurement is opt-in (defaults to Haiku, override with `CODEGUARD_E2E_MODEL`). An integrity check fails if the corpus and rules drift apart (unlabeled findings, or labels that no longer fire). One measurement caveat: when an LLM call errors, the pipeline conservatively keeps the finding (fail-open toward reporting), which counts as a confirm — so provider outages inflate confirm-recall rather than silently dropping findings.

### Suppressing a finding

Silence a specific finding with an inline comment (any language's comment syntax works). A bare directive suppresses every rule on the line; add rule IDs to scope it, and anything after the IDs is treated as a free-text reason:

```js
db.query("SELECT * FROM t WHERE id = " + id); // codeguard-ignore CG-001 — id is an internal constant
```

Use `codeguard-ignore-next-line` to annotate the following line instead:

```py
# codeguard-ignore-next-line CG-002
subprocess.run(cmd, shell=True)
```

Suppressed findings are dropped during Stage 1, so they never reach Stage 2 (no LLM cost). The scan reports how many were suppressed (`scan.suppressed` in JSON, a summary line in text) so they aren't hidden silently — run `--no-inline-suppression` to report them all and audit what's being hidden.

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
| JavaScript | `.js`, `.jsx`, `.mjs`, `.cjs` | all 19 built-in rules |
| TypeScript | `.ts`, `.tsx` | all 19 built-in rules |
| Python | `.py` | 18 of 19 built-in rules (all but `CG-011` DOM-based XSS, which needs a browser DOM) |
| Go | `.go` | `CG-001` SQL injection, `CG-002` command injection, `CG-020` hardcoded credentials, `CG-021` weak crypto (`crypto/md5`/`sha1`/`des`/`rc4`), `CG-022` insecure randomness (`math/rand`), `CG-023` insecure regex/ReDoS (`regexp.MustCompile`/`Compile`/`MatchString`), `CG-025` open redirect (`http.Redirect`), `CG-030` path traversal, `CG-031` arbitrary file access, `CG-040` sensitive data exposure (`log`/`logrus`/`zap`), `CG-050` security misconfiguration (`InsecureSkipVerify`), `CG-060` SSRF (12 rules) |
| Java | `.java` | `CG-001` SQL injection (incl. `String.format`), `CG-002` command injection (`Runtime.exec`, `ProcessBuilder`), `CG-010` XSS (unescaped `response.getWriter().write(...)`), `CG-020` hardcoded credentials, `CG-021` weak crypto (`MessageDigest`/`Cipher`), `CG-022` insecure randomness (`java.util.Random`), `CG-023` insecure regex/ReDoS (`Pattern.compile`), `CG-025` open redirect (`response.sendRedirect`), `CG-030` path traversal (`File`/`Files`/`Paths`), `CG-031` arbitrary file access, `CG-040` sensitive data exposure, `CG-041` insecure deserialization (`ObjectInputStream#readObject`), `CG-050` security misconfiguration (Spring CSRF/CORS, cookie flags), `CG-060` SSRF (`URL`, RestTemplate), `CG-070` XXE (`setExpandEntityReferences(true)`, `load-external-dtd`) (15 rules) |
| PHP | `.php` | `CG-001` SQL injection (`mysqli_query`, PDO/mysqli `->query`, `Class::query` facades), `CG-002` command injection (`exec`, `shell_exec`, `passthru`, `proc_open`), `CG-003` eval/code injection, `CG-020` hardcoded credentials, `CG-021` weak crypto (`md5`/`sha1`/`hash()`), `CG-022` insecure randomness (`rand`/`mt_rand`), `CG-023` insecure regex/ReDoS (`preg_match`/`preg_match_all`/`preg_replace`/`preg_split`), `CG-024` NoSQL injection (whole `$_GET`/`$_POST`/`$_REQUEST` as a MongoDB filter), `CG-025` open redirect (`header("Location: ...")`), `CG-026` JWT signature bypass (`JWT::decode(...)` allowing the `none` algorithm), `CG-030` path traversal (`file_get_contents`, `fopen`, etc.), `CG-031` arbitrary file access, `CG-040` sensitive data exposure (`error_log`, `Log::`, `$logger->`), `CG-041` insecure deserialization (`unserialize`), `CG-050` security misconfiguration (curl TLS verification, `display_errors`), `CG-060` SSRF (`curl_init`), `CG-070` XXE (`LIBXML_NOENT`, `libxml_disable_entity_loader(false)`) (17 rules) |

### Built-in Rule Set

| Category | Rule IDs | Notes |
|----------|----------|-------|
| Injection | `CG-001`, `CG-002`, `CG-003`, `CG-024` | SQL injection, command injection, eval/code injection, NoSQL injection; `CG-001`/`CG-002` also cover Go, Java, and PHP; `CG-003` also covers PHP; `CG-024` covers JS/TS, Python, and PHP (whole request object passed as a MongoDB filter/update document, or a dynamically-built `$where` clause) |
| XSS | `CG-010`, `CG-011` | Reflected/DOM-based XSS; `CG-010` also covers Python (`mark_safe`/`Markup`/`render_template_string`) and Java (unescaped response writes) |
| Auth / Crypto | `CG-020`, `CG-021`, `CG-022`, `CG-026` | Hardcoded credentials (also Go, Java, and PHP), weak cryptography — broken algorithms (MD5/SHA1/DES/RC4) and the ECB block-cipher mode, across Go/Java/PHP too — insecure randomness in a security-sensitive context (also Go, Java, and PHP), JWT signature bypass (also Python and PHP — accepting the `"none"` algorithm or explicitly disabling signature verification) |
| Path | `CG-030`, `CG-031` | Path traversal (also Go, Java, and PHP), arbitrary file read/write (also Go, Java, and PHP) |
| Data | `CG-040`, `CG-041` | Sensitive data exposure (also Go, Java, and PHP), insecure deserialization (also Java and PHP) |
| Config | `CG-050` | Security misconfiguration (also Go, Java, and PHP) |
| SSRF | `CG-060` | Server-side request forgery (also Go, Java, and PHP) |
| XXE | `CG-070` | XML External Entity — XML parsing configured to resolve external entities or load external DTDs (JS/TS, Python, Java, PHP; not Go, whose `encoding/xml` doesn't resolve them) |
| Other | `CG-023`, `CG-025` | Insecure regular expression / ReDoS — nested/overlapping quantifiers vulnerable to catastrophic backtracking (all 6 languages); open redirect — redirect target built from unvalidated user input (all 6 languages) |

Total: **19 built-in rules**.

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
7. Apply inline `codeguard-ignore` suppression and any `--baseline`, then, if `--dry-run` is **not** enabled, run Stage 2 LLM analysis on the remaining candidates
8. Render output as text / JSON / SARIF / GitHub PR review

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
    - "src/**/*.{ts,js,py,go,java,php}"
    - "lib/**/*.{ts,js,py,go,java,php}"
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
SARIF v2.1.0 output suitable for downstream tooling, including optional SARIF fixes and LLM markdown context. Each rule descriptor carries CWE tags, `security-severity`, and a MITRE `helpUri`, and each result carries a stable `partialFingerprints` value so GitHub Code Scanning keeps alert identity across line shifts.

SARIF output integrates with GitHub Code Scanning: the repository ships a composite Action (`action.yml`) and a `security-scan.yml` workflow that runs a Stage 1 scan and uploads the SARIF report via `github/codeql-action/upload-sarif`.

### GitHub PR review
`--output github` produces a GitHub PR review payload (summary + inline comments per finding) for a BYO-key PR bot — see the [PR review bot](#pr-review-bot-byo-key) section.

## Repository Structure

```text
ai-codeguard/
├── src/
│   ├── analyzer/            # Stage 2 orchestration and provider adapters
│   ├── cli/                 # Commander.js entry and commands
│   ├── config/              # Config schema, defaults, loader
│   ├── parser/              # Tree-sitter runtime, normalization, and adapters
│   ├── reporter/            # text / json / sarif / github formatters
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

```bash
npm run build
npm run test:run
npm run lint
```

Result (2026-07-11):
- build passed, lint clean
- `18` test files passed
- `571` tests passed (plus `2` opt-in real-provider tests skipped without `CODEGUARD_E2E=1` + an API key)
- self-scan of `./src` and the safe fixtures reports 0 findings; the vulnerable fixtures report 97

The scanner's own quality is measured, not just asserted: `npm run precision` reports Stage 1 precision/recall against a labeled corpus (baseline 95.8% / 92.0%, enforced by a ratchet test), and `npm run triage` (opt-in) measures Stage 2 confirm/dismiss accuracy. Stage 1 has also been validated by hand against three real open-source repositories — fixing the false-positive classes that run exposed cut noise on the clean repos by 84% while keeping every planted Juice Shop vulnerability (`docs/dev/REALWORLD.md`).

## Limitations

Current known limitations:
- default non-dry-run scans need an API key if Stage 2 is reached
- parser uses Tree-sitter with a compatibility-preserving normalized AST layer
- model-cost enforcement depends on a built-in pricing table; if `llm.maxCostUSD` is set for an unknown model, the scan fails fast
- `rules test` is intentionally Stage 1-only and does not exercise Stage 2
- Go covers 12 rules (`CG-001`/`CG-002`/`CG-020`/`CG-021`/`CG-022`/`CG-023`/`CG-025`/`CG-030`/`CG-031`/`CG-040`/`CG-050`/`CG-060`); Java covers those plus `CG-010`/`CG-041`/`CG-070` (15 total); PHP covers those plus `CG-003`/`CG-024`/`CG-026`/`CG-041`/`CG-070` (17 total). `CG-011` (DOM-based XSS) is JS/TS-only since it needs a browser DOM; `CG-024` (NoSQL injection) and `CG-026` (JWT signature bypass) are JS/TS/Python/PHP-only since they target MongoDB driver and JWT library call shapes that don't have a clean, low-false-positive equivalent in Go/Java's more strongly-typed driver APIs; `CG-070` (XXE) covers JS/TS/Python/Java/PHP but not Go, whose `encoding/xml` doesn't resolve external entities by default
- PHP's `CG-001` requires actual string concatenation/interpolation rather than falling back to a bare SQL-keyword sniff, because PDO's idiomatic `$pdo->prepare("SELECT ... WHERE id = ?")` takes the query as its only argument (parameters are bound via a later `execute([...])` call) — keyword-sniffing a plain literal would flag that standard safe pattern on every use
- Stage 1 has no dataflow analysis, so a rule can independently flag both an outer call and a call nested inside it for the same underlying issue (e.g. `db.Query(fmt.Sprintf(...))`, or a Go `tls.Config` struct literal nested inside an `http.Transport` literal). `runRules()` now suppresses same-rule findings whose location is fully contained within another finding of the same rule in the same file, keeping only the outer, more-contextual one — the separate two-step pattern (`query := fmt.Sprintf(...); db.Query(query)`), where the calls aren't nested, is unaffected and still reported
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
