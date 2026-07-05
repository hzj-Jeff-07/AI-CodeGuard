# Changelog

All notable changes to AI-CodeGuard are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added

- **Deeper Go/Java rule coverage** — Go goes from 5 to 8 built-in rules, Java from 5 to 9:
  - `CG-021` Weak Cryptography — Go: any call into the `crypto/md5`/`sha1`/`des`/`rc4` packages (the package itself is the weak-algorithm signal, e.g. `md5.Sum(...)`, `des.NewCipher(...)`); Java: `MessageDigest`/`Cipher.getInstance(...)` called with a weak algorithm string (`"MD5"`, `"SHA-1"`, `"DES"`, `"RC4"`); `"SHA-256"` and other strong algorithms are not flagged
  - `CG-040` Sensitive Data Exposure — Go: `log`/`logrus`/`zap`/`zerolog` logging calls; Java: `logger`/`log`/`System.out`/`System.err` logging calls; both reuse the existing password/token/secret/PII text heuristics
  - `CG-041` Insecure Deserialization (Java only) — `readObject()` method calls, the classic `ObjectInputStream`/`XMLDecoder` gadget-chain vector; Go has no equivalently clean idiom and is not covered
  - `CG-050` Security Misconfiguration — Go: `tls.Config{InsecureSkipVerify: true}`; Java: Spring `.csrf().disable()`, `.allowedOrigins("*")`, `setSecure(false)`, `setHttpOnly(false)`
  - Parser-level addition: Go `composite_literal` nodes (struct literals like `&tls.Config{...}`) are now normalized into the AST so text-pattern rules like `CG-050` can see them — previously only call/template/concat/credential nodes were reachable, so a misconfiguration expressed as a struct literal (not wrapped in a function call) was invisible to Stage 1
  - 20 new tests across the four rules; suite now at 297 tests (+1 opt-in skip)

## [0.3.0] — 2026-07-05

### Added

- **Java rule parity with Go** — Java now covers the same 5 rules as Go:
  - `CG-020` Hardcoded Credentials — field and local-variable literal assignments (`String password = "..."`); values read from `System.getenv` are not flagged
  - `CG-030` Path Traversal — `new File/FileInputStream/FileOutputStream/FileReader/FileWriter/RandomAccessFile` constructors and `Files`/`Paths` static helpers with concatenated or `String.format`-built paths; `normalize()`/`getCanonicalPath()` + `startsWith` in surrounding context is treated as sanitized
  - `CG-060` SSRF — `new URL/HttpGet/HttpPost/...`, `URI.create`, and RestTemplate-style calls (`getForObject`, `exchange`, …) with concatenated or `String.format`-built URLs
- 11 new tests (Java stretch-rule units + vulnerable/safe Java fixtures `Stretch.java` / `SecureStretch.java`)
- **Cost/model boundary tests** pinning the built-in pricing table (sonnet 3/15, opus 15/75, haiku 0.8/4, `gpt-4o-mini` matched before `gpt-4o`), unknown-model behavior (fail-fast with `llm.maxCostUSD`, zero-cost analysis without it), and budget-overshoot semantics under concurrency (in-flight calls finish and are honestly billed; no new calls start)
- **Opt-in real-provider acceptance test** (`tests/integration/llm-provider.test.ts`): runs `analyzeFindings` against the real Claude API when `CODEGUARD_E2E=1` and `ANTHROPIC_API_KEY` are set (defaults to Haiku); skipped otherwise so default regression stays offline
- **CI smoke test for the composite Action** (`action-smoke` job in `ci.yml`): runs the local `action.yml` against the vulnerable fixtures (asserts `findings-count > 0` and valid SARIF: version 2.1.0, driver name/version, results present) and the safe fixtures (asserts zero findings with `fail-on-findings: true` passing)
- `src/version.ts` as the single source for the version reported by `--version`, the JSON reporter, and the SARIF `tool.driver.version`, guarded by a test that fails when it drifts from `package.json`
- **Custom-rule pattern semantics and loader failure-path tests**: `function.on` receiver matching, `arguments` matchers (`template_string`/`string_concat`, `hasExpressions`, `operator`), `exclude` suppression, multi-pattern OR, Python f-string interpolation, custom-finding metadata, plus loader errors for missing paths, YAML-free directories, scalar documents, matcher-less patterns, cross-file duplicate IDs, and the wrapper/array file forms
- **Parser precision & compatibility tests**: 1-based line/column accuracy, nested-call normalization, syntax-error tolerance across all four grammars (including detection resuming after a broken statement), CRLF line numbers, CJK/emoji content, Go `var`/`const` and Java field credential normalization, and unit coverage for the Go/Java adapters (chained-invocation and package-qualified constructor callee parsing) — suite now at 277 tests (+1 opt-in skip)

### Fixed

- SARIF `informationUri` and the `init` config template pointed at the placeholder `github.com/user/ai-codeguard`; both now reference the real repository URL

## [0.2.0] — 2026-07-04

### Added

- **Java language support (MVP)**: Tree-sitter Java grammar bundled, `.java` detection, Java adapter (chained-invocation-aware callee extraction for `Runtime.getRuntime().exec(...)`), and 2 rules:
  - `CG-001` SQL Injection — `executeQuery/executeUpdate/prepareStatement/...` with concatenated or `String.format`-built queries, plus `String.format` calls assembling SQL; placeholder-parameterized `PreparedStatement` usage is not flagged
  - `CG-002` Command Injection — `Runtime.getRuntime().exec` / `new ProcessBuilder` with concatenated or `String.format`-built arguments

- **Go language support (M6)**: Tree-sitter Go grammar bundled into `dist/tree-sitter/`, `.go` extension detection, Go language adapter, and 5 rules covering Go:
  - `CG-001` SQL Injection — `db/tx/stmt` `Query/Exec/Prepare*` calls built via concatenation or `fmt.Sprintf`, plus `fmt.Sprintf` calls that assemble SQL strings (covers two-step `query := Sprintf(...)` patterns); placeholder-parameterized queries are not flagged
  - `CG-002` Command Injection — `exec.Command`/`CommandContext` with concatenated or Sprintf-built arguments
  - `CG-020` Hardcoded Credentials — `:=` / `var` / `const` literal assignments
  - `CG-030` Path Traversal — `os`/`ioutil` file functions with dynamic paths; `filepath.Clean` + `HasPrefix` treated as sanitized
  - `CG-060` SSRF — `http.*` calls with concatenated or Sprintf-built URLs
- **Stage 2 auditability**: findings the LLM does not confirm are no longer silently dropped — they are returned under `dismissedFindings` (JSON output) with the LLM's reasoning, and the text summary shows a dismissed count
- **Prompt-injection hardening**: the Stage 2 system prompt now explicitly treats scanned code as untrusted data and instructs the model not to follow instructions embedded in it
- `rules --list` now also prints custom rules loaded from config (supports `--config`)
- `init` template now enables the Stage 2 disk cache by default
- ESLint 9 flat config; `npm run lint` works and runs in CI
- CI now tests on Node 18 / 20 / 22 and runs lint
- `docs/design/CACHING.md` documenting the Stage 2 cache design
- npm publish readiness: `files` whitelist, `repository` field, `prepublishOnly` build+test gate
- README "Use as GitHub Action" section with a copy-paste workflow

### Changed

- Removed the unused `tree-sitter-cli` devDependency — its postinstall downloads a binary from GitHub releases, which broke `npm install` on networks where GitHub is unreachable; the project only needs the prebuilt wasm files shipped inside the grammar packages

- Default LLM model updated to `claude-sonnet-5`
- Default include patterns now match `.go` files
- `--severity` and `--output` CLI options validate their values (invalid values now error instead of being silently accepted)
- `action.yml` routes all inputs through environment variables (removes the workflow template-injection vector) and documents that `fail-on-findings` triggers on critical/high only

### Fixed

- **`--severity` typo no longer green-lights vulnerable code**: an invalid severity previously filtered out every finding and exited 0
- **Cache hits no longer inflate `estimatedCost`**: a fully cached rescan reports `llmCalls = 0` and `estimatedCost = 0`
- **`action.yml` `findings-count` output** was always 0 (`require()` cannot load `.sarif` files); now parsed with `JSON.parse`
- **CG-060 SSRF false positive** on Express route registrations (`app.get`, `router.post`)
- `package-lock.json` reconciled with `package.json` (stale entries for removed dependencies)

## [0.1.0] — 2026-04-12

Initial release: two-stage scanning CLI (Tree-sitter Stage 1 pre-filter + optional Claude/OpenAI Stage 2 confirmation) for JavaScript / TypeScript / Python, 13 built-in OWASP-oriented rules, YAML custom rules with `rules validate/create/test` workflow, text / JSON / SARIF output, config loading via `.codeguard.yml` and environment variables.
