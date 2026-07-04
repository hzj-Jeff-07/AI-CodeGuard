# Changelog

All notable changes to AI-CodeGuard are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased] — targeting v0.2.0

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
