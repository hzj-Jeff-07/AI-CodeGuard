# Real-World Validation Report

The precision corpus (`tests/corpus/`) is written by the same hands that
write the rules, so its numbers carry self-grading bias. This report is the
counterweight: Stage 1 (`--dry-run`, no LLM) run against three unmodified
open-source repositories and every finding assessed by hand.

- **Date:** 2026-07-11 (v0.4.0 development)
- **Targets:**
  - [OWASP Juice Shop](https://github.com/juice-shop/juice-shop) — deliberately vulnerable TypeScript app (recall signal)
  - [fastify](https://github.com/fastify/fastify) — well-maintained Node framework (false-positive signal)
  - [flask](https://github.com/pallets/flask) — well-maintained Python framework (false-positive signal)
- **Method:** `ai-codeguard scan <repo> --dry-run -o json --fail-on none`,
  shallow clones of the default branch, default config.

## Headline

The first run exposed three systematic false-positive classes. Fixing them
(same session, commits in this branch) removed **84% of the noise on the two
clean repos while losing zero true vulnerabilities** on Juice Shop.

| Repo | Files | Before | After | Change |
|---|---|---|---|---|
| fastify | 102 | 177 | 29 | **−84%** |
| flask | 83 | 43 | 7 | **−84%** |
| juice-shop | 404 | 177 | 128 | −28% |

## False-positive classes found (and fixed)

### 1. CG-060 (SSRF): incoming `request` objects treated as HTTP clients

The receiver check used a substring match (`call.object.includes('request')`),
and the user-input regex was run over the whole expression — so it matched the
receiver itself. Every method call on fastify's incoming `request`
(`request.log.warn(...)`, 170 hits), pytest's `request` fixture
(`request.addfinalizer(...)`), and `flask.request.get_json()` was reported as
server-side request forgery.

**Fix:** receiver must contain an HTTP-module name as an exact dot-path
segment *and* the method must be a request-issuing verb (`get`, `post`,
`urlopen`, …); the user-input regex now tests the argument list only.

### 2. CG-003 (code injection): timers with function arguments

`setTimeout(resolve, ms)`, `setInterval(() => poll(), 5000)`, and the
socket-timeout API `server.setTimeout(ms)` were all flagged as eval-style
code injection. Only the legacy string form (`setTimeout("code()", ms)`)
evaluates anything.

**Fix:** timer functions are now flagged only when called bare (no receiver)
with a string-shaped first argument.

### 3. CG-001 (SQL injection): constant SQL treated as dynamic

Any query string containing SQL keywords was flagged, including flask's
canonical parameterized form `db.execute("SELECT * FROM user WHERE id = ?",
(user_id,))` (14 hits — every DB call in the flaskr tutorial app) and static
literals like `sequelize.query('SELECT sql FROM sqlite_master')`.

**Fix:** the rule now requires dynamic assembly — interpolation, concatenation
with a non-literal part, or Python's `.format()`/`%` builders. Concatenation
of pure literals (multi-line constant SQL) and interpolation-free template
literals count as constants.

### 4. Minified bundles dominate scans

A single vendored `dat.gui.min.js` produced more XSS findings than the rest
of Juice Shop's frontend. `**/*.min.js` is now in the default exclude list —
nobody fixes a minified line.

## What remains after the fixes

**fastify (29):** 28 CG-060 hits are genuine dynamic-URL `fetch()` calls in
test helpers and release scripts (`fetch('http://localhost:' + port)`); 1
CG-030 is a build script writing a path from a variable. All are the exact
textual shape the rules target, with context (test/localhost) that only
Stage 2 — or a human — can use to dismiss them. This is the intended division
of labor, not rule failure.

**flask (7):** `app.run(debug=True)` in tests (×2), `Markup(value)` inside
flask's own escaping implementation (×3), and `eval`/`exec` of user config
files in `cli.py`/`config.py` (×2) — the last two are real dynamic code
execution that flask does by design.

**juice-shop (128):** the flagship planted vulnerabilities are all still
found — SQL injection in `routes/login.ts:34` and `routes/search.ts:23`,
`$where` NoSQL injection (×7), path traversal in `routes/fileUpload.ts:34`,
MD5 password hashing and `Math.random()` tokens in `lib/insecurity.ts`,
`eval(expression)` in `routes/captcha.ts:22`. The remaining CG-060 volume
(74) is dominated by the Angular frontend's dynamic-URL HTTP calls, which
Stage 1 cannot distinguish from server-side fetches.

## Honest limits this run confirmed

- **No dataflow.** Query built on one line, executed on the next → missed.
  The corpus documents these as known FNs; real code hits them more often
  than fixtures do.
- **Stage 1 alone is not the product.** Even after the fixes, a clean repo
  gets ~0.3 findings/file of "textually suspicious, contextually fine" —
  exactly the residue Stage 2 triage exists to clear.

## Reproducing

```bash
git clone --depth 1 https://github.com/fastify/fastify /tmp/fastify
node dist/index.js scan /tmp/fastify --dry-run -o json -f report.json --fail-on none
```

The FP classes above are pinned as regression tests in
`tests/corpus/realworld.ts`, `tests/corpus/realworld_service.py`, and
`tests/unit/rules-builtin.test.ts`; the precision ratchet
(`npm run precision`) fails if any of them reappears.
