# Using AI-CodeGuard as a GitHub Action

> Drop-in security scanning for your repository. Outputs SARIF, integrates with GitHub Code Scanning.

## Quick Start (Stage 1 only, no API key needed)

```yaml
name: security-scan
on:
  pull_request:
  push:
    branches: [main]

permissions:
  contents: read
  security-events: write

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Run AI-CodeGuard
        uses: hzj-Jeff-07/AI-CodeGuard@main
        with:
          paths: ./src
          dry-run: 'true'
          output-file: ai-codeguard.sarif

      - name: Upload SARIF to Code Scanning
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: ai-codeguard.sarif
          category: ai-codeguard
```

That's it. Push or open a PR — findings will appear under your repository's **Security → Code scanning** tab.

## Full Two-Stage Scan (with LLM confirmation)

Add a secret named `CODEGUARD_API_KEY` (Anthropic or OpenAI key), then:

```yaml
- name: Run AI-CodeGuard (Stage 1 + Stage 2)
  uses: hzj-Jeff-07/AI-CodeGuard@main
  with:
    paths: ./src
    dry-run: 'false'
    fix: 'true'
    api-key: ${{ secrets.CODEGUARD_API_KEY }}
    output-file: ai-codeguard.sarif
```

## Inputs

| Input | Default | Description |
|---|---|---|
| `paths` | `.` | Files or directories to scan (space-separated). |
| `config` | — | Path to `.codeguard.yml`. |
| `output-file` | `ai-codeguard.sarif` | Where to write the SARIF report. |
| `dry-run` | `true` | `true` = Stage 1 only (no API key). `false` = run Stage 2. |
| `fix` | `false` | Generate LLM fix suggestions (Stage 2 only). |
| `api-key` | — | Required when `dry-run=false`. Pass via `${{ secrets.* }}`. |
| `severity` | — | Minimum severity: `low`, `medium`, `high`, `critical`. |
| `fail-on-findings` | `true` | Fail the job if critical/high findings exist. |
| `node-version` | `20` | Node.js version. |

## Outputs

| Output | Description |
|---|---|
| `sarif-file` | Path to the generated SARIF file. |
| `findings-count` | Number of findings in the report. |

## Recipes

### Block PR on critical findings only

```yaml
- uses: hzj-Jeff-07/AI-CodeGuard@main
  with:
    paths: ./src
    severity: critical
    fail-on-findings: 'true'
```

### Comment on PR with findings count

```yaml
- name: Run scan
  id: scan
  uses: hzj-Jeff-07/AI-CodeGuard@main
  with:
    paths: ./src

- name: Report findings
  run: echo "Found ${{ steps.scan.outputs.findings-count }} potential issues"
```

### Custom config file

```yaml
- uses: hzj-Jeff-07/AI-CodeGuard@main
  with:
    paths: ./src
    config: .github/codeguard.yml
```

## Permissions

For SARIF upload to GitHub Code Scanning, the workflow needs:

```yaml
permissions:
  contents: read
  security-events: write
```

## Cost Notes

- **Stage 1 only** (`dry-run: true`): zero API cost, runs fully local.
- **Stage 2 enabled**: each finding triggers one LLM call. Use `.codeguard.yml` to set `llm.maxCostUSD` as a hard cap.

## Limitations

- Currently supports JavaScript / TypeScript / Python (Go / Java planned).
- Linux runner is the primary target. Windows / macOS may work but are not yet tested.
- For private repos, ensure `security-events: write` is granted at the workflow level.
