# 🛡️ AppShield — AI Security Scanner CLI

**AppShield** scans your source code for security vulnerabilities using Claude AI. It produces structured reports with severity ratings, explanations, and patched code suggestions — so you can ship fast without shipping exploits.

Built for developers who vibe-code and need a safety net.

---

## Quick Start

```bash
# 1. Clone or download appshield
git clone https://github.com/yourusername/appshield.git && cd appshield

# 2. Install dependencies & build
npm install && npm run build

# 3. Set your Anthropic API key
cp .env.example .env
# Edit .env and add your key from https://console.anthropic.com/

# 4. Run your first scan
node dist/index.js scan ./your-project
```

### Global Install

```bash
npm install -g .
appshield scan ./your-project
```

### Docker

```bash
# Build and run via Docker
docker compose build
docker compose run --rm appshield scan ./your-project

# CI mode (SARIF output for GitHub Code Scanning)
docker compose --profile ci run --rm ci-scan
```

### One-off with npx

```bash
npx appshield scan ./src
```

---

## CLI Commands

### `appshield scan <path>`

Scan a file or directory for security vulnerabilities.

| Flag | Short | Description | Default |
|------|-------|-------------|---------|
| `--output <format>` | `-o` | Output format: `terminal`, `json`, `html`, `sarif`, `markdown`, `csv`, `junit` | `terminal` |
| `--severity <level>` | `-s` | Min severity to report: `critical`, `high`, `medium`, `low`, `info` | `medium` |
| `--rules <rules>` | `-r` | Comma-separated rules to run | all |
| `--ignore <patterns>` | | Comma-separated glob patterns to ignore | — |
| `--fix` | | Write patched files as `*.shielded.ext` | `false` |
| `--ci` | | Exit code 1 if vulnerabilities found ≥ severity | `false` |
| `--debug` | | Show raw API responses for debugging | `false` |
| `--concurrency <n>` | `-c` | Number of parallel analysis calls | `3` |
| `--baseline <path>` | | Path to baseline file for suppressing known false positives | — |
| `--incremental` | | Only scan files changed since last scan | `false` |
| `--quiet` | `-q` | Suppress progress output | `false` |

**Examples:**

```bash
# Scan a directory with default settings
appshield scan ./src

# Only report high+ severity, output as SARIF
appshield scan ./src --severity high --output sarif > scan.sarif

# Scan a single file with specific rules
appshield scan ./app.py --rules sql,injection

# CI mode: fail the build on critical issues
appshield scan . --ci --severity critical

# Generate an HTML report
appshield scan ./src --output html

# Markdown report (saved to appshield-report.md)
appshield scan ./src --output markdown

# CSV output for spreadsheet analysis
appshield scan ./src --output csv > findings.csv

# JUnit XML for CI test runners
appshield scan ./src --output junit > junit.xml

# Auto-generate patched files
appshield scan ./src --fix

# Fast incremental scan (only changed files)
appshield scan ./src --incremental

# Faster analysis with higher concurrency
appshield scan ./src --concurrency 5

# Suppress known false positives
appshield scan ./src --baseline .appshield-baseline.json
```

### `appshield rules`

List all available security rules with severity, CWE, and OWASP references.

### `appshield init`

Create a `.appshield.json` config file with customizable defaults.

### `appshield baseline <report.json>`

Generate a baseline file from a JSON scan report. Suppressed findings won't appear in future scans when using `--baseline`.

```bash
# First scan
appshield scan ./src --output json > report.json

# Generate baseline from the report
appshield baseline report.json

# Re-scan with baseline (suppressed findings hidden)
appshield scan ./src --baseline .appshield-baseline.json
```

---

## Example Terminal Output

```
  AppShield Security Report
  ══════════════════════════════════════════

    Scanned: ./src  (14 files, 2.3s)

    ● 2 CRITICAL   ▲ 3 HIGH   ◆ 1 MEDIUM   ○ 0 LOW

    2 finding(s) suppressed by baseline
    7 new finding(s)

  ══════════════════════════════════════════

    [CRITICAL] SQL Injection — src/routes/users.ts:42
    CWE-89 · OWASP A03:2021

    Raw user input is concatenated directly into a SQL query,
    allowing an attacker to manipulate the query logic, dump
    the database, or bypass authentication entirely.

    Vulnerable:
    ┌─────────────────────────────────────────────────────────┐
    │  const query = "SELECT * FROM users WHERE id = " + req.params.id
    └─────────────────────────────────────────────────────────┘

    Fixed:
    ┌─────────────────────────────────────────────────────────┐
    │  const query = "SELECT * FROM users WHERE id = ?"       │
    │  db.execute(query, [req.params.id]) // parameterized    │
    └─────────────────────────────────────────────────────────┘

  ──────────────────────────────────────────

    Run with --output json for machine-readable output.
    Run with --fix to write patched files.
```

---

## Output Formats

AppShield supports seven output formats for different use cases:

| Format | Use Case | Flag |
|--------|----------|------|
| `terminal` | Interactive CLI usage with colored output | `-o terminal` |
| `json` | Machine-readable, CI pipelines | `-o json` |
| `html` | Shareable visual report | `-o html` |
| `sarif` | GitHub Code Scanning integration | `-o sarif` |
| `markdown` | PR comments, documentation | `-o markdown` |
| `csv` | Spreadsheet analysis, data processing | `-o csv` |
| `junit` | Test runner integration (Jenkins, CircleCI) | `-o junit` |

---

## Security Rules

AppShield ships with **14 detection rules**:

| Rule | Name | Severity | CWE | OWASP |
|------|------|----------|-----|-------|
| `sql-injection` | SQL Injection | 🔴 Critical | CWE-89 | A03:2021 |
| `xss` | Cross-Site Scripting | 🔴 Critical | CWE-79 | A03:2021 |
| `injection` | Command Injection & Path Traversal | 🔴 Critical | CWE-78, CWE-22 | A03:2021 |
| `insecure-deserialization` | Insecure Deserialization | 🔴 Critical | CWE-502 | A08:2021 |
| `secrets` | Hardcoded Secrets | 🟡 High | CWE-798 | A02:2021 |
| `auth` | Broken Authentication | 🟡 High | CWE-287 | A07:2021 |
| `idor` | Insecure Direct Object Reference | 🟡 High | CWE-639 | A01:2021 |
| `csrf` | Cross-Site Request Forgery | 🟡 High | CWE-352 | A01:2021 |
| `ssrf` | Server-Side Request Forgery | 🟡 High | CWE-918 | A10:2021 |
| `prototype-pollution` | Prototype Pollution | 🟡 High | CWE-1321 | A08:2021 |
| `weak-crypto` | Weak Cryptography | 🟡 High | CWE-327 | A02:2021 |
| `headers` | Missing Security Headers | 🔵 Medium | CWE-693 | A05:2021 |
| `open-redirect` | Open Redirect | 🔵 Medium | CWE-601 | A01:2021 |
| `redos` | ReDoS | 🔵 Medium | CWE-1333 | A05:2021 |

---

## Incremental Scanning

Use `--incremental` to scan only files that changed since the last scan. AppShield maintains a `.appshield-cache.json` with SHA256 hashes of each scanned file.

```bash
# First scan (full scan, builds cache)
appshield scan ./src --incremental

# Subsequent scans (only changed files are analyzed)
appshield scan ./src --incremental
# → "Skipped 42 unchanged files (incremental scan)."
```

---

## Baseline Suppression

Suppress known false positives by creating a baseline:

```bash
# 1. Run a JSON scan
appshield scan ./src --output json > report.json

# 2. Generate baseline from report
appshield baseline report.json

# 3. Edit .appshield-baseline.json to add reasons
# 4. Re-scan with baseline — suppressed findings won't appear
appshield scan ./src --baseline .appshield-baseline.json
```

---

## CI/CD Integration

### GitHub Actions

```yaml
name: Security Scan
on: [push, pull_request]

jobs:
  appshield:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: actions/setup-node@v4
        with:
          node-version: '20'

      - name: Install AppShield
        run: |
          git clone https://github.com/yourusername/appshield.git /tmp/appshield
          cd /tmp/appshield && npm install && npm run build

      - name: Run Security Scan
        env:
          ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}
        run: |
          node /tmp/appshield/dist/index.js scan ./src --ci --severity high --output sarif > security-report.sarif

      - name: Upload SARIF Report
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: security-report.sarif

      - name: Upload JSON Report
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: security-report
          path: security-report.sarif
```

### GitHub Actions (Docker)

```yaml
name: Security Scan (Docker)
on: [push]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Build and scan with Docker
        env:
          ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}
        run: |
          docker compose --profile ci run --rm ci-scan
```

### Jenkins / CircleCI (JUnit)

```bash
# Output JUnit XML for test runner integration
appshield scan ./src --output junit --ci --severity high > appshield-results.xml
```

---

## Configuration

### `.appshield.json` (auto-loaded)

AppShield automatically loads `.appshield.json` from the scanned directory (or current working directory as fallback). CLI flags override config values.

Create one manually or run `appshield init`:

```json
{
  "ignore": ["node_modules", "dist", "build", "*.test.ts", "*.spec.ts"],
  "severity": "medium",
  "rules": [],
  "output": "terminal",
  "concurrency": 3,
  "baseline": ".appshield-baseline.json"
}
```

### `.appshieldignore`

Ignore specific files/directories from scanning (similar to `.gitignore`):

```
node_modules
dist
build
*.test.ts
fixtures/
```

### `.appshield-baseline.json`

Stores suppressed false positives:

```json
{
  "version": "1.0.0",
  "projectPath": "./src",
  "entries": [
    {
      "id": "SQL_001",
      "rule": "sql-injection",
      "file": "src/legacy/db.ts",
      "snippetHash": "abc123...",
      "reason": "Legacy code, scheduled for deprecation in Q4",
      "suppressedAt": "2026-07-13T00:00:00Z"
    }
  ]
}
```

---

## Docker

### Local Usage

```bash
# Build the image
docker compose build

# Scan a local directory
docker compose run --rm appshield scan /scan-target

# Scan the current directory
docker compose run --rm appshield scan /scan-target --output sarif

# Run with incremental scanning
docker compose run --rm appshield scan /scan-target --incremental --quiet
```

### CI/CD

```bash
# Run CI scan (exits 1 on findings, outputs SARIF)
docker compose --profile ci run --rm ci-scan
```

### Custom Build

```bash
docker build -t appshield .
docker run --rm \
  -e ANTHROPIC_API_KEY=$ANTHROPIC_API_KEY \
  -v $(pwd):/scan-target:ro \
  appshield scan /scan-target --output json
```

---

## How It Works

1. **File Discovery** — Recursively walks the target path, skipping binary files, `node_modules`, `.git`, and configured ignore patterns
2. **Rule Matching** — Each file is matched against applicable rules based on its extension
3. **Incremental Skip** — In `--incremental` mode, SHA256 hashes are compared against `.appshield-cache.json` to skip unchanged files
4. **Code Chunking** — Files >500 lines are split into overlapping 400-line chunks for thorough analysis
5. **AI Analysis** — Claude analyzes each file × rule combination with specialized security prompts
6. **Deduplication** — Findings with identical rule + file + snippet are collapsed into one
7. **Baseline Filtering** — Previously suppressed findings from `.appshield-baseline.json` are hidden
8. **Report Generation** — Findings are aggregated, count by severity, and formatted per your output preference

---

## Tech Stack

- **Runtime**: Node.js (v18+)
- **Language**: TypeScript
- **AI**: Anthropic Claude API
- **CLI**: commander, chalk, ora, cli-table3
- **Config**: dotenv
- **Testing**: Jest + ts-jest

---

## Development

```bash
# Install dependencies
npm install

# Build
npm run build

# Run tests
npm test

# Typecheck
npx tsc --noEmit

# Run CLI in dev mode
npm run dev -- scan ./src
```

---

## License

MIT
