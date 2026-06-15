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
| `--output <format>` | `-o` | Output format: `terminal`, `json`, `html` | `terminal` |
| `--severity <level>` | `-s` | Min severity to report: `critical`, `high`, `medium`, `low`, `info` | `medium` |
| `--rules <rules>` | `-r` | Comma-separated rules to run | all |
| `--ignore <patterns>` | | Comma-separated glob patterns to ignore | — |
| `--fix` | | Write patched files as `*.shielded.ext` | `false` |
| `--ci` | | Exit code 1 if vulnerabilities found ≥ severity | `false` |
| `--debug` | | Show raw API responses for debugging | `false` |

**Examples:**

```bash
# Scan a directory with default settings
appshield scan ./src

# Only report high+ severity, output as JSON
appshield scan ./src --severity high --output json > report.json

# Scan a single file with specific rules
appshield scan ./app.py --rules sql,injection

# CI mode: fail the build on critical issues
appshield scan . --ci --severity critical

# Generate an HTML report
appshield scan ./src --output html

# Auto-generate patched files
appshield scan ./src --fix
```

### `appshield rules`

List all available security rules with severity, CWE, and OWASP references.

### `appshield init`

Create a `.appshield.json` config file with customizable defaults.

---

## Example Terminal Output

```
  AppShield Security Report
  ══════════════════════════════════════════

    Scanned: ./src  (14 files, 2.3s)

    ● 2 CRITICAL   ▲ 3 HIGH   ◆ 1 MEDIUM   ○ 0 LOW

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

## Security Rules

| Rule | Name | Severity | CWE | OWASP |
|------|------|----------|-----|-------|
| `sql` | SQL Injection | 🔴 Critical | CWE-89 | A03:2021 |
| `xss` | Cross-Site Scripting | 🔴 Critical | CWE-79 | A03:2021 |
| `injection` | Command Injection & Path Traversal | 🔴 Critical | CWE-78, CWE-22 | A03:2021 |
| `secrets` | Hardcoded Secrets | 🟡 High | CWE-798 | A02:2021 |
| `auth` | Broken Authentication | 🟡 High | CWE-287 | A07:2021 |
| `idor` | Insecure Direct Object Reference | 🟡 High | CWE-639 | A01:2021 |
| `headers` | Missing Security Headers | 🔵 Medium | CWE-693 | A05:2021 |

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
          node /tmp/appshield/dist/index.js scan ./src --ci --severity high --output json > security-report.json

      - name: Upload Report
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: security-report
          path: security-report.json
```

---

## Configuration

Create a `.appshield.json` in your project root (or run `appshield init`):

```json
{
  "ignore": ["node_modules", "dist", "build", "*.test.ts", "*.spec.ts"],
  "severity": "medium",
  "rules": [],
  "output": "terminal"
}
```

You can also create a `.appshieldignore` file (similar to `.gitignore`) with one pattern per line:

```
node_modules
dist
build
*.test.ts
fixtures/
```

---

## How It Works

1. **File Discovery** — Recursively walks the target path, skipping binary files, `node_modules`, `.git`, and configured ignore patterns
2. **Rule Matching** — Each file is matched against applicable rules based on its extension
3. **Code Chunking** — Files >500 lines are split into overlapping 400-line chunks for thorough analysis
4. **AI Analysis** — Claude analyzes each file × rule combination with specialized security prompts
5. **Report Generation** — Findings are aggregated, deduplicated, and formatted per your output preference

---

## Tech Stack

- **Runtime**: Node.js (v18+)
- **Language**: TypeScript
- **AI**: Anthropic Claude API
- **CLI**: commander, chalk, ora, cli-table3
- **Config**: dotenv

---

## License

MIT
