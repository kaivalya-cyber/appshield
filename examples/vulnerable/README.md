# Vulnerable Code Examples

This directory contains **intentionally vulnerable code** for testing AppShield.
**DO NOT use this code in production.**

## Usage

Scan this directory to see AppShield in action:

```bash
appshield scan ./examples/vulnerable --output terminal
```

Or with specific rules and format:

```bash
appshield scan ./examples/vulnerable --rules sql-injection,xss --output sarif
```

## Rules Demonstrated

| File | Rules Triggered |
|------|----------------|
| `sql-injection.ts` | SQL Injection |
| `xss.tsx` | Cross-Site Scripting |
| `hardcoded-secrets.ts` | Hardcoded Secrets |
| `command-injection.ts` | Command Injection, Path Traversal |
| `weak-crypto.ts` | Weak Cryptography |
| `csrf-ssrf.ts` | CSRF, SSRF |
| `idor-auth.ts` | IDOR, Broken Authentication |
