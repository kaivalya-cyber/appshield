# Changelog

All notable changes to this project will be documented in this file. See [standard-version](https://github.com/conventional-changelog/standard-version) for commit guidelines.

## [1.0.0] - 2026-07-13

### Features
- Initial release: AI-powered security scanner CLI using Claude
- 14 security rules: SQL Injection, XSS, Command Injection, Insecure Deserialization, Secrets, Auth, IDOR, CSRF, SSRF, Prototype Pollution, Weak Cryptography, Security Headers, Open Redirect, ReDoS
- 7 output formats: terminal, JSON, HTML, SARIF, Markdown, CSV, JUnit XML
- Incremental scanning with SHA256 file hashing
- Baseline suppression for known false positives
- `.appshield.json` config auto-loading
- Docker support with multi-stage build and docker-compose
- 67 unit + integration tests with mocked API
- GitHub Actions CI pipeline (build, test, Docker publish)
- Pre-commit hooks with typecheck + test

### Bug Fixes
- CSV output double-escaping fix
- `matchesIgnorePattern` basename check for glob patterns
- Dockerfile production stage dev dependency leak
- `BaselineEntry` type now includes `rule` and `snippetHash` fields
