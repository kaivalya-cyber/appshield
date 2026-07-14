# Changelog

All notable changes to this project will be documented in this file. See [standard-version](https://github.com/conventional-changelog/standard-version) for commit guidelines.

## 1.0.0 (2026-07-14)


### Features

* add --ext filter, ruleset presets, and --watch mode ([069f490](https://github.com/yourusername/appshield/commit/069f4907c281a27c3dfcf420c27590e4a573e225))
* add 7 new security rules, 4 output formats, incremental scanning, baseline suppression, config auto-loading, Docker support, and unit tests ([3d76dfb](https://github.com/yourusername/appshield/commit/3d76dfb95f1fe089ac528ff35d2fef7e68c4d828))
* add CI pipeline, docs update, and integration tests ([b71f74b](https://github.com/yourusername/appshield/commit/b71f74b87a6eca7707276357412381ea46a1a86f))
* add pre-commit hooks, standard-version, CHANGELOG, and npm release workflow ([4c4017c](https://github.com/yourusername/appshield/commit/4c4017c34a1df48d963849f84bc31319fefad450))
* add self-scan workflow, ESLint/Prettier configs, and vulnerable code examples ([20ddd25](https://github.com/yourusername/appshield/commit/20ddd2518198ecfec125c810b15f17af083c3676))
* switch --watch mode to chokidar for reliable cross-platform file watching ([1e8cef0](https://github.com/yourusername/appshield/commit/1e8cef0cdbb6086b4684cf74cbdf262e76dc0cee))

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
