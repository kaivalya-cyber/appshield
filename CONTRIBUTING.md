# Contributing to AppShield

Thanks for contributing! AppShield is an AI-powered security scanner CLI.

## Setup

```bash
git clone https://github.com/yourusername/appshield.git
cd appshield
npm install
npm run build
cp .env.example .env
# Edit .env with your Anthropic API key
```

## Development Workflow

```bash
# Typecheck
npm run typecheck

# Run tests
npm test

# Run a scan in dev mode
npm run dev -- scan ./src
```

## Pre-commit Checks

Husky runs automatically before each commit:
- `tsc --noEmit` (typecheck)
- `jest` (all tests)

## Commit Convention

Use [Conventional Commits](https://www.conventionalcommits.org/):

```
feat: add SQL injection detection rule
fix: handle empty file list in scanner
docs: update README with new output formats
test: add integration test for SARIF reporter
```

## Adding New Rules

1. Create `src/rules/<your_rule>.ts` following the `Rule` interface
2. Register it in `src/rules/index.ts`
3. Add a test in `src/__tests__/rules.test.ts`
4. Run `npm test` to verify

## Release Process

```bash
# Bump version, update CHANGELOG, create tag
npm run release

# Or specific bump
npm run release:patch   # 1.0.0 → 1.0.1
npm run release:minor   # 1.0.0 → 1.1.0
npm run release:major   # 1.0.0 → 2.0.0

# Push with tags
git push --follow-tags
```

GitHub Actions will auto-publish to npm and create a GitHub release.

## Branch Protection

For repository maintainers, configure branch protection on `main`:

1. Go to **Settings → Branches → Add rule**
2. Set branch name pattern: `main`
3. Enable:
   - ✅ **Require a pull request before merging** (with 1 approval)
   - ✅ **Require status checks to pass before merging** (`build-and-test (18)`, `build-and-test (20)`, `build-and-test (22)`)
   - ✅ **Require conversation resolution before merging**
   - ✅ **Do not allow bypassing the above settings** (include administrators)

These settings ensure every change passes CI and gets reviewed before landing.

## Questions?

Open an issue or start a discussion!
