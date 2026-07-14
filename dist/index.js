#!/usr/bin/env node
"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const dotenv_1 = require("dotenv");
const path_1 = require("path");
const fs_1 = require("fs");
const promises_1 = require("fs/promises");
const crypto_1 = require("crypto");
const commander_1 = require("commander");
const chalk_1 = __importDefault(require("chalk"));
const ora_1 = __importDefault(require("ora"));
const scanner_1 = require("./scanner");
const rules_1 = require("./rules");
const chokidar_1 = __importDefault(require("chokidar"));
const reporter_1 = require("./reporter");
// ─── Valid output formats ──────────────────────────────────────────────────
const VALID_OUTPUTS = ['terminal', 'json', 'html', 'sarif', 'markdown', 'csv', 'junit'];
const VALID_SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'];
// ─── Load .env ─────────────────────────────────────────────────────────────
const envPath = (0, fs_1.existsSync)((0, path_1.join)(process.cwd(), '.env'))
    ? (0, path_1.join)(process.cwd(), '.env')
    : (0, path_1.join)(__dirname, '..', '.env');
(0, dotenv_1.config)({ path: envPath });
const program = new commander_1.Command();
program
    .name('appshield')
    .description('AI-powered security scanner that uses Claude to find vulnerabilities in your code')
    .version('1.0.0');
// ─── scan command ───────────────────────────────────────────────────────────
program
    .command('scan')
    .description('Scan a file or directory for security vulnerabilities')
    .argument('<path>', 'File or directory to scan')
    .option('-o, --output <format>', 'Output format: terminal, json, html, sarif, markdown, csv, junit')
    .option('-s, --severity <level>', 'Minimum severity: critical, high, medium, low, info')
    .option('-r, --rules <rules>', 'Comma-separated list of rules to run (default: all)')
    .option('--ignore <patterns>', 'Comma-separated glob patterns to ignore')
    .option('--fix', 'Write patched files as *.shielded.ext', false)
    .option('--ci', 'CI mode: exit code 1 if vulnerabilities found at or above severity', false)
    .option('--debug', 'Show debug information including raw API responses', false)
    .option('-c, --concurrency <n>', 'Number of parallel analysis calls (default: 3)')
    .option('--baseline <path>', 'Path to baseline file for suppressing known false positives')
    .option('--incremental', 'Only scan files that changed since last scan', false)
    .option('-q, --quiet', 'Suppress progress output, only show final report', false)
    .option('--ext <extensions>', 'Comma-separated file extensions to scan (e.g. .ts,.js)')
    .option('--preset <name>', 'Ruleset preset: owasp-top10, critical-only, web-app')
    .option('-w, --watch', 'Watch for file changes and re-scan', false)
    .action(async (targetPath, opts) => {
    // ─── Load .appshield.json config ──────────────────────────────────────
    let config = {};
    try {
        const targetAbs = (0, path_1.resolve)(targetPath);
        const isDir = (0, fs_1.existsSync)(targetAbs) && (0, fs_1.statSync)(targetAbs).isDirectory();
        const targetConfigPath = (0, path_1.join)(targetAbs, '.appshield.json');
        const fallbackConfigPath = (0, path_1.join)(process.cwd(), '.appshield.json');
        const finalConfigPath = (isDir && (0, fs_1.existsSync)(targetConfigPath))
            ? targetConfigPath
            : ((0, fs_1.existsSync)(fallbackConfigPath) ? fallbackConfigPath : null);
        if (finalConfigPath) {
            const fileContent = await (0, promises_1.readFile)(finalConfigPath, 'utf-8');
            config = JSON.parse(fileContent);
        }
    }
    catch {
        // Malformed or missing config — fall through to defaults
    }
    // Parse CLI arrays
    const cliRules = opts.rules ? opts.rules.split(',').map((r) => r.trim()) : undefined;
    const cliIgnore = opts.ignore ? opts.ignore.split(',').map((p) => p.trim()) : [];
    const cliExt = opts.ext ? opts.ext.split(',').map((e) => {
        e = e.trim().toLowerCase();
        return e.startsWith('.') ? e : '.' + e;
    }) : [];
    // Resolve preset if provided (adds to any explicit --rules)
    const presetRules = [];
    if (opts.preset) {
        const resolved = (0, rules_1.resolvePreset)(opts.preset);
        if (!resolved) {
            console.error(chalk_1.default.red(`❌ Unknown preset: ${opts.preset}. Use: owasp-top10, critical-only, web-app`));
            process.exit(1);
        }
        presetRules.push(...resolved);
    }
    // Build ScanOptions (CLI overrides config, config overrides defaults)
    const options = {
        output: opts.output ?? config.output ?? 'terminal',
        severity: opts.severity ?? config.severity ?? 'medium',
        rules: [...new Set([...(cliRules ?? config.rules ?? []), ...presetRules])],
        ignore: Array.from(new Set([...(config.ignore || []), ...cliIgnore])),
        extensions: cliExt,
        fix: opts.fix || false,
        ci: opts.ci || false,
        debug: opts.debug || false,
        concurrency: opts.concurrency ? parseInt(opts.concurrency, 10) : (config.concurrency ?? 3),
        baseline: opts.baseline ?? config.baseline ?? undefined,
        incremental: opts.incremental || false,
        quiet: opts.quiet || false,
        watch: opts.watch || false,
    };
    // Validate output format
    if (!VALID_OUTPUTS.includes(options.output)) {
        console.error(chalk_1.default.red(`❌ Invalid output format: ${options.output}. Use: ${VALID_OUTPUTS.join(', ')}`));
        process.exit(1);
    }
    // Validate severity
    if (!VALID_SEVERITIES.includes(options.severity)) {
        console.error(chalk_1.default.red(`❌ Invalid severity: ${options.severity}. Use: ${VALID_SEVERITIES.join(', ')}`));
        process.exit(1);
    }
    // Validate concurrency
    if (options.concurrency < 1 || options.concurrency > 10) {
        console.error(chalk_1.default.red('❌ Concurrency must be between 1 and 10.'));
        process.exit(1);
    }
    // Show banner (unless JSON/SARIF/CSV/JUnit output or quiet mode)
    const isMachineOutput = ['json', 'sarif', 'csv', 'junit'].includes(options.output);
    if (!isMachineOutput && !options.quiet) {
        console.log('');
        console.log(chalk_1.default.bold.white('  🛡️  AppShield v1.0.0'));
        console.log(chalk_1.default.gray('  AI-powered security scanner'));
        console.log('');
    }
    // Show incremental/baseline info
    if (!isMachineOutput && !options.quiet) {
        if (options.incremental) {
            console.log(chalk_1.default.gray('  ⚡ Incremental scan mode — only changed files will be analyzed'));
        }
        if (options.baseline) {
            console.log(chalk_1.default.gray(`  📋 Using baseline: ${options.baseline}`));
        }
    }
    // Start spinner (unless machine output or quiet mode)
    const spinner = isMachineOutput || options.quiet
        ? null
        : (0, ora_1.default)({ text: 'Initializing scan...', color: 'cyan' }).start();
    try {
        const report = await (0, scanner_1.scan)(targetPath, options, (message) => {
            if (spinner) {
                spinner.text = message;
            }
        });
        spinner?.stop();
        // Output the report
        switch (options.output) {
            case 'terminal':
                (0, reporter_1.reportTerminal)(report);
                break;
            case 'json':
                console.log((0, reporter_1.reportJSON)(report));
                break;
            case 'sarif':
                console.log((0, reporter_1.reportSARIF)(report));
                break;
            case 'markdown': {
                const mdContent = (0, reporter_1.reportMarkdown)(report);
                const outputPath = (0, path_1.resolve)('appshield-report.md');
                await (0, promises_1.writeFile)(outputPath, mdContent, 'utf-8');
                console.log(chalk_1.default.green(`\n  ✓ Markdown report written to ${outputPath}\n`));
                break;
            }
            case 'csv':
                console.log((0, reporter_1.reportCSV)(report));
                break;
            case 'junit':
                console.log((0, reporter_1.reportJUnit)(report));
                break;
            case 'html': {
                const htmlContent = (0, reporter_1.reportHTML)(report);
                const outputPath = (0, path_1.resolve)('appshield-report.html');
                await (0, promises_1.writeFile)(outputPath, htmlContent, 'utf-8');
                console.log(chalk_1.default.green(`\n  ✓ HTML report written to ${outputPath}\n`));
                break;
            }
        }
        // Write fixed files if --fix flag is set
        if (options.fix && report.totalVulnerabilities > 0) {
            const basePath = (0, path_1.resolve)(targetPath);
            const writtenFiles = await (0, scanner_1.writeFixedFiles)(report, basePath);
            if (writtenFiles.length > 0) {
                console.log(chalk_1.default.green.bold(`\n  ✓ Patched ${writtenFiles.length} file(s):`));
                for (const f of writtenFiles) {
                    console.log(chalk_1.default.green(`    → ${f}`));
                }
                console.log('');
            }
        }
        // CI mode: exit with code 1 if vulnerabilities found
        if (options.ci && report.totalVulnerabilities > 0) {
            process.exit(1);
        }
        // ─── Watch mode: re-scan on file changes (debounced) ───────────
        if (options.watch) {
            const targetAbs = (0, path_1.resolve)(targetPath);
            const isDir = (0, fs_1.statSync)(targetAbs).isDirectory();
            const targetBasename = isDir ? null : (0, path_1.basename)(targetAbs);
            const watchDir = isDir ? targetAbs : (0, path_1.resolve)(targetAbs, '..');
            console.log(chalk_1.default.gray(`\n  👀 Watching for changes in ${watchDir}...`));
            console.log(chalk_1.default.gray('  Press Ctrl+C to stop.\n'));
            // Debounce: wait 2s after last change before re-scanning
            let debounceTimer = null;
            let scanning = false;
            const watcher = chokidar_1.default.watch(watchDir, {
                ignored: /(^|[/\\])\./,
                persistent: true,
                ignoreInitial: true,
            });
            const handleChange = (filename) => {
                // Filter by extension
                const ext = (0, path_1.extname)(filename).toLowerCase();
                if (options.extensions.length > 0 && !options.extensions.includes(ext))
                    return;
                // For single-file watch, ignore changes to other files
                if (!isDir && (0, path_1.basename)(filename) !== targetBasename)
                    return;
                // Reset debounce timer
                if (debounceTimer)
                    clearTimeout(debounceTimer);
                debounceTimer = setTimeout(async () => {
                    if (scanning)
                        return;
                    scanning = true;
                    console.log(chalk_1.default.cyan(`\n  🔄 Change detected: ${filename}`));
                    console.log(chalk_1.default.gray('  Re-scanning...\n'));
                    try {
                        const newReport = await (0, scanner_1.scan)(targetPath, options, (msg) => {
                            if (!options.quiet)
                                console.log(chalk_1.default.gray(`  ${msg}`));
                        });
                        if (newReport.totalVulnerabilities > 0) {
                            console.log(chalk_1.default.red.bold(`  ⚠ ${newReport.totalVulnerabilities} finding(s) after re-scan`));
                        }
                        else {
                            console.log(chalk_1.default.green.bold('  ✓ No findings'));
                        }
                    }
                    catch (err) {
                        console.error(chalk_1.default.red(`  ❌ Scan error: ${err.message}`));
                    }
                    finally {
                        scanning = false;
                    }
                }, 2000); // 2-second debounce
            };
            watcher.on('change', handleChange);
            watcher.on('add', handleChange);
            // Keep process alive
            await new Promise(() => { });
        }
    }
    catch (error) {
        spinner?.fail('Scan failed');
        console.error(chalk_1.default.red(`\n  ❌ ${error.message}\n`));
        if (options.debug && error.stack) {
            console.error(chalk_1.default.gray(error.stack));
        }
        process.exit(1);
    }
});
// ─── rules command ──────────────────────────────────────────────────────────
program
    .command('rules')
    .description('List all available security rules')
    .action(() => {
    (0, reporter_1.reportRulesTable)();
});
// ─── init command ───────────────────────────────────────────────────────────
program
    .command('init')
    .description('Create a .appshield.json config file with defaults')
    .action(async () => {
    const configPath = (0, path_1.resolve)('.appshield.json');
    if ((0, fs_1.existsSync)(configPath)) {
        console.log(chalk_1.default.yellow(`\n  ⚠ .appshield.json already exists. Delete it first to reinitialize.\n`));
        return;
    }
    const defaultConfig = {
        ignore: ['node_modules', 'dist', 'build', '*.test.ts', '*.test.js', '*.spec.ts', '*.spec.js'],
        severity: 'medium',
        rules: [], // empty = all rules
        output: 'terminal',
        concurrency: 3,
        baseline: undefined,
    };
    await (0, promises_1.writeFile)(configPath, JSON.stringify(defaultConfig, null, 2) + '\n', 'utf-8');
    console.log(chalk_1.default.green(`\n  ✓ Created .appshield.json with default configuration.\n`));
    console.log(chalk_1.default.gray('  Edit the file to customize ignored paths, default severity, and active rules.'));
    console.log(chalk_1.default.gray('  Supported options: ignore, severity, rules, output, concurrency, baseline'));
    console.log('');
});
// ─── baseline command ────────────────────────────────────────────────────────
program
    .command('baseline')
    .description('Create or update a .appshield-baseline.json from a scan report')
    .argument('<report>', 'Path to JSON scan report to generate baseline from')
    .option('-o, --output <path>', 'Output path for baseline file', '.appshield-baseline.json')
    .action(async (reportPath, opts) => {
    try {
        const reportContent = await (0, promises_1.readFile)((0, path_1.resolve)(reportPath), 'utf-8');
        const report = JSON.parse(reportContent);
        if (!report.results || !Array.isArray(report.results)) {
            console.error(chalk_1.default.red('❌ Invalid report file: missing "results" array.'));
            process.exit(1);
        }
        const entries = [];
        for (const result of report.results) {
            for (const vuln of result.vulnerabilities) {
                const snippetHash = (0, crypto_1.createHash)('sha256').update(vuln.snippet.trim()).digest('hex');
                entries.push({
                    id: vuln.id,
                    rule: vuln.rule,
                    file: result.file,
                    snippetHash,
                    reason: 'Auto-generated from scan report',
                    suppressedAt: new Date().toISOString(),
                });
            }
        }
        const baseline = {
            version: '1.0.0',
            projectPath: report.projectPath || '.',
            entries,
        };
        const outputPath = (0, path_1.resolve)(opts.output || '.appshield-baseline.json');
        await (0, promises_1.writeFile)(outputPath, JSON.stringify(baseline, null, 2) + '\n', 'utf-8');
        console.log(chalk_1.default.green(`\n  ✓ Baseline created with ${entries.length} entries at ${outputPath}\n`));
        console.log(chalk_1.default.gray('  Run scans with --baseline to suppress these findings.'));
        console.log(chalk_1.default.gray('  Edit the file to add reasons for each suppression.'));
        console.log('');
    }
    catch (error) {
        console.error(chalk_1.default.red(`\n  ❌ Failed to create baseline: ${error.message}\n`));
        process.exit(1);
    }
});
// ─── Parse & run ────────────────────────────────────────────────────────────
program.parse();
//# sourceMappingURL=index.js.map