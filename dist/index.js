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
const commander_1 = require("commander");
const chalk_1 = __importDefault(require("chalk"));
const ora_1 = __importDefault(require("ora"));
const scanner_1 = require("./scanner");
const reporter_1 = require("./reporter");
// Load .env from current directory or project root
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
    .option('-o, --output <format>', 'Output format: terminal, json, html', 'terminal')
    .option('-s, --severity <level>', 'Minimum severity: critical, high, medium, low, info', 'medium')
    .option('-r, --rules <rules>', 'Comma-separated list of rules to run (default: all)')
    .option('--ignore <patterns>', 'Comma-separated glob patterns to ignore')
    .option('--fix', 'Write patched files as *.shielded.ext', false)
    .option('--ci', 'CI mode: exit code 1 if vulnerabilities found at or above severity', false)
    .option('--debug', 'Show debug information including raw API responses', false)
    .action(async (targetPath, opts) => {
    const options = {
        output: opts.output || 'terminal',
        severity: opts.severity || 'medium',
        rules: opts.rules ? opts.rules.split(',').map((r) => r.trim()) : [],
        ignore: opts.ignore ? opts.ignore.split(',').map((p) => p.trim()) : [],
        fix: opts.fix || false,
        ci: opts.ci || false,
        debug: opts.debug || false,
    };
    // Validate output format
    if (!['terminal', 'json', 'html'].includes(options.output)) {
        console.error(chalk_1.default.red(`❌ Invalid output format: ${options.output}. Use terminal, json, or html.`));
        process.exit(1);
    }
    // Validate severity
    if (!['critical', 'high', 'medium', 'low', 'info'].includes(options.severity)) {
        console.error(chalk_1.default.red(`❌ Invalid severity: ${options.severity}. Use critical, high, medium, low, or info.`));
        process.exit(1);
    }
    // Show banner (unless JSON output)
    if (options.output !== 'json') {
        console.log('');
        console.log(chalk_1.default.bold.white('  🛡️  AppShield v1.0.0'));
        console.log(chalk_1.default.gray('  AI-powered security scanner'));
        console.log('');
    }
    // Start spinner (unless JSON output)
    const spinner = options.output !== 'json'
        ? (0, ora_1.default)({ text: 'Initializing scan...', color: 'cyan' }).start()
        : null;
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
    };
    await (0, promises_1.writeFile)(configPath, JSON.stringify(defaultConfig, null, 2) + '\n', 'utf-8');
    console.log(chalk_1.default.green(`\n  ✓ Created .appshield.json with default configuration.\n`));
    console.log(chalk_1.default.gray('  Edit the file to customize ignored paths, default severity, and active rules.'));
    console.log('');
});
// ─── Parse & run ────────────────────────────────────────────────────────────
program.parse();
//# sourceMappingURL=index.js.map