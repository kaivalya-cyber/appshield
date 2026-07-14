#!/usr/bin/env node

import { config } from 'dotenv';
import { resolve, join, extname, basename } from 'path';
import { existsSync, statSync } from 'fs';
import { writeFile, readFile } from 'fs/promises';
import { createHash } from 'crypto';
import { Command } from 'commander';
import chalk from 'chalk';
import ora from 'ora';
import { ScanOptions, AppShieldConfig } from './types';
import { scan, writeFixedFiles } from './scanner';
import { resolvePreset } from './rules';
import chokidar from 'chokidar';
import {
  reportTerminal,
  reportJSON,
  reportHTML,
  reportSARIF,
  reportMarkdown,
  reportCSV,
  reportJUnit,
  reportRulesTable,
} from './reporter';

// ─── Valid output formats ──────────────────────────────────────────────────

const VALID_OUTPUTS = ['terminal', 'json', 'html', 'sarif', 'markdown', 'csv', 'junit'] as const;
const VALID_SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'] as const;

// ─── Load .env ─────────────────────────────────────────────────────────────

const envPath = existsSync(join(process.cwd(), '.env'))
  ? join(process.cwd(), '.env')
  : join(__dirname, '..', '.env');
config({ path: envPath });

const program = new Command();

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
  .action(async (targetPath: string, opts: any) => {
    // ─── Load .appshield.json config ──────────────────────────────────────
    let config: Partial<AppShieldConfig> = {};
    try {
      const targetAbs = resolve(targetPath);
      const isDir = existsSync(targetAbs) && statSync(targetAbs).isDirectory();

      const targetConfigPath = join(targetAbs, '.appshield.json');
      const fallbackConfigPath = join(process.cwd(), '.appshield.json');

      const finalConfigPath = (isDir && existsSync(targetConfigPath))
        ? targetConfigPath
        : (existsSync(fallbackConfigPath) ? fallbackConfigPath : null);

      if (finalConfigPath) {
        const fileContent = await readFile(finalConfigPath, 'utf-8');
        config = JSON.parse(fileContent);
      }
    } catch {
      // Malformed or missing config — fall through to defaults
    }

    // Parse CLI arrays
    const cliRules = opts.rules ? opts.rules.split(',').map((r: string) => r.trim()) : undefined;
    const cliIgnore = opts.ignore ? opts.ignore.split(',').map((p: string) => p.trim()) : [];
    const cliExt = opts.ext ? opts.ext.split(',').map((e: string) => {
      e = e.trim().toLowerCase();
      return e.startsWith('.') ? e : '.' + e;
    }) : [];

    // Resolve preset if provided (adds to any explicit --rules)
    const presetRules: string[] = [];
    if (opts.preset) {
      const resolved = resolvePreset(opts.preset);
      if (!resolved) {
        console.error(chalk.red(`❌ Unknown preset: ${opts.preset}. Use: owasp-top10, critical-only, web-app`));
        process.exit(1);
      }
      presetRules.push(...resolved);
    }

    // Build ScanOptions (CLI overrides config, config overrides defaults)
    const options: ScanOptions = {
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
      console.error(chalk.red(`❌ Invalid output format: ${options.output}. Use: ${VALID_OUTPUTS.join(', ')}`));
      process.exit(1);
    }

    // Validate severity
    if (!VALID_SEVERITIES.includes(options.severity)) {
      console.error(chalk.red(`❌ Invalid severity: ${options.severity}. Use: ${VALID_SEVERITIES.join(', ')}`));
      process.exit(1);
    }

    // Validate concurrency
    if (options.concurrency < 1 || options.concurrency > 10) {
      console.error(chalk.red('❌ Concurrency must be between 1 and 10.'));
      process.exit(1);
    }

    // Show banner (unless JSON/SARIF/CSV/JUnit output or quiet mode)
    const isMachineOutput = ['json', 'sarif', 'csv', 'junit'].includes(options.output);
    if (!isMachineOutput && !options.quiet) {
      console.log('');
      console.log(chalk.bold.white('  🛡️  AppShield v1.0.0'));
      console.log(chalk.gray('  AI-powered security scanner'));
      console.log('');
    }

    // Show incremental/baseline info
    if (!isMachineOutput && !options.quiet) {
      if (options.incremental) {
        console.log(chalk.gray('  ⚡ Incremental scan mode — only changed files will be analyzed'));
      }
      if (options.baseline) {
        console.log(chalk.gray(`  📋 Using baseline: ${options.baseline}`));
      }
    }

    // Start spinner (unless machine output or quiet mode)
    const spinner = isMachineOutput || options.quiet
      ? null
      : ora({ text: 'Initializing scan...', color: 'cyan' }).start();

    try {
      const report = await scan(targetPath, options, (message) => {
        if (spinner) {
          spinner.text = message;
        }
      });

      spinner?.stop();

      // Output the report
      switch (options.output) {
        case 'terminal':
          reportTerminal(report);
          break;

        case 'json':
          console.log(reportJSON(report));
          break;

        case 'sarif':
          console.log(reportSARIF(report));
          break;

        case 'markdown': {
          const mdContent = reportMarkdown(report);
          const outputPath = resolve('appshield-report.md');
          await writeFile(outputPath, mdContent, 'utf-8');
          console.log(chalk.green(`\n  ✓ Markdown report written to ${outputPath}\n`));
          break;
        }

        case 'csv':
          console.log(reportCSV(report));
          break;

        case 'junit':
          console.log(reportJUnit(report));
          break;

        case 'html': {
          const htmlContent = reportHTML(report);
          const outputPath = resolve('appshield-report.html');
          await writeFile(outputPath, htmlContent, 'utf-8');
          console.log(chalk.green(`\n  ✓ HTML report written to ${outputPath}\n`));
          break;
        }
      }

      // Write fixed files if --fix flag is set
      if (options.fix && report.totalVulnerabilities > 0) {
        const basePath = resolve(targetPath);
        const writtenFiles = await writeFixedFiles(report, basePath);
        if (writtenFiles.length > 0) {
          console.log(chalk.green.bold(`\n  ✓ Patched ${writtenFiles.length} file(s):`));
          for (const f of writtenFiles) {
            console.log(chalk.green(`    → ${f}`));
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
        const targetAbs = resolve(targetPath);
        const isDir = statSync(targetAbs).isDirectory();
        const targetBasename = isDir ? null : basename(targetAbs);
        const watchDir = isDir ? targetAbs : resolve(targetAbs, '..');

        console.log(chalk.gray(`\n  👀 Watching for changes in ${watchDir}...`));
        console.log(chalk.gray('  Press Ctrl+C to stop.\n'));

        // Debounce: wait 2s after last change before re-scanning
        let debounceTimer: ReturnType<typeof setTimeout> | null = null;
        let scanning = false;

        const watcher = chokidar.watch(watchDir, {
          ignored: /(^|[/\\])\./,
          persistent: true,
          ignoreInitial: true,
        });

        const handleChange = (filename: string) => {

          // Filter by extension
          const ext = extname(filename).toLowerCase();
          if (options.extensions.length > 0 && !options.extensions.includes(ext)) return;

          // For single-file watch, ignore changes to other files
          if (!isDir && basename(filename) !== targetBasename) return;

          // Reset debounce timer
          if (debounceTimer) clearTimeout(debounceTimer);

          debounceTimer = setTimeout(async () => {
            if (scanning) return;
            scanning = true;

            console.log(chalk.cyan(`\n  🔄 Change detected: ${filename}`));
            console.log(chalk.gray('  Re-scanning...\n'));

            try {
              const newReport = await scan(targetPath, options, (msg) => {
                if (!options.quiet) console.log(chalk.gray(`  ${msg}`));
              });

              if (newReport.totalVulnerabilities > 0) {
                console.log(chalk.red.bold(`  ⚠ ${newReport.totalVulnerabilities} finding(s) after re-scan`));
              } else {
                console.log(chalk.green.bold('  ✓ No findings'));
              }
            } catch (err: any) {
              console.error(chalk.red(`  ❌ Scan error: ${err.message}`));
            } finally {
              scanning = false;
            }
          }, 2000); // 2-second debounce
        };

        watcher.on('change', handleChange);
        watcher.on('add', handleChange);

        // Keep process alive
        await new Promise(() => {});
      }

    } catch (error: any) {
      spinner?.fail('Scan failed');
      console.error(chalk.red(`\n  ❌ ${error.message}\n`));
      if (options.debug && error.stack) {
        console.error(chalk.gray(error.stack));
      }
      process.exit(1);
    }
  });

// ─── rules command ──────────────────────────────────────────────────────────

program
  .command('rules')
  .description('List all available security rules')
  .action(() => {
    reportRulesTable();
  });

// ─── init command ───────────────────────────────────────────────────────────

program
  .command('init')
  .description('Create a .appshield.json config file with defaults')
  .action(async () => {
    const configPath = resolve('.appshield.json');
    if (existsSync(configPath)) {
      console.log(chalk.yellow(`\n  ⚠ .appshield.json already exists. Delete it first to reinitialize.\n`));
      return;
    }

    const defaultConfig: AppShieldConfig = {
      ignore: ['node_modules', 'dist', 'build', '*.test.ts', '*.test.js', '*.spec.ts', '*.spec.js'],
      severity: 'medium',
      rules: [],  // empty = all rules
      output: 'terminal',
      concurrency: 3,
      baseline: undefined,
    };

    await writeFile(configPath, JSON.stringify(defaultConfig, null, 2) + '\n', 'utf-8');
    console.log(chalk.green(`\n  ✓ Created .appshield.json with default configuration.\n`));
    console.log(chalk.gray('  Edit the file to customize ignored paths, default severity, and active rules.'));
    console.log(chalk.gray('  Supported options: ignore, severity, rules, output, concurrency, baseline'));
    console.log('');
  });

// ─── baseline command ────────────────────────────────────────────────────────

program
  .command('baseline')
  .description('Create or update a .appshield-baseline.json from a scan report')
  .argument('<report>', 'Path to JSON scan report to generate baseline from')
  .option('-o, --output <path>', 'Output path for baseline file', '.appshield-baseline.json')
  .action(async (reportPath: string, opts: any) => {
    try {
      const reportContent = await readFile(resolve(reportPath), 'utf-8');
      const report = JSON.parse(reportContent);

      if (!report.results || !Array.isArray(report.results)) {
        console.error(chalk.red('❌ Invalid report file: missing "results" array.'));
        process.exit(1);
      }

      const entries: any[] = [];
      for (const result of report.results) {
        for (const vuln of result.vulnerabilities) {
          const snippetHash = createHash('sha256').update(vuln.snippet.trim()).digest('hex');
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

      const outputPath = resolve(opts.output || '.appshield-baseline.json');
      await writeFile(outputPath, JSON.stringify(baseline, null, 2) + '\n', 'utf-8');

      console.log(chalk.green(`\n  ✓ Baseline created with ${entries.length} entries at ${outputPath}\n`));
      console.log(chalk.gray('  Run scans with --baseline to suppress these findings.'));
      console.log(chalk.gray('  Edit the file to add reasons for each suppression.'));
      console.log('');
    } catch (error: any) {
      console.error(chalk.red(`\n  ❌ Failed to create baseline: ${error.message}\n`));
      process.exit(1);
    }
  });

// ─── Parse & run ────────────────────────────────────────────────────────────

program.parse();
