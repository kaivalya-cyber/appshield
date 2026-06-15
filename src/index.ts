#!/usr/bin/env node

import { config } from 'dotenv';
import { resolve, join } from 'path';
import { existsSync } from 'fs';
import { writeFile } from 'fs/promises';
import { Command } from 'commander';
import chalk from 'chalk';
import ora from 'ora';
import { ScanOptions, AppShieldConfig } from './types';
import { scan, writeFixedFiles } from './scanner';
import { reportTerminal, reportJSON, reportHTML, reportRulesTable } from './reporter';

// Load .env from current directory or project root
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
  .option('-o, --output <format>', 'Output format: terminal, json, html', 'terminal')
  .option('-s, --severity <level>', 'Minimum severity: critical, high, medium, low, info', 'medium')
  .option('-r, --rules <rules>', 'Comma-separated list of rules to run (default: all)')
  .option('--ignore <patterns>', 'Comma-separated glob patterns to ignore')
  .option('--fix', 'Write patched files as *.shielded.ext', false)
  .option('--ci', 'CI mode: exit code 1 if vulnerabilities found at or above severity', false)
  .option('--debug', 'Show debug information including raw API responses', false)
  .action(async (targetPath: string, opts: any) => {
    const options: ScanOptions = {
      output: opts.output || 'terminal',
      severity: opts.severity || 'medium',
      rules: opts.rules ? opts.rules.split(',').map((r: string) => r.trim()) : [],
      ignore: opts.ignore ? opts.ignore.split(',').map((p: string) => p.trim()) : [],
      fix: opts.fix || false,
      ci: opts.ci || false,
      debug: opts.debug || false,
    };

    // Validate output format
    if (!['terminal', 'json', 'html'].includes(options.output)) {
      console.error(chalk.red(`❌ Invalid output format: ${options.output}. Use terminal, json, or html.`));
      process.exit(1);
    }

    // Validate severity
    if (!['critical', 'high', 'medium', 'low', 'info'].includes(options.severity)) {
      console.error(chalk.red(`❌ Invalid severity: ${options.severity}. Use critical, high, medium, low, or info.`));
      process.exit(1);
    }

    // Show banner (unless JSON output)
    if (options.output !== 'json') {
      console.log('');
      console.log(chalk.bold.white('  🛡️  AppShield v1.0.0'));
      console.log(chalk.gray('  AI-powered security scanner'));
      console.log('');
    }

    // Start spinner (unless JSON output)
    const spinner = options.output !== 'json'
      ? ora({ text: 'Initializing scan...', color: 'cyan' }).start()
      : null;

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
    };

    await writeFile(configPath, JSON.stringify(defaultConfig, null, 2) + '\n', 'utf-8');
    console.log(chalk.green(`\n  ✓ Created .appshield.json with default configuration.\n`));
    console.log(chalk.gray('  Edit the file to customize ignored paths, default severity, and active rules.'));
    console.log('');
  });

// ─── Parse & run ────────────────────────────────────────────────────────────

program.parse();
