import chalk from 'chalk';
import Table from 'cli-table3';
import { ScanReport, Vulnerability, Severity } from './types';

// ─── Severity styling ───────────────────────────────────────────────────────

const severityColors: Record<Severity, (text: string) => string> = {
  critical: (t) => chalk.red.bold(t),
  high: (t) => chalk.yellow.bold(t),
  medium: (t) => chalk.cyan(t),
  low: (t) => chalk.gray(t),
  info: (t) => chalk.white(t),
};

const severityIcons: Record<Severity, string> = {
  critical: '●',
  high: '▲',
  medium: '◆',
  low: '○',
  info: 'ℹ',
};

// ─── Terminal reporter ──────────────────────────────────────────────────────

export function reportTerminal(report: ScanReport): void {
  const duration = (report.durationMs / 1000).toFixed(1);

  console.log('');
  console.log(chalk.bold.white('  AppShield Security Report'));
  console.log(chalk.gray('  ══════════════════════════════════════════'));
  console.log('');
  console.log(chalk.white(`    Scanned: ${chalk.bold(report.projectPath)}  (${report.totalFiles} files, ${duration}s)`));
  console.log('');

  // Summary line
  const summary = [
    report.criticalCount > 0
      ? severityColors.critical(`${severityIcons.critical} ${report.criticalCount} CRITICAL`)
      : chalk.gray(`${severityIcons.critical} 0 CRITICAL`),
    report.highCount > 0
      ? severityColors.high(`${severityIcons.high} ${report.highCount} HIGH`)
      : chalk.gray(`${severityIcons.high} 0 HIGH`),
    report.mediumCount > 0
      ? severityColors.medium(`${severityIcons.medium} ${report.mediumCount} MEDIUM`)
      : chalk.gray(`${severityIcons.medium} 0 MEDIUM`),
    report.lowCount > 0
      ? severityColors.low(`${severityIcons.low} ${report.lowCount} LOW`)
      : chalk.gray(`${severityIcons.low} 0 LOW`),
  ].join('   ');

  console.log(`    ${summary}`);
  console.log('');

  // Show suppressed count if any
  if (report.suppressedCount && report.suppressedCount > 0) {
    console.log(chalk.gray(`    ${report.suppressedCount} finding(s) suppressed by baseline`));
    if (report.newFindings !== undefined) {
      console.log(chalk.gray(`    ${report.newFindings} new finding(s)`));
    }
    console.log('');
  }

  console.log(chalk.gray('  ══════════════════════════════════════════'));

  if (report.totalVulnerabilities === 0) {
    console.log('');
    console.log(chalk.green.bold('  ✓ No vulnerabilities found! Your code looks clean.'));
    console.log('');
    return;
  }

  // Print each vulnerability
  for (const result of report.results) {
    for (const vuln of result.vulnerabilities) {
      printVulnerability(vuln);
    }
  }

  console.log('');
  console.log(chalk.gray('  ──────────────────────────────────────────'));
  console.log('');
  console.log(chalk.gray('    Run with --output json for machine-readable output.'));
  console.log(chalk.gray('    Run with --fix to write patched files.'));
  console.log('');
}

function printVulnerability(vuln: Vulnerability): void {
  console.log('');
  const severityLabel = severityColors[vuln.severity](`[${vuln.severity.toUpperCase()}]`);
  const location = vuln.line
    ? `${vuln.file}:${vuln.line}`
    : vuln.file;

  console.log(`    ${severityLabel} ${chalk.bold.white(vuln.title)} — ${chalk.gray(location)}`);

  // CWE/OWASP reference
  const refs: string[] = [];
  if (vuln.cwe) refs.push(vuln.cwe);
  if (vuln.owasp) refs.push(`OWASP ${vuln.owasp}`);
  if (refs.length > 0) {
    console.log(`    ${chalk.gray(refs.join(' · '))}`);
  }

  console.log('');
  // Description with wrapping
  const descLines = wrapText(vuln.description, 60);
  for (const line of descLines) {
    console.log(`    ${chalk.white(line)}`);
  }

  // Vulnerable code
  console.log('');
  console.log(chalk.gray('    Vulnerable:'));
  console.log(chalk.gray('    ┌─────────────────────────────────────────────────────────┐'));
  const snippetLines = vuln.snippet.split('\n');
  for (const line of snippetLines) {
    console.log(`    ${chalk.gray('│')}  ${chalk.red(line)}`);
  }
  console.log(chalk.gray('    └─────────────────────────────────────────────────────────┘'));

  // Fixed code
  console.log('');
  console.log(chalk.gray('    Fixed:'));
  console.log(chalk.gray('    ┌─────────────────────────────────────────────────────────┐'));
  const fixLines = vuln.fix.split('\n');
  for (const line of fixLines) {
    console.log(`    ${chalk.gray('│')}  ${chalk.green(line)}`);
  }
  console.log(chalk.gray('    └─────────────────────────────────────────────────────────┘'));

  console.log('');
  console.log(chalk.gray('  ──────────────────────────────────────────'));
}

function wrapText(text: string, maxWidth: number): string[] {
  const words = text.split(' ');
  const lines: string[] = [];
  let currentLine = '';

  for (const word of words) {
    if ((currentLine + ' ' + word).trim().length > maxWidth) {
      if (currentLine) lines.push(currentLine.trim());
      currentLine = word;
    } else {
      currentLine = currentLine ? currentLine + ' ' + word : word;
    }
  }
  if (currentLine) lines.push(currentLine.trim());
  return lines;
}

// ─── JSON reporter ──────────────────────────────────────────────────────────

export function reportJSON(report: ScanReport): string {
  return JSON.stringify(report, null, 2);
}

// ─── SARIF reporter (GitHub Code Scanning) ─────────────────────────────────

export function reportSARIF(report: ScanReport): string {
  const rulesMap = new Map<string, any>();

  // Collect unique rules
  const uniqueRules: any[] = [];
  for (const result of report.results) {
    for (const vuln of result.vulnerabilities) {
      if (!rulesMap.has(vuln.rule)) {
        const rule = {
          id: vuln.rule,
          shortDescription: { text: vuln.title },
          fullDescription: { text: vuln.description },
          defaultConfiguration: { level: severityToSarifLevel(vuln.severity) },
          properties: {
            tags: ['security', vuln.severity],
            ...(vuln.cwe ? { cwe: vuln.cwe } : {}),
            ...(vuln.owasp ? { owasp: vuln.owasp } : {}),
          },
        };
        uniqueRules.push(rule);
        rulesMap.set(vuln.rule, true);
      }
    }
  }

  // Collect artifacts
  const artifactsMap = new Map<string, number>();
  for (const result of report.results) {
    if (!artifactsMap.has(result.file)) {
      artifactsMap.set(result.file, artifactsMap.size);
    }
  }

  const artifacts = Array.from(artifactsMap.keys()).map(uri => ({
    location: { uri },
  }));

  // Build results
  const sarifResults = report.results.flatMap(result =>
    result.vulnerabilities.map(vuln => ({
      ruleId: vuln.rule,
      level: severityToSarifLevel(vuln.severity),
      message: {
        text: `${vuln.title}\n\n${vuln.description}\n\nFix: ${vuln.fix}`,
      },
      locations: [
        {
          physicalLocation: {
            artifactLocation: { uri: result.file },
            ...(vuln.line ? { region: { startLine: vuln.line } } : {}),
          },
        },
      ],
    }))
  );

  const sarifReport = {
    $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
    version: '2.1.0',
    runs: [
      {
        tool: {
          driver: {
            name: 'AppShield',
            version: '1.0.0',
            informationUri: 'https://github.com/yourusername/appshield',
            rules: uniqueRules,
          },
        },
        artifacts,
        results: sarifResults,
      },
    ],
  };

  return JSON.stringify(sarifReport, null, 2);
}

function severityToSarifLevel(severity: Severity): string {
  switch (severity) {
    case 'critical':
    case 'high':
      return 'error';
    case 'medium':
      return 'warning';
    case 'low':
      return 'note';
    case 'info':
      return 'none';
  }
}

// ─── Markdown reporter ──────────────────────────────────────────────────────

export function reportMarkdown(report: ScanReport): string {
  const duration = (report.durationMs / 1000).toFixed(1);
  let md = '';

  md += `# 🛡️ AppShield Security Report\n\n`;
  md += `**Project:** \`${escapeText(report.projectPath)}\`  \n`;
  md += `**Files scanned:** ${report.totalFiles}  \n`;
  md += `**Duration:** ${duration}s  \n`;
  md += `**Generated:** ${new Date().toISOString()}\n\n`;

  // Summary table
  md += `| Severity | Count |\n`;
  md += `|----------|-------|\n`;
  md += `| 🔴 Critical | ${report.criticalCount} |\n`;
  md += `| 🟡 High     | ${report.highCount} |\n`;
  md += `| 🔵 Medium   | ${report.mediumCount} |\n`;
  md += `| ⚪ Low      | ${report.lowCount} |\n`;
  md += `| **Total**   | **${report.totalVulnerabilities}** |\n`;

  if (report.suppressedCount && report.suppressedCount > 0) {
    md += `\n> ℹ️ ${report.suppressedCount} finding(s) suppressed by baseline\n`;
  }

  md += `\n---\n\n`;

  if (report.totalVulnerabilities === 0) {
    md += `✅ **No vulnerabilities found!** Your code looks clean.\n`;
    return md;
  }

  // Group by severity for table of contents
  md += `## Findings by Severity\n\n`;

  for (const result of report.results) {
    for (const vuln of result.vulnerabilities) {
      md += `### ${severityEmoji(vuln.severity)} ${vuln.severity.toUpperCase()}: ${escapeText(vuln.title)}\n\n`;
      md += `- **File:** \`${escapeText(result.file)}\``;
      if (vuln.line) md += ` (line ${vuln.line})`;
      md += `\n`;
      if (vuln.cwe) md += `- **CWE:** ${escapeText(vuln.cwe)}\n`;
      if (vuln.owasp) md += `- **OWASP:** ${escapeText(vuln.owasp)}\n`;
      md += `\n${escapeText(vuln.description)}\n\n`;

      md += `<details>\n<summary>🔍 Vulnerable Code</summary>\n\n`;
      md += `~~~\n${mdSanitizeFences(vuln.snippet)}\n~~~\n\n`;
      md += `</details>\n\n`;

      md += `<details>\n<summary>✅ Fixed Code</summary>\n\n`;
      md += `~~~\n${mdSanitizeFences(vuln.fix)}\n~~~\n\n`;
      md += `</details>\n\n`;

      md += `---\n\n`;
    }
  }

  return md;
}

function severityEmoji(severity: Severity): string {
  switch (severity) {
    case 'critical': return '🔴';
    case 'high': return '🟡';
    case 'medium': return '🔵';
    case 'low': return '⚪';
    case 'info': return 'ℹ️';
  }
}

// ─── CSV reporter ───────────────────────────────────────────────────────────

export function reportCSV(report: ScanReport): string {
  const headers = [
    'ID', 'Rule', 'Severity', 'Title', 'Description',
    'File', 'Line', 'CWE', 'OWASP', 'Snippet', 'Fix',
  ];
  const rows: string[][] = [];

  for (const result of report.results) {
    for (const vuln of result.vulnerabilities) {
      rows.push([
        vuln.id,
        vuln.rule,
        vuln.severity,
        csvEscape(vuln.title),
        csvEscape(vuln.description),
        result.file,
        vuln.line?.toString() || '',
        vuln.cwe || '',
        vuln.owasp || '',
        csvEscape(vuln.snippet),
        csvEscape(vuln.fix),
      ]);
    }
  }

  // CSV header row + summary row
  const headerRow = headers.join(',');
  const dataRows = rows.map(row => row.map(cell => `"${cell}"`).join(','));

  let csv = `# AppShield Security Report\n`;
  csv += `# Project: ${csvEscape(report.projectPath)}\n`;
  csv += `# Files scanned: ${report.totalFiles}\n`;
  csv += `# Duration: ${(report.durationMs / 1000).toFixed(1)}s\n`;
  csv += `# Critical: ${report.criticalCount}, High: ${report.highCount}, Medium: ${report.mediumCount}, Low: ${report.lowCount}\n`;
  if (report.suppressedCount && report.suppressedCount > 0) {
    csv += `# Suppressed by baseline: ${report.suppressedCount}\n`;
  }
  csv += `${headerRow}\n`;
  csv += dataRows.join('\n');
  csv += '\n';

  return csv;
}

function csvEscape(text: string): string {
  return text.replace(/"/g, '""').replace(/\n/g, ' ');
}

// ─── JUnit XML reporter (CI integration) ────────────────────────────────────

export function reportJUnit(report: ScanReport): string {
  const duration = (report.durationMs / 1000).toFixed(3);

  let failures = 0;
  let errors = 0;

  const testCases: string[] = [];

  for (const result of report.results) {
    for (const vuln of result.vulnerabilities) {
      const tcName = `${vuln.rule}.${vuln.id}`;
      const className = result.file;
      const severity = vuln.severity;

      if (severity === 'critical' || severity === 'high') {
        failures++;
        testCases.push(
          `    <testcase name="${escapeXml(tcName)}" classname="${escapeXml(className)}" time="0.0">\n` +
          `      <failure message="${escapeXml(vuln.title)}" type="${escapeXml(severity)}">\n` +
          `${escapeXml(vuln.description)}\n` +
          `File: ${escapeXml(vuln.line ? `${result.file}:${vuln.line}` : result.file)}\n` +
          `Fix: ${escapeXml(vuln.fix)}\n` +
          `      </failure>\n` +
          `    </testcase>`
        );
      } else if (severity === 'medium') {
        errors++;
        testCases.push(
          `    <testcase name="${escapeXml(tcName)}" classname="${escapeXml(className)}" time="0.0">\n` +
          `      <error message="${escapeXml(vuln.title)}" type="${escapeXml(severity)}">\n` +
          `${escapeXml(vuln.description)}\n` +
          `File: ${escapeXml(vuln.line ? `${result.file}:${vuln.line}` : result.file)}\n` +
          `Fix: ${escapeXml(vuln.fix)}\n` +
          `      </error>\n` +
          `    </testcase>`
        );
      } else {
        testCases.push(
          `    <testcase name="${escapeXml(tcName)}" classname="${escapeXml(className)}" time="0.0" />`
        );
      }
    }
  }

  // If no findings, create a single passing testcase
  if (testCases.length === 0) {
    testCases.push(
      `    <testcase name="appshield.scan" classname="${escapeXml(report.projectPath)}" time="${duration}" />`
    );
  }

  const xml = [
    `<?xml version="1.0" encoding="UTF-8"?>`,
    `<testsuite name="AppShield Security Scan" tests="${Math.max(testCases.length, 1)}" failures="${failures}" errors="${errors}" time="${duration}" timestamp="${new Date().toISOString()}">`,
    ...testCases,
    `</testsuite>`,
  ];

  return xml.join('\n') + '\n';
}

// ─── HTML reporter ──────────────────────────────────────────────────────────

export function reportHTML(report: ScanReport): string {
  const duration = (report.durationMs / 1000).toFixed(1);

  const severityBadgeColors: Record<Severity, string> = {
    critical: '#ef4444',
    high: '#f59e0b',
    medium: '#06b6d4',
    low: '#6b7280',
    info: '#8b5cf6',
  };

  const vulnSections = report.results
    .map(result => {
      const vulnCards = result.vulnerabilities
        .map((vuln) => {
          const refs: string[] = [];
          if (vuln.cwe) refs.push(vuln.cwe);
          if (vuln.owasp) refs.push(`OWASP ${vuln.owasp}`);

          return `
          <div class="vuln-card">
            <div class="vuln-header">
              <span class="badge" style="background:${severityBadgeColors[vuln.severity]}">${vuln.severity.toUpperCase()}</span>
              <span class="vuln-title">${escapeHtml(vuln.title)}</span>
              <span class="vuln-location">${escapeHtml(vuln.line ? `${vuln.file}:${vuln.line}` : vuln.file)}</span>
            </div>
            ${refs.length > 0 ? `<div class="vuln-refs">${refs.join(' · ')}</div>` : ''}
            <p class="vuln-desc">${escapeHtml(vuln.description)}</p>
            <div class="code-section">
              <div class="code-label vulnerable-label">Vulnerable</div>
              <pre class="code-block vulnerable"><code>${escapeHtml(vuln.snippet)}</code></pre>
            </div>
            <div class="code-section">
              <div class="code-label fixed-label">Fixed</div>
              <pre class="code-block fixed"><code>${escapeHtml(vuln.fix)}</code></pre>
            </div>
          </div>`;
        })
        .join('');

      return `
        <details class="file-section" open>
          <summary class="file-header">
            <span class="file-name">${escapeHtml(result.file)}</span>
            <span class="file-count">${result.vulnerabilities.length} finding${result.vulnerabilities.length !== 1 ? 's' : ''}</span>
          </summary>
          <div class="file-body">
            ${vulnCards}
          </div>
        </details>`;
    })
    .join('');

  const suppressedNote = report.suppressedCount && report.suppressedCount > 0
    ? `<p class="suppressed-note">ℹ️ ${report.suppressedCount} finding(s) suppressed by baseline</p>`
    : '';

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>AppShield Security Report</title>
  <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.9.0/styles/github-dark.min.css">
  <script src="https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.9.0/highlight.min.js"></script>
  <style>
    :root {
      --bg: #0f172a;
      --surface: #1e293b;
      --surface-2: #334155;
      --text: #e2e8f0;
      --text-muted: #94a3b8;
      --border: #475569;
      --critical: #ef4444;
      --high: #f59e0b;
      --medium: #06b6d4;
      --low: #6b7280;
      --green: #22c55e;
      --red: #ef4444;
    }
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body {
      font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
      background: var(--bg);
      color: var(--text);
      line-height: 1.6;
      padding: 2rem;
    }
    .container { max-width: 960px; margin: 0 auto; }
    h1 {
      font-size: 1.75rem;
      font-weight: 700;
      margin-bottom: 0.5rem;
    }
    .subtitle { color: var(--text-muted); margin-bottom: 2rem; }
    .suppressed-note { color: var(--text-muted); font-size: 0.85rem; margin-bottom: 1rem; }
    .summary-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
      gap: 1rem;
      margin-bottom: 2rem;
    }
    .summary-card {
      background: var(--surface);
      border-radius: 12px;
      padding: 1.25rem;
      text-align: center;
      border: 1px solid var(--border);
    }
    .summary-card .count {
      font-size: 2rem;
      font-weight: 700;
      display: block;
    }
    .summary-card .label {
      font-size: 0.75rem;
      text-transform: uppercase;
      letter-spacing: 0.05em;
      color: var(--text-muted);
    }
    .file-section {
      margin-bottom: 1rem;
      border: 1px solid var(--border);
      border-radius: 8px;
      overflow: hidden;
    }
    .file-header {
      background: var(--surface);
      padding: 0.75rem 1rem;
      cursor: pointer;
      display: flex;
      justify-content: space-between;
      align-items: center;
      font-weight: 600;
    }
    .file-header:hover { background: var(--surface-2); }
    .file-count {
      font-size: 0.8rem;
      color: var(--text-muted);
      font-weight: 400;
    }
    .file-body { padding: 1rem; }
    .vuln-card {
      background: var(--surface);
      border-radius: 8px;
      padding: 1.25rem;
      margin-bottom: 1rem;
      border-left: 4px solid var(--border);
    }
    .vuln-header {
      display: flex;
      align-items: center;
      gap: 0.75rem;
      flex-wrap: wrap;
      margin-bottom: 0.5rem;
    }
    .badge {
      display: inline-block;
      padding: 0.15rem 0.5rem;
      border-radius: 4px;
      font-size: 0.7rem;
      font-weight: 700;
      color: white;
      text-transform: uppercase;
      letter-spacing: 0.03em;
    }
    .vuln-title { font-weight: 600; }
    .vuln-location { color: var(--text-muted); font-size: 0.85rem; margin-left: auto; }
    .vuln-refs { color: var(--text-muted); font-size: 0.8rem; margin-bottom: 0.5rem; }
    .vuln-desc { color: var(--text-muted); font-size: 0.9rem; margin-bottom: 1rem; }
    .code-section { margin-bottom: 0.75rem; }
    .code-label {
      font-size: 0.7rem;
      text-transform: uppercase;
      letter-spacing: 0.05em;
      font-weight: 600;
      margin-bottom: 0.25rem;
    }
    .vulnerable-label { color: var(--red); }
    .fixed-label { color: var(--green); }
    .code-block {
      background: #0d1117;
      border-radius: 6px;
      padding: 1rem;
      overflow-x: auto;
      font-size: 0.85rem;
      line-height: 1.5;
    }
    .code-block.vulnerable { border-left: 3px solid var(--red); }
    .code-block.fixed { border-left: 3px solid var(--green); }
    code { font-family: 'Fira Code', 'Cascadia Code', Consolas, monospace; }
    .footer {
      text-align: center;
      margin-top: 3rem;
      color: var(--text-muted);
      font-size: 0.8rem;
    }
  </style>
</head>
<body>
  <div class="container">
    <h1>🛡️ AppShield Security Report</h1>
    <p class="subtitle">Scanned ${escapeHtml(report.projectPath)} · ${report.totalFiles} files · ${duration}s</p>

    <div class="summary-grid">
      <div class="summary-card">
        <span class="count" style="color:var(--critical)">${report.criticalCount}</span>
        <span class="label">Critical</span>
      </div>
      <div class="summary-card">
        <span class="count" style="color:var(--high)">${report.highCount}</span>
        <span class="label">High</span>
      </div>
      <div class="summary-card">
        <span class="count" style="color:var(--medium)">${report.mediumCount}</span>
        <span class="label">Medium</span>
      </div>
      <div class="summary-card">
        <span class="count" style="color:${report.lowCount > 0 ? 'var(--low)' : 'var(--text-muted)'}">${report.lowCount}</span>
        <span class="label">Low</span>
      </div>
      <div class="summary-card">
        <span class="count" style="color:var(--text)">${report.totalVulnerabilities}</span>
        <span class="label">Total</span>
      </div>
    </div>

    ${suppressedNote}

    ${report.totalVulnerabilities === 0 ? '<p style="text-align:center;font-size:1.25rem;color:var(--green);margin:2rem 0">✓ No vulnerabilities found! Your code looks clean.</p>' : vulnSections}

    <div class="footer">
      Generated by AppShield · ${new Date().toISOString()}
    </div>
  </div>
  <script>hljs.highlightAll();</script>
</body>
</html>`;
}

function escapeHtml(text: string): string {
  return text
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

function escapeText(text: string): string {
  return text
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;');
}

/** Replace ~~~ fences with '~~~' to avoid breaking markdown code blocks */
function mdSanitizeFences(text: string): string {
  return text.replace(/~~~/g, "'~~~'");
}

function escapeXml(text: string): string {
  return text
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&apos;');
}

// ─── Rules table ────────────────────────────────────────────────────────────

import { allRules } from './rules';

export function reportRulesTable(): void {
  const table = new Table({
    head: [
      chalk.white.bold('ID'),
      chalk.white.bold('Name'),
      chalk.white.bold('Severity'),
      chalk.white.bold('CWE'),
      chalk.white.bold('OWASP'),
      chalk.white.bold('Description'),
    ],
    colWidths: [16, 28, 12, 10, 12, 40],
    wordWrap: true,
    style: { head: [], border: ['gray'] },
  });

  for (const rule of allRules) {
    const severityStr = severityColors[rule.severity](rule.severity.toUpperCase());
    table.push([
      rule.id,
      rule.name,
      severityStr,
      rule.cwe || '—',
      rule.owasp || '—',
      rule.description.substring(0, 100) + (rule.description.length > 100 ? '...' : ''),
    ]);
  }

  console.log('');
  console.log(chalk.bold.white('  AppShield Rules'));
  console.log('');
  console.log(table.toString());
  console.log('');
}
