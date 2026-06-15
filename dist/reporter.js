"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.reportTerminal = reportTerminal;
exports.reportJSON = reportJSON;
exports.reportHTML = reportHTML;
exports.reportRulesTable = reportRulesTable;
const chalk_1 = __importDefault(require("chalk"));
const cli_table3_1 = __importDefault(require("cli-table3"));
// ─── Severity styling ───────────────────────────────────────────────────────
const severityColors = {
    critical: (t) => chalk_1.default.red.bold(t),
    high: (t) => chalk_1.default.yellow.bold(t),
    medium: (t) => chalk_1.default.cyan(t),
    low: (t) => chalk_1.default.gray(t),
    info: (t) => chalk_1.default.white(t),
};
const severityIcons = {
    critical: '●',
    high: '▲',
    medium: '◆',
    low: '○',
    info: 'ℹ',
};
// ─── Terminal reporter ──────────────────────────────────────────────────────
function reportTerminal(report) {
    const duration = (report.durationMs / 1000).toFixed(1);
    console.log('');
    console.log(chalk_1.default.bold.white('  AppShield Security Report'));
    console.log(chalk_1.default.gray('  ══════════════════════════════════════════'));
    console.log('');
    console.log(chalk_1.default.white(`    Scanned: ${chalk_1.default.bold(report.projectPath)}  (${report.totalFiles} files, ${duration}s)`));
    console.log('');
    // Summary line
    const summary = [
        report.criticalCount > 0
            ? severityColors.critical(`${severityIcons.critical} ${report.criticalCount} CRITICAL`)
            : chalk_1.default.gray(`${severityIcons.critical} 0 CRITICAL`),
        report.highCount > 0
            ? severityColors.high(`${severityIcons.high} ${report.highCount} HIGH`)
            : chalk_1.default.gray(`${severityIcons.high} 0 HIGH`),
        report.mediumCount > 0
            ? severityColors.medium(`${severityIcons.medium} ${report.mediumCount} MEDIUM`)
            : chalk_1.default.gray(`${severityIcons.medium} 0 MEDIUM`),
        report.lowCount > 0
            ? severityColors.low(`${severityIcons.low} ${report.lowCount} LOW`)
            : chalk_1.default.gray(`${severityIcons.low} 0 LOW`),
    ].join('   ');
    console.log(`    ${summary}`);
    console.log('');
    console.log(chalk_1.default.gray('  ══════════════════════════════════════════'));
    if (report.totalVulnerabilities === 0) {
        console.log('');
        console.log(chalk_1.default.green.bold('  ✓ No vulnerabilities found! Your code looks clean.'));
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
    console.log(chalk_1.default.gray('  ──────────────────────────────────────────'));
    console.log('');
    console.log(chalk_1.default.gray('    Run with --output json for machine-readable output.'));
    console.log(chalk_1.default.gray('    Run with --fix to write patched files.'));
    console.log('');
}
function printVulnerability(vuln) {
    console.log('');
    const severityLabel = severityColors[vuln.severity](`[${vuln.severity.toUpperCase()}]`);
    const location = vuln.line
        ? `${vuln.file}:${vuln.line}`
        : vuln.file;
    console.log(`    ${severityLabel} ${chalk_1.default.bold.white(vuln.title)} — ${chalk_1.default.gray(location)}`);
    // CWE/OWASP reference
    const refs = [];
    if (vuln.cwe)
        refs.push(vuln.cwe);
    if (vuln.owasp)
        refs.push(`OWASP ${vuln.owasp}`);
    if (refs.length > 0) {
        console.log(`    ${chalk_1.default.gray(refs.join(' · '))}`);
    }
    console.log('');
    // Description with wrapping
    const descLines = wrapText(vuln.description, 60);
    for (const line of descLines) {
        console.log(`    ${chalk_1.default.white(line)}`);
    }
    // Vulnerable code
    console.log('');
    console.log(chalk_1.default.gray('    Vulnerable:'));
    console.log(chalk_1.default.gray('    ┌─────────────────────────────────────────────────────────┐'));
    const snippetLines = vuln.snippet.split('\n');
    for (const line of snippetLines) {
        console.log(`    ${chalk_1.default.gray('│')}  ${chalk_1.default.red(line)}`);
    }
    console.log(chalk_1.default.gray('    └─────────────────────────────────────────────────────────┘'));
    // Fixed code
    console.log('');
    console.log(chalk_1.default.gray('    Fixed:'));
    console.log(chalk_1.default.gray('    ┌─────────────────────────────────────────────────────────┐'));
    const fixLines = vuln.fix.split('\n');
    for (const line of fixLines) {
        console.log(`    ${chalk_1.default.gray('│')}  ${chalk_1.default.green(line)}`);
    }
    console.log(chalk_1.default.gray('    └─────────────────────────────────────────────────────────┘'));
    console.log('');
    console.log(chalk_1.default.gray('  ──────────────────────────────────────────'));
}
function wrapText(text, maxWidth) {
    const words = text.split(' ');
    const lines = [];
    let currentLine = '';
    for (const word of words) {
        if ((currentLine + ' ' + word).trim().length > maxWidth) {
            if (currentLine)
                lines.push(currentLine.trim());
            currentLine = word;
        }
        else {
            currentLine = currentLine ? currentLine + ' ' + word : word;
        }
    }
    if (currentLine)
        lines.push(currentLine.trim());
    return lines;
}
// ─── JSON reporter ──────────────────────────────────────────────────────────
function reportJSON(report) {
    return JSON.stringify(report, null, 2);
}
// ─── HTML reporter ──────────────────────────────────────────────────────────
function reportHTML(report) {
    const duration = (report.durationMs / 1000).toFixed(1);
    const severityBadgeColors = {
        critical: '#ef4444',
        high: '#f59e0b',
        medium: '#06b6d4',
        low: '#6b7280',
        info: '#8b5cf6',
    };
    const vulnSections = report.results
        .map(result => {
        const vulnCards = result.vulnerabilities
            .map((vuln, i) => {
            const refs = [];
            if (vuln.cwe)
                refs.push(vuln.cwe);
            if (vuln.owasp)
                refs.push(`OWASP ${vuln.owasp}`);
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

    ${report.totalVulnerabilities === 0 ? '<p style="text-align:center;font-size:1.25rem;color:var(--green);margin:2rem 0">✓ No vulnerabilities found! Your code looks clean.</p>' : vulnSections}

    <div class="footer">
      Generated by AppShield · ${new Date().toISOString()}
    </div>
  </div>
  <script>hljs.highlightAll();</script>
</body>
</html>`;
}
function escapeHtml(text) {
    return text
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#039;');
}
// ─── Rules table ────────────────────────────────────────────────────────────
const rules_1 = require("./rules");
function reportRulesTable() {
    const table = new cli_table3_1.default({
        head: [
            chalk_1.default.white.bold('ID'),
            chalk_1.default.white.bold('Name'),
            chalk_1.default.white.bold('Severity'),
            chalk_1.default.white.bold('CWE'),
            chalk_1.default.white.bold('OWASP'),
            chalk_1.default.white.bold('Description'),
        ],
        colWidths: [16, 28, 12, 10, 12, 40],
        wordWrap: true,
        style: { head: [], border: ['gray'] },
    });
    for (const rule of rules_1.allRules) {
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
    console.log(chalk_1.default.bold.white('  AppShield Rules'));
    console.log('');
    console.log(table.toString());
    console.log('');
}
//# sourceMappingURL=reporter.js.map