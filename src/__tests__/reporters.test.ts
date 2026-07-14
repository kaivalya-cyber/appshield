import {
  reportJSON,
  reportSARIF,
  reportMarkdown,
  reportCSV,
  reportJUnit,
} from '../reporter';
import { ScanReport, Vulnerability, ScanResult, Severity } from '../types';

function makeVuln(overrides: Partial<Vulnerability> = {}): Vulnerability {
  return {
    id: 'SQL_001',
    rule: 'sql-injection',
    severity: 'critical',
    title: 'SQL Injection in user query',
    description: 'User input is directly concatenated into a SQL query.',
    file: 'src/db.ts',
    line: 42,
    snippet: "const q = 'SELECT * FROM users WHERE id = ' + req.params.id",
    fix: "const q = 'SELECT * FROM users WHERE id = ?'",
    cwe: 'CWE-89',
    owasp: 'A03:2021',
    ...overrides,
  };
}

function makeReport(overrides: Partial<ScanReport> = {}): ScanReport {
  const vuln = makeVuln();
  return {
    projectPath: './test-project',
    totalFiles: 10,
    totalVulnerabilities: 1,
    criticalCount: 1,
    highCount: 0,
    mediumCount: 0,
    lowCount: 0,
    results: [
      {
        file: 'src/db.ts',
        vulnerabilities: [vuln],
        scannedAt: '2026-01-01T00:00:00Z',
        tokensUsed: 150,
      },
    ],
    durationMs: 2500,
    newFindings: 1,
    suppressedCount: 0,
    ...overrides,
  };
}

describe('Reporters', () => {
  describe('reportJSON', () => {
    it('should produce valid JSON', () => {
      const report = makeReport();
      const json = reportJSON(report);
      const parsed = JSON.parse(json);
      expect(parsed.projectPath).toBe('./test-project');
      expect(parsed.totalVulnerabilities).toBe(1);
    });
  });

  describe('reportSARIF', () => {
    it('should produce valid SARIF 2.1.0 JSON', () => {
      const report = makeReport();
      const sarif = reportSARIF(report);
      const parsed = JSON.parse(sarif);

      expect(parsed.version).toBe('2.1.0');
      expect(parsed.$schema).toContain('sarif-schema-2.1.0.json');
      expect(parsed.runs).toHaveLength(1);
    });

    it('should include tool driver info', () => {
      const report = makeReport();
      const sarif = reportSARIF(report);
      const parsed = JSON.parse(sarif);

      const driver = parsed.runs[0].tool.driver;
      expect(driver.name).toBe('AppShield');
      expect(driver.version).toBe('1.0.0');
    });

    it('should map severity levels correctly', () => {
      const severities: { severity: Severity; expectedLevel: string }[] = [
        { severity: 'critical', expectedLevel: 'error' },
        { severity: 'high', expectedLevel: 'error' },
        { severity: 'medium', expectedLevel: 'warning' },
        { severity: 'low', expectedLevel: 'note' },
        { severity: 'info', expectedLevel: 'none' },
      ];

      for (const { severity, expectedLevel } of severities) {
        const vuln = makeVuln({ severity });
        const report = makeReport({
          results: [{
            file: 'test.ts', vulnerabilities: [vuln],
            scannedAt: '', tokensUsed: 0,
          }],
        });
        const sarif = reportSARIF(report);
        const parsed = JSON.parse(sarif);
        expect(parsed.runs[0].results[0].level).toBe(expectedLevel);
      }
    });

    it('should include artifact locations', () => {
      const report = makeReport();
      const sarif = reportSARIF(report);
      const parsed = JSON.parse(sarif);

      const artifacts = parsed.runs[0].artifacts;
      expect(artifacts).toHaveLength(1);
      expect(artifacts[0].location.uri).toBe('src/db.ts');
    });

    it('should produce empty results for empty report', () => {
      const report = makeReport({
        totalVulnerabilities: 0,
        criticalCount: 0,
        results: [],
      });
      const sarif = reportSARIF(report);
      const parsed = JSON.parse(sarif);
      expect(parsed.runs[0].results).toHaveLength(0);
    });

    it('should include CWE and OWASP in rule properties', () => {
      const report = makeReport();
      const sarif = reportSARIF(report);
      const parsed = JSON.parse(sarif);

      const rule = parsed.runs[0].tool.driver.rules[0];
      expect(rule.properties.cwe).toBe('CWE-89');
      expect(rule.properties.owasp).toBe('A03:2021');
    });
  });

  describe('reportMarkdown', () => {
    it('should generate a markdown report with title', () => {
      const report = makeReport();
      const md = reportMarkdown(report);
      expect(md).toContain('# 🛡️ AppShield Security Report');
      expect(md).toContain('./test-project');
    });

    it('should include a summary table', () => {
      const report = makeReport();
      const md = reportMarkdown(report);
      expect(md).toContain('| Severity | Count |');
      expect(md).toContain('| 🔴 Critical | 1 |');
      expect(md).toContain('**Total**');
    });

    it('should show clean message for zero vulnerabilities', () => {
      const report = makeReport({
        totalVulnerabilities: 0,
        criticalCount: 0,
        results: [],
      });
      const md = reportMarkdown(report);
      expect(md).toContain('No vulnerabilities found');
    });

    it('should show suppressed count when present', () => {
      const report = makeReport({ suppressedCount: 3 });
      const md = reportMarkdown(report);
      expect(md).toContain('3 finding(s) suppressed');
    });

    it('should include file paths and line numbers', () => {
      const report = makeReport();
      const md = reportMarkdown(report);
      expect(md).toContain('src/db.ts');
      expect(md).toContain('(line 42)');
    });

    it('should use ~~~ fences for code blocks', () => {
      const report = makeReport();
      const md = reportMarkdown(report);
      expect(md).toContain('~~~');
    });
  });

  describe('reportCSV', () => {
    it('should produce valid CSV with headers', () => {
      const report = makeReport();
      const csv = reportCSV(report);

      expect(csv).toContain('ID,Rule,Severity,Title,Description,File,Line,CWE,OWASP,Snippet,Fix');
      expect(csv).toContain('SQL_001');
      expect(csv).toContain('sql-injection');
      expect(csv).toContain('critical');
    });

    it('should include summary comments', () => {
      const report = makeReport();
      const csv = reportCSV(report);
      expect(csv).toContain('# AppShield Security Report');
      expect(csv).toContain('# Critical: 1');
    });

    it('should properly escape double quotes', () => {
      const vuln = makeVuln({ description: 'Test with "quotes"' });
      const report = makeReport({
        results: [{ file: 'test.ts', vulnerabilities: [vuln], scannedAt: '', tokensUsed: 0 }],
      });
      const csv = reportCSV(report);
      expect(csv).toContain('"Test with ""quotes"""');
    });

    it('should handle empty report gracefully', () => {
      const report = makeReport({
        totalVulnerabilities: 0,
        criticalCount: 0,
        results: [],
      });
      const csv = reportCSV(report);
      expect(csv).toContain('ID,Rule,Severity');
    });
  });

  describe('reportJUnit', () => {
    it('should produce valid JUnit XML', () => {
      const report = makeReport();
      const xml = reportJUnit(report);

      expect(xml).toContain('<?xml version="1.0" encoding="UTF-8"?>');
      expect(xml).toContain('<testsuite');
      expect(xml).toContain('name="AppShield Security Scan"');
    });

    it('should map critical and high to failures', () => {
      const vulnCritical = makeVuln({ id: 'C_001', severity: 'critical' });
      const vulnHigh = makeVuln({ id: 'H_001', severity: 'high', rule: 'csrf' });
      const report = makeReport({
        criticalCount: 1,
        highCount: 1,
        results: [
          { file: 'a.ts', vulnerabilities: [vulnCritical], scannedAt: '', tokensUsed: 0 },
          { file: 'b.ts', vulnerabilities: [vulnHigh], scannedAt: '', tokensUsed: 0 },
        ],
      });
      const xml = reportJUnit(report);
      expect(xml).toContain('failures="2"');
      expect(xml).toContain('<failure');
    });

    it('should map medium to errors', () => {
      const vuln = makeVuln({ severity: 'medium' });
      const report = makeReport({
        criticalCount: 0,
        mediumCount: 1,
        results: [
          { file: 'test.ts', vulnerabilities: [vuln], scannedAt: '', tokensUsed: 0 },
        ],
      });
      const xml = reportJUnit(report);
      expect(xml).toContain('errors="1"');
      expect(xml).toContain('<error');
    });

    it('should create a passing testcase for low/empty reports', () => {
      const report = makeReport({
        totalVulnerabilities: 0,
        criticalCount: 0,
        results: [],
      });
      const xml = reportJUnit(report);
      expect(xml).toContain('tests="1"');
      expect(xml).toContain('failures="0"');
      expect(xml).toContain('errors="0"');
    });

    it('should escape XML special characters', () => {
      const vuln = makeVuln({ title: 'Test <script> & "special"' });
      const report = makeReport({
        results: [{ file: 'test.ts', vulnerabilities: [vuln], scannedAt: '', tokensUsed: 0 }],
      });
      const xml = reportJUnit(report);
      expect(xml).toContain('&lt;script&gt;');
      expect(xml).toContain('&amp;');
      expect(xml).toContain('&quot;');
    });
  });
});
