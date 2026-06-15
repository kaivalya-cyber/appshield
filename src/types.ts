export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';

export interface Vulnerability {
  id: string;                  // e.g. "SQL_001"
  rule: string;                // e.g. "sql-injection"
  severity: Severity;
  title: string;               // Short human-readable title
  description: string;         // Why this is dangerous
  file: string;                // Relative file path
  line?: number;               // Line number if detectable
  snippet: string;             // The vulnerable code snippet
  fix: string;                 // Fixed version of the snippet
  cwe?: string;                // e.g. "CWE-89"
  owasp?: string;              // e.g. "A03:2021"
}

export interface ScanResult {
  file: string;
  vulnerabilities: Vulnerability[];
  scannedAt: string;
  tokensUsed: number;
}

export interface ScanReport {
  projectPath: string;
  totalFiles: number;
  totalVulnerabilities: number;
  criticalCount: number;
  highCount: number;
  mediumCount: number;
  lowCount: number;
  results: ScanResult[];
  durationMs: number;
}

export interface Rule {
  id: string;
  name: string;
  severity: Severity;
  description: string;
  prompt: string;              // The system prompt for this rule category
  fileExtensions: string[];    // Which file types to apply this rule to
  cwe?: string;
  owasp?: string;
}

export interface ScanOptions {
  output: 'terminal' | 'json' | 'html';
  severity: Severity;
  rules: string[];
  ignore: string[];
  fix: boolean;
  ci: boolean;
  debug: boolean;
}

export interface AppShieldConfig {
  ignore: string[];
  severity: Severity;
  rules: string[];
  output: 'terminal' | 'json' | 'html';
}
