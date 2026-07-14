export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';

export type OutputFormat = 'terminal' | 'json' | 'html' | 'sarif' | 'markdown' | 'csv' | 'junit';

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
  newFindings?: number;        // Count of findings not in baseline
  suppressedCount?: number;    // Count of findings suppressed by baseline
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
  output: OutputFormat;
  severity: Severity;
  rules: string[];
  ignore: string[];
  fix: boolean;
  ci: boolean;
  debug: boolean;
  concurrency: number;         // Number of parallel API calls (default: 3)
  baseline?: string;           // Path to baseline file for suppression
  incremental?: boolean;       // Only scan files changed since last scan
  quiet: boolean;              // Suppress progress output, only show report
}

export interface AppShieldConfig {
  ignore: string[];
  severity: Severity;
  rules: string[];
  output: OutputFormat;
  concurrency: number;
  baseline?: string;
}

/** A single suppressed finding in the baseline */
export interface BaselineEntry {
  id: string;                  // Matches Vulnerability.id
  rule: string;                // Rule identifier
  file: string;                // File path at time of suppression
  snippetHash: string;         // SHA256 of the suppressed snippet
  reason: string;              // Why this was suppressed
  suppressedAt: string;        // ISO date string
}

/** Contents of .appshield-baseline.json */
export interface Baseline {
  version: string;
  projectPath: string;
  entries: BaselineEntry[];
}

/** Metadata stored in .appshield-cache.json for incremental scans */
export interface ScanCache {
  version: string;
  lastScanAt: string;
  fileHashes: Record<string, string>;  // relativePath → sha256 hash
}

/** Describes a finding in SARIF format for GitHub Code Scanning */
export interface SarifReport {
  $schema: string;
  version: string;
  runs: SarifRun[];
}

export interface SarifRun {
  tool: {
    driver: {
      name: string;
      version: string;
      informationUri: string;
      rules: SarifRule[];
    };
  };
  results: SarifResult[];
  artifacts: SarifArtifact[];
}

export interface SarifRule {
  id: string;
  shortDescription: { text: string };
  fullDescription: { text: string };
  defaultConfiguration: { level: string };
  properties: {
    tags: string[];
    cwe?: string;
    owasp?: string;
  };
}

export interface SarifResult {
  ruleId: string;
  level: string;
  message: { text: string };
  locations: SarifLocation[];
  partialFingerprints?: { primaryLocationLineHash?: string };
}

export interface SarifLocation {
  physicalLocation: {
    artifactLocation: { uri: string };
    region?: { startLine?: number };
  };
}

export interface SarifArtifact {
  location: { uri: string };
}

/** Deduplication key for findings */
export interface FindingKey {
  rule: string;
  file: string;
  snippetHash: string;
}
