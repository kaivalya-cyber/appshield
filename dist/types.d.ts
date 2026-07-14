export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';
export type OutputFormat = 'terminal' | 'json' | 'html' | 'sarif' | 'markdown' | 'csv' | 'junit';
export interface Vulnerability {
    id: string;
    rule: string;
    severity: Severity;
    title: string;
    description: string;
    file: string;
    line?: number;
    snippet: string;
    fix: string;
    cwe?: string;
    owasp?: string;
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
    newFindings?: number;
    suppressedCount?: number;
}
export interface Rule {
    id: string;
    name: string;
    severity: Severity;
    description: string;
    prompt: string;
    fileExtensions: string[];
    cwe?: string;
    owasp?: string;
}
export interface ScanOptions {
    output: OutputFormat;
    severity: Severity;
    rules: string[];
    ignore: string[];
    extensions: string[];
    fix: boolean;
    ci: boolean;
    debug: boolean;
    concurrency: number;
    baseline?: string;
    incremental?: boolean;
    quiet: boolean;
    watch?: boolean;
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
    id: string;
    rule: string;
    file: string;
    snippetHash: string;
    reason: string;
    suppressedAt: string;
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
    fileHashes: Record<string, string>;
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
    shortDescription: {
        text: string;
    };
    fullDescription: {
        text: string;
    };
    defaultConfiguration: {
        level: string;
    };
    properties: {
        tags: string[];
        cwe?: string;
        owasp?: string;
    };
}
export interface SarifResult {
    ruleId: string;
    level: string;
    message: {
        text: string;
    };
    locations: SarifLocation[];
    partialFingerprints?: {
        primaryLocationLineHash?: string;
    };
}
export interface SarifLocation {
    physicalLocation: {
        artifactLocation: {
            uri: string;
        };
        region?: {
            startLine?: number;
        };
    };
}
export interface SarifArtifact {
    location: {
        uri: string;
    };
}
/** Deduplication key for findings */
export interface FindingKey {
    rule: string;
    file: string;
    snippetHash: string;
}
//# sourceMappingURL=types.d.ts.map