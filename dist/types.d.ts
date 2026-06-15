export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';
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
//# sourceMappingURL=types.d.ts.map