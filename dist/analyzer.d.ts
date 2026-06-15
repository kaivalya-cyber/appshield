import { Rule, Vulnerability } from './types';
/**
 * Analyze a code chunk against a specific rule using Claude.
 * Returns an array of vulnerabilities found.
 */
export declare function analyzeCode(code: string, filePath: string, rule: Rule, debug?: boolean, retryCount?: number): Promise<{
    vulnerabilities: Vulnerability[];
    tokensUsed: number;
}>;
//# sourceMappingURL=analyzer.d.ts.map