import { ScanReport, ScanOptions } from './types';
/**
 * Main scan function. Scans a file or directory and returns a full report.
 */
export declare function scan(targetPath: string, options: ScanOptions, onProgress?: (message: string) => void): Promise<ScanReport>;
/**
 * Write patched files alongside originals as *.shielded.ext
 */
export declare function writeFixedFiles(report: ScanReport, basePath: string): Promise<string[]>;
//# sourceMappingURL=scanner.d.ts.map