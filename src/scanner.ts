import * as fs from 'fs/promises';
import * as path from 'path';
import { Rule, ScanResult, ScanReport, ScanOptions } from './types';
import { getRulesByIds, getApplicableRules } from './rules';
import { analyzeCode } from './analyzer';

// Always skip these directories and file patterns
const ALWAYS_SKIP_DIRS = new Set([
  'node_modules', '.git', 'dist', 'build', '.next', '__pycache__',
  '.venv', 'venv', '.tox', 'vendor', '.bundle',
]);

const ALWAYS_SKIP_PATTERNS = [
  /\.min\.js$/,
  /\.lock$/,
  /\.map$/,
  /\.d\.ts$/,
  /\.png$/i, /\.jpg$/i, /\.jpeg$/i, /\.gif$/i, /\.svg$/i, /\.ico$/i,
  /\.woff2?$/i, /\.ttf$/i, /\.eot$/i,
  /\.pdf$/i, /\.zip$/i, /\.tar$/i, /\.gz$/i,
  /\.exe$/i, /\.dll$/i, /\.so$/i, /\.dylib$/i,
  /\.mp3$/i, /\.mp4$/i, /\.mov$/i, /\.avi$/i,
  /\.wasm$/i,
];

/**
 * Check if a file is likely binary by reading first 8KB and looking for null bytes.
 */
async function isBinary(filePath: string): Promise<boolean> {
  try {
    const handle = await fs.open(filePath, 'r');
    const buffer = Buffer.alloc(8192);
    const { bytesRead } = await handle.read(buffer, 0, 8192);
    await handle.close();
    for (let i = 0; i < bytesRead; i++) {
      if (buffer[i] === 0) return true;
    }
    return false;
  } catch {
    return true; // If we can't read it, treat as binary
  }
}

/**
 * Check if a path matches any of the ignore patterns.
 */
function matchesIgnorePattern(filePath: string, patterns: string[]): boolean {
  for (const pattern of patterns) {
    // Simple glob matching: support * and direct string matching
    if (pattern.startsWith('*')) {
      // e.g. *.test.ts → match files ending with .test.ts
      const suffix = pattern.slice(1);
      if (filePath.endsWith(suffix)) return true;
    } else if (filePath.includes(pattern)) {
      return true;
    }
  }
  return false;
}

/**
 * Recursively walk a directory and collect all scannable file paths.
 */
async function walkDirectory(
  dir: string,
  ignorePatterns: string[],
  basePath: string
): Promise<string[]> {
  const files: string[] = [];
  let entries;
  try {
    entries = await fs.readdir(dir, { withFileTypes: true });
  } catch (err: any) {
    console.warn(`⚠ Cannot read directory: ${dir} — ${err.message}`);
    return files;
  }

  for (const entry of entries) {
    const fullPath = path.join(dir, entry.name);
    const relativePath = path.relative(basePath, fullPath);

    if (entry.isDirectory()) {
      if (ALWAYS_SKIP_DIRS.has(entry.name)) continue;
      if (matchesIgnorePattern(relativePath, ignorePatterns)) continue;
      const subFiles = await walkDirectory(fullPath, ignorePatterns, basePath);
      files.push(...subFiles);
    } else if (entry.isFile()) {
      // Skip always-skip patterns
      if (ALWAYS_SKIP_PATTERNS.some(p => p.test(entry.name))) continue;
      if (matchesIgnorePattern(relativePath, ignorePatterns)) continue;
      files.push(fullPath);
    }
  }

  return files;
}

/**
 * Load .appshieldignore file patterns if it exists.
 */
async function loadIgnoreFile(projectPath: string): Promise<string[]> {
  const ignorePath = path.join(projectPath, '.appshieldignore');
  try {
    const content = await fs.readFile(ignorePath, 'utf-8');
    return content
      .split('\n')
      .map(line => line.trim())
      .filter(line => line && !line.startsWith('#'));
  } catch {
    return [];
  }
}

/**
 * Chunk a file's code into overlapping segments for large files.
 * Files >500 lines are split into 400-line chunks with 20-line overlap.
 */
function chunkCode(code: string): string[] {
  const lines = code.split('\n');
  if (lines.length <= 500) {
    return [code];
  }

  const chunks: string[] = [];
  const chunkSize = 400;
  const overlap = 20;
  let start = 0;

  while (start < lines.length) {
    const end = Math.min(start + chunkSize, lines.length);
    chunks.push(lines.slice(start, end).join('\n'));
    if (end >= lines.length) break;
    start = end - overlap; // Overlap for context continuity
  }

  return chunks;
}

/**
 * Simple promise pool for concurrent API calls.
 * Runs up to `concurrency` tasks at a time.
 */
async function promisePool<T>(
  tasks: (() => Promise<T>)[],
  concurrency: number
): Promise<T[]> {
  const results: T[] = [];
  let index = 0;

  async function worker(): Promise<void> {
    while (index < tasks.length) {
      const i = index++;
      results[i] = await tasks[i]();
    }
  }

  const workers = Array.from({ length: Math.min(concurrency, tasks.length) }, () => worker());
  await Promise.all(workers);
  return results;
}

interface ScanTask {
  filePath: string;
  relativePath: string;
  code: string;
  rule: Rule;
  chunkIndex: number;
  totalChunks: number;
}

/**
 * Main scan function. Scans a file or directory and returns a full report.
 */
export async function scan(
  targetPath: string,
  options: ScanOptions,
  onProgress?: (message: string) => void
): Promise<ScanReport> {
  const startTime = Date.now();
  const resolvedPath = path.resolve(targetPath);

  // Check if path exists
  let stat;
  try {
    stat = await fs.stat(resolvedPath);
  } catch {
    console.error(`❌ Path not found: ${targetPath}`);
    process.exit(1);
  }

  // Collect files to scan
  let filePaths: string[];
  let basePath: string;

  if (stat.isFile()) {
    filePaths = [resolvedPath];
    basePath = path.dirname(resolvedPath);
  } else if (stat.isDirectory()) {
    basePath = resolvedPath;
    // Load ignore patterns
    const fileIgnore = await loadIgnoreFile(resolvedPath);
    const allIgnorePatterns = [...options.ignore, ...fileIgnore];
    filePaths = await walkDirectory(resolvedPath, allIgnorePatterns, basePath);
  } else {
    console.error(`❌ Path is neither a file nor a directory: ${targetPath}`);
    process.exit(1);
  }

  // Filter out binary files
  const textFiles: string[] = [];
  for (const fp of filePaths) {
    if (!(await isBinary(fp))) {
      textFiles.push(fp);
    }
  }

  if (textFiles.length === 0) {
    onProgress?.('No scannable files found.');
    return {
      projectPath: targetPath,
      totalFiles: 0,
      totalVulnerabilities: 0,
      criticalCount: 0,
      highCount: 0,
      mediumCount: 0,
      lowCount: 0,
      results: [],
      durationMs: Date.now() - startTime,
    };
  }

  // Get selected rules
  const selectedRules = getRulesByIds(options.rules);

  // Build scan tasks: file × rule × chunk combinations
  const tasks: ScanTask[] = [];

  for (const filePath of textFiles) {
    const ext = path.extname(filePath).toLowerCase();
    const relativePath = path.relative(basePath, filePath);
    const applicableRules = getApplicableRules(ext, selectedRules);

    if (applicableRules.length === 0) continue;

    let code: string;
    try {
      code = await fs.readFile(filePath, 'utf-8');
    } catch (err: any) {
      console.warn(`⚠ Cannot read file: ${relativePath} — ${err.message}`);
      continue;
    }

    const chunks = chunkCode(code);

    for (const rule of applicableRules) {
      for (let i = 0; i < chunks.length; i++) {
        tasks.push({
          filePath,
          relativePath,
          code: chunks[i],
          rule,
          chunkIndex: i,
          totalChunks: chunks.length,
        });
      }
    }
  }

  onProgress?.(`Scanning ${textFiles.length} files with ${selectedRules.length} rules (${tasks.length} analysis tasks)...`);

  // Execute tasks with concurrency pool (max 3 parallel)
  let completed = 0;
  const taskFunctions = tasks.map(task => async () => {
    const result = await analyzeCode(
      task.code,
      task.relativePath,
      task.rule,
      options.debug
    );
    completed++;
    if (completed % 5 === 0 || completed === tasks.length) {
      onProgress?.(`Progress: ${completed}/${tasks.length} tasks completed`);
    }
    return { task, result };
  });

  const results = await promisePool(taskFunctions, 3);

  // Group results by file
  const fileResults = new Map<string, ScanResult>();

  for (const { task, result } of results) {
    if (!fileResults.has(task.relativePath)) {
      fileResults.set(task.relativePath, {
        file: task.relativePath,
        vulnerabilities: [],
        scannedAt: new Date().toISOString(),
        tokensUsed: 0,
      });
    }

    const fileResult = fileResults.get(task.relativePath)!;
    fileResult.vulnerabilities.push(...result.vulnerabilities);
    fileResult.tokensUsed += result.tokensUsed;
  }

  // Build severity filter
  const severityOrder: Record<string, number> = {
    critical: 4,
    high: 3,
    medium: 2,
    low: 1,
    info: 0,
  };
  const minSeverity = severityOrder[options.severity] || 0;

  // Filter vulnerabilities by severity threshold
  const allResults = Array.from(fileResults.values()).map(result => ({
    ...result,
    vulnerabilities: result.vulnerabilities.filter(
      v => (severityOrder[v.severity] || 0) >= minSeverity
    ),
  }));

  // Count by severity
  const allVulns = allResults.flatMap(r => r.vulnerabilities);

  const report: ScanReport = {
    projectPath: targetPath,
    totalFiles: textFiles.length,
    totalVulnerabilities: allVulns.length,
    criticalCount: allVulns.filter(v => v.severity === 'critical').length,
    highCount: allVulns.filter(v => v.severity === 'high').length,
    mediumCount: allVulns.filter(v => v.severity === 'medium').length,
    lowCount: allVulns.filter(v => v.severity === 'low').length,
    results: allResults.filter(r => r.vulnerabilities.length > 0),
    durationMs: Date.now() - startTime,
  };

  return report;
}

/**
 * Write patched files alongside originals as *.shielded.ext
 */
export async function writeFixedFiles(report: ScanReport, basePath: string): Promise<string[]> {
  const writtenFiles: string[] = [];

  for (const result of report.results) {
    if (result.vulnerabilities.length === 0) continue;

    const originalPath = path.resolve(basePath, result.file);
    let code: string;
    try {
      code = await fs.readFile(originalPath, 'utf-8');
    } catch {
      continue;
    }

    // Apply fixes sequentially
    let patchedCode = code;
    for (const vuln of result.vulnerabilities) {
      if (vuln.snippet && vuln.fix) {
        // Simple text replacement — replace first occurrence
        const idx = patchedCode.indexOf(vuln.snippet);
        if (idx !== -1) {
          patchedCode =
            patchedCode.substring(0, idx) +
            vuln.fix +
            patchedCode.substring(idx + vuln.snippet.length);
        }
      }
    }

    if (patchedCode !== code) {
      const ext = path.extname(originalPath);
      const base = originalPath.slice(0, -ext.length);
      const shieldedPath = `${base}.shielded${ext}`;
      await fs.writeFile(shieldedPath, patchedCode, 'utf-8');
      writtenFiles.push(path.relative(basePath, shieldedPath));
    }
  }

  return writtenFiles;
}
