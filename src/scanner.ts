import * as fs from 'fs/promises';
import * as path from 'path';
import * as crypto from 'crypto';
import { Rule, ScanResult, ScanReport, ScanOptions, BaselineEntry } from './types';
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

// ─── Crypto & hashing helpers ──────────────────────────────────────────────

function simpleSHA256(content: string): string {
  return crypto.createHash('sha256').update(content).digest('hex');
}

function hashSnippet(snippet: string): string {
  return simpleSHA256(snippet.trim());
}

// ─── Cache (incremental scan) helpers ──────────────────────────────────────

async function loadCache(projectPath: string): Promise<Record<string, string>> {
  try {
    const cachePath = path.join(projectPath, '.appshield-cache.json');
    const content = await fs.readFile(cachePath, 'utf-8');
    const data = JSON.parse(content);
    return data.fileHashes || {};
  } catch {
    return {};
  }
}

async function saveCache(projectPath: string, fileHashes: Record<string, string>): Promise<void> {
  const cachePath = path.join(projectPath, '.appshield-cache.json');
  const cacheData = {
    version: '1.0.0',
    lastScanAt: new Date().toISOString(),
    fileHashes,
  };
  await fs.writeFile(cachePath, JSON.stringify(cacheData, null, 2), 'utf-8');
}

// ─── Baseline helpers ──────────────────────────────────────────────────────

async function loadBaseline(baselinePath: string | undefined, basePath: string): Promise<BaselineEntry[]> {
  try {
    const finalPath = baselinePath || path.join(basePath, '.appshield-baseline.json');
    const content = await fs.readFile(finalPath, 'utf-8');
    const data = JSON.parse(content);
    return Array.isArray(data.entries) ? data.entries : [];
  } catch {
    return [];
  }
}

// ─── File discovery ────────────────────────────────────────────────────────

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
  const basename = path.basename(filePath);
  for (const pattern of patterns) {
    if (pattern.startsWith('*')) {
      // Glob-like pattern: check against basename (e.g. *.test.ts)
      const suffix = pattern.slice(1);
      if (basename.endsWith(suffix)) return true;
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
    start = end - overlap;
  }

  return chunks;
}

/**
 * Simple promise pool for concurrent API calls.
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

  // Quiet-mode-aware progress helper
  const progress = (msg: string) => {
    if (!options.quiet && onProgress) {
      onProgress(msg);
    }
  };

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
    progress('No scannable files found.');
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
      newFindings: 0,
      suppressedCount: 0,
    };
  }

  // Get selected rules
  const selectedRules = getRulesByIds(options.rules);

  // ─── Incremental scan: load cache and hash files ────────────────────────
  let oldCache: Record<string, string> = {};
  if (options.incremental) {
    oldCache = await loadCache(basePath);
  }
  const newCache: Record<string, string> = {};

  // Build scan tasks: file × rule × chunk combinations
  const tasks: ScanTask[] = [];

  let skippedByCache = 0;

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

    // Compute hash for incremental cache
    const fileHash = simpleSHA256(code);
    newCache[relativePath] = fileHash;

    // Skip unchanged files in incremental mode
    if (options.incremental && oldCache[relativePath] === fileHash) {
      skippedByCache++;
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

  // Save updated cache (including entries for unchanged files)
  if (options.incremental) {
    for (const filePath of textFiles) {
      const relativePath = path.relative(basePath, filePath);
      if (!newCache[relativePath] && oldCache[relativePath]) {
        newCache[relativePath] = oldCache[relativePath];
      }
    }
    await saveCache(basePath, newCache);
  }

  if (options.incremental && skippedByCache > 0) {
    progress(`Skipped ${skippedByCache} unchanged files (incremental scan).`);
  }

  if (tasks.length === 0) {
    progress('All files unchanged since last scan — nothing to analyze.');
    return {
      projectPath: targetPath,
      totalFiles: textFiles.length,
      totalVulnerabilities: 0,
      criticalCount: 0,
      highCount: 0,
      mediumCount: 0,
      lowCount: 0,
      results: [],
      durationMs: Date.now() - startTime,
      newFindings: 0,
      suppressedCount: 0,
    };
  }

  progress(`Scanning ${textFiles.length} files with ${selectedRules.length} rules (${tasks.length} analysis tasks)...`);

  // Execute tasks with configurable concurrency pool
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
      const percent = Math.round((completed / tasks.length) * 100);
      progress(`Progress: ${percent}% (${completed}/${tasks.length})`);
    }
    return { task, result };
  });

  const results = await promisePool(taskFunctions, options.concurrency || 3);

  // ─── Group results by file with deduplication ───────────────────────────
  const fileResults = new Map<string, ScanResult>();
  const uniqueFindingKeys = new Set<string>();

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

    for (const vuln of result.vulnerabilities) {
      const snippetHash = hashSnippet(vuln.snippet);
      const dedupKey = `${vuln.rule}:${task.relativePath}:${snippetHash}`;

      if (!uniqueFindingKeys.has(dedupKey)) {
        uniqueFindingKeys.add(dedupKey);
        fileResult.vulnerabilities.push(vuln);
      }
    }
    fileResult.tokensUsed += result.tokensUsed;
  }

  // ─── Load baseline and filter suppressed findings ───────────────────────
  const baselineEntries = await loadBaseline(options.baseline, basePath);
  let suppressedCount = 0;

  // Build severity filter
  const severityOrder: Record<string, number> = {
    critical: 4,
    high: 3,
    medium: 2,
    low: 1,
    info: 0,
  };
  const minSeverity = severityOrder[options.severity] || 0;

  // Filter: severity threshold + baseline suppression
  const allFilteredResults = Array.from(fileResults.values()).map(result => {
    const activeVulns = [];
    for (const v of result.vulnerabilities) {
      // Severity threshold check
      if ((severityOrder[v.severity] || 0) < minSeverity) {
        continue;
      }

      // Baseline suppression check
      const snippetHash = hashSnippet(v.snippet);
      const isSuppressed = baselineEntries.some(entry =>
        entry.id === v.id ||
        (entry.rule === v.rule && entry.file === result.file && entry.snippetHash === snippetHash)
      );

      if (isSuppressed) {
        suppressedCount++;
      } else {
        activeVulns.push(v);
      }
    }

    return {
      ...result,
      vulnerabilities: activeVulns,
    };
  });

  // Build report
  const allVulns = allFilteredResults.flatMap(r => r.vulnerabilities);

  const report: ScanReport = {
    projectPath: targetPath,
    totalFiles: textFiles.length,
    totalVulnerabilities: allVulns.length,
    criticalCount: allVulns.filter(v => v.severity === 'critical').length,
    highCount: allVulns.filter(v => v.severity === 'high').length,
    mediumCount: allVulns.filter(v => v.severity === 'medium').length,
    lowCount: allVulns.filter(v => v.severity === 'low').length,
    results: allFilteredResults.filter(r => r.vulnerabilities.length > 0),
    durationMs: Date.now() - startTime,
    newFindings: allVulns.length,
    suppressedCount,
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
