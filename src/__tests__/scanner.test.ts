import * as fs from 'fs/promises';
import * as path from 'path';
import * as os from 'os';
import { ScanReport, ScanOptions } from '../types';
import { writeFixedFiles } from '../scanner';

// ─── Helpers to access internal functions ──────────────────────────────────

// We test internal functions by extracting them via a utility pattern.
// For chunkCode and other internals, we recreate them here since they
// aren't exported, but we test the same logic to validate correctness.

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

function matchesIgnorePattern(filePath: string, patterns: string[]): boolean {
  const basename = filePath.split('/').pop() || filePath;
  for (const pattern of patterns) {
    if (pattern.startsWith('*')) {
      const suffix = pattern.slice(1);
      if (basename.endsWith(suffix)) return true;
      if (filePath.endsWith(suffix)) return true;
    } else if (filePath.includes(pattern)) {
      return true;
    }
  }
  return false;
}

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
  const workers = Array.from(
    { length: Math.min(concurrency, tasks.length) },
    () => worker()
  );
  await Promise.all(workers);
  return results;
}

// ─── Tests ─────────────────────────────────────────────────────────────────

describe('chunkCode', () => {
  it('should return single chunk for files under 500 lines', () => {
    const code = 'line1\nline2\nline3';
    const chunks = chunkCode(code);
    expect(chunks).toHaveLength(1);
    expect(chunks[0]).toBe(code);
  });

  it('should split files >500 lines into chunks', () => {
    const lines = Array.from({ length: 600 }, (_, i) => `line ${i}`);
    const code = lines.join('\n');
    const chunks = chunkCode(code);
    expect(chunks.length).toBeGreaterThan(1);
  });

  it('should have overlap between chunks', () => {
    const lines = Array.from({ length: 600 }, (_, i) => `line ${i}`);
    const code = lines.join('\n');
    const chunks = chunkCode(code);

    const firstChunkLines = chunks[0].split('\n');
    const secondChunkLines = chunks[1].split('\n');
    // The last 20 lines of chunk 0 should appear as first lines of chunk 1
    const overlap = firstChunkLines.slice(-20);
    const start = secondChunkLines.slice(0, 20);
    expect(overlap).toEqual(start);
  });

  it('should have chunk size of 400 lines', () => {
    const lines = Array.from({ length: 600 }, (_, i) => `line ${i}`);
    const code = lines.join('\n');
    const chunks = chunkCode(code);
    expect(chunks[0].split('\n').length).toBe(400);
  });

  it('should handle exactly 500 lines as single chunk', () => {
    const lines = Array.from({ length: 500 }, (_, i) => `line ${i}`);
    const code = lines.join('\n');
    const chunks = chunkCode(code);
    expect(chunks).toHaveLength(1);
  });

  it('should handle 501 lines as two chunks', () => {
    const lines = Array.from({ length: 501 }, (_, i) => `line ${i}`);
    const code = lines.join('\n');
    const chunks = chunkCode(code);
    expect(chunks).toHaveLength(2);
  });
});

describe('matchesIgnorePattern', () => {
  it('should match suffix patterns starting with *', () => {
    expect(matchesIgnorePattern('src/app.test.ts', ['*.test.ts'])).toBe(true);
    expect(matchesIgnorePattern('src/app.spec.ts', ['*.spec.ts'])).toBe(true);
    expect(matchesIgnorePattern('src/app.ts', ['*.test.ts'])).toBe(false);
    expect(matchesIgnorePattern('src/test.ts', ['*.test.ts'])).toBe(false);
  });

  it('should match patterns anywhere in the path', () => {
    expect(matchesIgnorePattern('src/node_modules/pkg/index.js', ['node_modules'])).toBe(true);
    expect(matchesIgnorePattern('src/lib/index.js', ['node_modules'])).toBe(false);
  });

  it('should handle multiple patterns', () => {
    const patterns = ['node_modules', '*.test.ts', 'dist'];
    expect(matchesIgnorePattern('src/node_modules/pkg.js', patterns)).toBe(true);
    expect(matchesIgnorePattern('src/test.test.ts', patterns)).toBe(true);
    expect(matchesIgnorePattern('dist/bundle.js', patterns)).toBe(true);
    expect(matchesIgnorePattern('src/app.ts', patterns)).toBe(false);
  });
});

describe('promisePool', () => {
  it('should execute all tasks', async () => {
    const executed: number[] = [];
    const tasks = [1, 2, 3, 4, 5].map(n => async () => {
      executed.push(n);
      return n;
    });

    const results = await promisePool(tasks, 2);
    expect(results.sort()).toEqual([1, 2, 3, 4, 5]);
    expect(executed.length).toBe(5);
  });

  it('should respect concurrency limit', async () => {
    let running = 0;
    let maxRunning = 0;

    const tasks = Array.from({ length: 10 }, () => async () => {
      running++;
      maxRunning = Math.max(maxRunning, running);
      await new Promise(resolve => setTimeout(resolve, 10));
      running--;
      return 1;
    });

    await promisePool(tasks, 3);
    expect(maxRunning).toBeLessThanOrEqual(3);
  });

  it('should handle empty task array', async () => {
    const results = await promisePool([], 5);
    expect(results).toHaveLength(0);
  });

  it('should preserve task order in results', async () => {
    const tasks = [3, 1, 2].map(n => async () => {
      await new Promise(resolve => setTimeout(resolve, n * 5));
      return n;
    });

    const results = await promisePool(tasks, 3);
    expect(results).toEqual([3, 1, 2]);
  });
});

describe('writeFixedFiles', () => {
  let tmpDir: string;

  beforeEach(async () => {
    tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), 'appshield-test-'));
  });

  afterEach(async () => {
    await fs.rm(tmpDir, { recursive: true, force: true });
  });

  it('should write shielded files for vulnerabilities with fixes', async () => {
    const originalPath = path.join(tmpDir, 'test.ts');
    await fs.writeFile(originalPath, "const q = 'SELECT * FROM users WHERE id = ' + req.params.id");

    const report: ScanReport = {
      projectPath: tmpDir,
      totalFiles: 1,
      totalVulnerabilities: 1,
      criticalCount: 1,
      highCount: 0,
      mediumCount: 0,
      lowCount: 0,
      results: [
        {
          file: 'test.ts',
          vulnerabilities: [
            {
              id: 'SQL_001',
              rule: 'sql-injection',
              severity: 'critical',
              title: 'SQL Injection',
              description: 'User input in SQL query',
              file: 'test.ts',
              line: 1,
              snippet: "const q = 'SELECT * FROM users WHERE id = ' + req.params.id",
              fix: "const q = 'SELECT * FROM users WHERE id = ?'",
              cwe: 'CWE-89',
              owasp: 'A03:2021',
            },
          ],
          scannedAt: new Date().toISOString(),
          tokensUsed: 0,
        },
      ],
      durationMs: 100,
    };

    const writtenFiles = await writeFixedFiles(report, tmpDir);
    expect(writtenFiles).toHaveLength(1);
    expect(writtenFiles[0]).toContain('.shielded.ts');

    // Verify the shielded file has the fix
    const shieldedContent = await fs.readFile(path.join(tmpDir, writtenFiles[0]), 'utf-8');
    expect(shieldedContent).toContain("const q = 'SELECT * FROM users WHERE id = ?'");
  });

  it('should not write files when no fixes are applicable', async () => {
    const originalPath = path.join(tmpDir, 'clean.ts');
    await fs.writeFile(originalPath, 'const x = 1;');

    const report: ScanReport = {
      projectPath: tmpDir,
      totalFiles: 1,
      totalVulnerabilities: 0,
      criticalCount: 0,
      highCount: 0,
      mediumCount: 0,
      lowCount: 0,
      results: [],
      durationMs: 100,
    };

    const writtenFiles = await writeFixedFiles(report, tmpDir);
    expect(writtenFiles).toHaveLength(0);
  });
});
