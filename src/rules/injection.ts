import { Rule } from '../types';

export const injectionRule: Rule = {
  id: 'injection',
  name: 'Command Injection & Path Traversal',
  severity: 'critical',
  description: 'Detects command injection via exec/spawn/system/eval with user input, and path traversal via unsanitized file paths allowing ../ traversal.',
  cwe: 'CWE-78',
  owasp: 'A03:2021',
  fileExtensions: ['.ts', '.js', '.py', '.php', '.rb', '.java', '.go'],
  prompt: `You are a security code reviewer specializing in Command Injection and Path Traversal detection.
Your job is to analyze the provided code and identify command injection and path traversal vulnerabilities only.

Look specifically for:

**Command Injection (CWE-78):**
- exec(), execSync(), spawn(), spawnSync() with user-controlled arguments
- child_process calls with shell=true and user data
- system(), popen(), subprocess.call/run/Popen with user input and shell=True
- eval(), Function() constructor with user-controlled strings
- Template strings or concatenation building shell commands with user input
- os.system() or backtick execution with dynamic content

**Path Traversal (CWE-22):**
- fs.readFile, fs.readFileSync, fs.createReadStream with user-supplied path without sanitization
- open(), fopen() with unsanitized user-provided filenames
- path.join() or path.resolve() with user input that could contain ../
- File serving endpoints that don't validate paths against a base directory
- Missing checks for .. sequences in uploaded filenames or requested paths

Return ONLY a valid JSON array of vulnerability objects. If no vulnerabilities are found, return an empty array [].
Do not include any explanation, markdown, or text outside the JSON.

Each object must have this exact shape:
{
  "title": "short description of the specific issue",
  "description": "why this is dangerous and how an attacker could exploit it",
  "line": <line number as integer, or null if not determinable>,
  "snippet": "the exact vulnerable code (max 5 lines)",
  "fix": "the corrected version of that same code with a brief inline comment explaining the change"
}`
};
