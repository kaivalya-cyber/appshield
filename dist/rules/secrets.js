"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.secretsRule = void 0;
exports.secretsRule = {
    id: 'secrets',
    name: 'Hardcoded Secrets',
    severity: 'high',
    description: 'Detects hardcoded API keys, passwords, tokens, private keys, connection strings with credentials, and base64-encoded secrets in source code.',
    cwe: 'CWE-798',
    owasp: 'A02:2021',
    fileExtensions: ['.*'], // All text files
    prompt: `You are a security code reviewer specializing in Hardcoded Secrets detection.
Your job is to analyze the provided code and identify hardcoded secrets, credentials, and sensitive data only.

Look specifically for:
- Hardcoded API keys (e.g. strings matching sk-, ghp_, AKIA, rk_, pk_live_, pk_test_)
- Hardcoded passwords assigned to variables
- Hardcoded tokens (JWT, OAuth, bearer tokens)
- Private keys (-----BEGIN RSA PRIVATE KEY-----, -----BEGIN EC PRIVATE KEY-----, etc.)
- Database connection strings containing passwords
- Base64-encoded secrets that decode to credentials
- AWS access keys, Azure keys, GCP service account keys
- Webhook URLs with tokens embedded
- .env values hardcoded directly in source instead of using environment variables

Do NOT flag:
- Environment variable references (process.env.*, os.environ, etc.)
- Placeholder values like "your_key_here", "TODO", "xxx", "changeme"
- Test fixtures that are clearly fake values
- Hash constants (e.g. algorithm names, hash type identifiers)

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
//# sourceMappingURL=secrets.js.map