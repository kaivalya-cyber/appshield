"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.authRule = void 0;
exports.authRule = {
    id: 'auth',
    name: 'Broken Authentication',
    severity: 'high',
    description: 'Detects broken authentication issues including weak session tokens, missing JWT expiry, no rate limiting on login, passwords stored without hashing, and missing auth middleware on sensitive routes.',
    cwe: 'CWE-287',
    owasp: 'A07:2021',
    fileExtensions: ['.ts', '.js', '.py', '.php', '.rb', '.java', '.go'],
    prompt: `You are a security code reviewer specializing in Broken Authentication detection.
Your job is to analyze the provided code and identify authentication and session management vulnerabilities only.

Look specifically for:
- Weak session token generation (e.g. using Math.random(), predictable IDs, sequential tokens)
- JWTs created without expiration (missing exp claim or expiresIn option)
- Missing rate limiting on login, registration, or password reset routes
- Passwords stored in plaintext or with weak hashing (MD5, SHA1 without salt)
- Password comparison using == or === instead of constant-time comparison (timing attacks)
- Missing authentication middleware on routes that access sensitive data
- Session tokens that don't rotate after login (session fixation)
- Missing CSRF protection on state-changing operations
- "Remember me" tokens stored insecurely

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
//# sourceMappingURL=auth.js.map