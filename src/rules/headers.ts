import { Rule } from '../types';

export const headersRule: Rule = {
  id: 'headers',
  name: 'Missing Security Headers',
  severity: 'medium',
  description: 'Detects missing security headers in web applications including missing helmet/CSP/HSTS, permissive CORS, and insecure cookie configuration.',
  cwe: 'CWE-693',
  owasp: 'A05:2021',
  fileExtensions: ['.ts', '.js', '.py', '.rb'],
  prompt: `You are a security code reviewer specializing in Missing Security Headers detection.
Your job is to analyze the provided code and identify missing or misconfigured security headers only.

Look specifically for:
- Express.js apps not using helmet middleware
- Missing Content-Security-Policy header
- Missing X-Frame-Options header (clickjacking protection)
- Missing Strict-Transport-Security (HSTS) header
- Permissive CORS configuration (Access-Control-Allow-Origin: * on sensitive endpoints)
- Cookies set without SameSite attribute
- Cookies set without Secure flag
- Cookies set without HttpOnly flag
- Missing X-Content-Type-Options: nosniff
- Missing Referrer-Policy header
- Flask/Django apps missing security middleware
- Explicitly disabling security features (e.g. app.disable('x-powered-by') is GOOD)

Do NOT flag:
- Development-only configurations clearly gated behind NODE_ENV checks
- Static file servers or public CDN endpoints where permissive CORS is intentional
- Code that's already using helmet or equivalent security middleware

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
