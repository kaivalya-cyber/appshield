import { Rule } from '../types';

export const ssrfRule: Rule = {
  id: 'ssrf',
  name: 'Server-Side Request Forgery (SSRF)',
  severity: 'high',
  description: 'Detects SSRF vulnerabilities where user-controlled URLs are fetched server-side without validation, allowing attackers to access internal services and metadata endpoints.',
  cwe: 'CWE-918',
  owasp: 'A10:2021',
  fileExtensions: ['.ts', '.js', '.py', '.php', '.rb', '.java', '.go'],
  prompt: `You are a security code reviewer specializing in Server-Side Request Forgery (SSRF) detection.
Your job is to analyze the provided code and identify SSRF vulnerabilities only.

Look specifically for:
- fetch(), axios.get(), requests.get(), http.get(), urllib.urlopen() with user-supplied URLs
- HTTP client calls where the URL comes from req.query, req.body, request.args, or similar user input
- Webhook or callback URL endpoints that fetch arbitrary URLs without validation
- curl_exec(), file_get_contents('http://...'), or similar with user-controlled URLs
- URL validation that only checks the scheme (http/https) but not the host/IP
- Image/file download endpoints that fetch resources from user-provided URLs
- Missing hostname/IP allowlisting or denylisting for internal addresses
- Metadata service endpoints potentially accessible (169.254.169.254, metadata.google.internal, etc.)

Do NOT flag:
- Hardcoded or configuration-based URLs not controlled by users
- Properly validated URLs checked against an allowlist of known safe domains
- Code using a dedicated proxy or secure webhook service
- URLs that are validated with proper DNS resolution and IP range checking

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
