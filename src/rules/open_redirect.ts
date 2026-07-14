import { Rule } from '../types';

export const openRedirectRule: Rule = {
  id: 'open-redirect',
  name: 'Open Redirect',
  severity: 'medium',
  description: 'Detects open redirect vulnerabilities where user-supplied URLs are used in redirects without validation, enabling phishing and credential theft attacks.',
  cwe: 'CWE-601',
  owasp: 'A01:2021',
  fileExtensions: ['.ts', '.js', '.py', '.php', '.rb', '.java', '.go'],
  prompt: `You are a security code reviewer specializing in Open Redirect detection.
Your job is to analyze the provided code and identify open redirect vulnerabilities only.

Look specifically for:
- res.redirect() in Express with user-controlled URLs from query params or request body
- window.location, location.href, or location.replace() with unvalidated user input
- Django's HttpResponseRedirect or redirect() with user-supplied next/redirect_url params
- Flask's redirect() with request.args.get('next') or similar unvalidated parameters
- header('Location: ' . $_GET['url']) or similar in PHP without validation
- response.sendRedirect() in Java servlets with user input
- Any redirect that accepts arbitrary URLs from query parameters
- Missing URL validation or only checking for http/https scheme

Do NOT flag:
- Redirects to hardcoded or configuration-based URLs
- Redirects validated against an allowlist of known safe domains/paths
- Relative path redirects (starting with /)
- Login redirects that validate the redirect URL against a whitelist
- Redirects where the URL is constructed entirely from server-side data

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
