"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.xssRule = void 0;
exports.xssRule = {
    id: 'xss',
    name: 'Cross-Site Scripting (XSS)',
    severity: 'critical',
    description: 'Detects XSS vulnerabilities including innerHTML usage, dangerouslySetInnerHTML, document.write, unescaped template variables rendered to HTML, and missing output encoding.',
    cwe: 'CWE-79',
    owasp: 'A03:2021',
    fileExtensions: ['.ts', '.tsx', '.js', '.jsx', '.php', '.py', '.rb', '.html', '.ejs', '.hbs'],
    prompt: `You are a security code reviewer specializing in Cross-Site Scripting (XSS) detection.
Your job is to analyze the provided code and identify XSS vulnerabilities only.

Look specifically for:
- Use of innerHTML with user-controlled data
- dangerouslySetInnerHTML in React components with user input
- document.write() with dynamic content
- Unescaped template variables rendered into HTML (e.g. <%- %> in EJS, {{{ }}} in Handlebars, | safe in Jinja2)
- Missing output encoding when inserting user data into DOM
- Reflected input from URL parameters or form data rendered without sanitization
- Using v-html in Vue with user data

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
//# sourceMappingURL=xss.js.map