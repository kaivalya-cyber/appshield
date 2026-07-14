import { Rule } from '../types';

export const prototypePollutionRule: Rule = {
  id: 'prototype-pollution',
  name: 'Prototype Pollution',
  severity: 'high',
  description: 'Detects prototype pollution vulnerabilities in JavaScript/TypeScript where user input can modify Object.prototype through unsafe merge, deep clone, or property assignment operations.',
  cwe: 'CWE-1321',
  owasp: 'A08:2021',
  fileExtensions: ['.ts', '.js'],
  prompt: `You are a security code reviewer specializing in Prototype Pollution detection.
Your job is to analyze the provided code and identify prototype pollution vulnerabilities only in JavaScript/TypeScript.

Look specifically for:
- Recursive merge/deep merge functions that merge user input into objects without filtering __proto__, constructor, or prototype keys
- Object.assign() or spread operator (...) used with unsanitized user-controlled objects
- Deep clone utilities (lodash.cloneDeep, custom clone functions) applied to user input
- lodash.merge, lodash.defaultsDeep, or similar with user-controlled objects
- _.set(), _.setWith() with user-provided paths that could target __proto__
- Custom path-based property setters (e.g., obj[a][b] = value with user-controlled a, b)
- JSON.parse() results being merged into configuration or system objects
- express.urlencoded() with extended: true parsing nested objects from query strings
- Object.create(null) NOT used for objects that store user-provided keys
- Libraries known to be vulnerable to prototype pollution (hoek < 4.2.1, handlebars < 4.5.3, etc.)

Do NOT flag:
- Objects created with Object.create(null)
- Merging into objects where all keys are predefined and validated
- Functions that explicitly filter out __proto__, constructor, and prototype
- Configuration objects that are entirely server-defined

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
