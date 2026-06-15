import { Rule } from '../types';

export const sqlInjectionRule: Rule = {
  id: 'sql-injection',
  name: 'SQL Injection',
  severity: 'critical',
  description: 'Detects SQL injection vulnerabilities including string concatenation in queries, unparameterized queries, raw user input in .query()/.execute()/.raw() calls, and ORM escape bypasses.',
  cwe: 'CWE-89',
  owasp: 'A03:2021',
  fileExtensions: ['.ts', '.js', '.py', '.php', '.rb', '.java', '.go', '.cs'],
  prompt: `You are a security code reviewer specializing in SQL Injection detection.
Your job is to analyze the provided code and identify SQL Injection vulnerabilities only.

Look specifically for:
- String concatenation or template literals used to build SQL queries with user input
- Unparameterized queries that embed variables directly
- Raw user input passed to .query(), .execute(), .raw(), or similar database methods
- ORM methods that bypass parameterization (e.g. Sequelize.literal, knex.raw with user data)
- Dynamic table or column names from user input without whitelisting

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
