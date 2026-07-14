import { Rule } from '../types';

export const redosRule: Rule = {
  id: 'redos',
  name: 'ReDoS (Regular Expression Denial of Service)',
  severity: 'medium',
  description: 'Detects regular expressions vulnerable to catastrophic backtracking (ReDoS), where specially crafted input can cause exponential processing time and denial of service.',
  cwe: 'CWE-1333',
  owasp: 'A05:2021',
  fileExtensions: ['.ts', '.js', '.py', '.php', '.rb', '.java', '.go'],
  prompt: `You are a security code reviewer specializing in ReDoS (Regular Expression Denial of Service) detection.
Your job is to analyze the provided code and identify regex patterns vulnerable to catastrophic backtracking only.

Look specifically for:
- Regex patterns with nested quantifiers: (a+)+, (a*)*, ([a-z]+)*, (a|b)*, (.*)*
- Alternation with overlaps under repetition: (a|ab)*, (a|aa)+
- Greedy quantifiers followed by optional groups: .*(optional)?
- User-controlled input matched against complex regex without timeout protection
- RegExp() constructor with user-supplied patterns (regex injection)
- Patterns like /^(a+)+$/ that backtrack exponentially on non-matching input
- Unanchored regex with .* at beginning used for validation
- Regex used in URL routing, input validation, or data parsing without safeguards
- Missing regex timeout mechanisms (e.g., no re2, safe-regex, or timeout wrapper)

Do NOT flag:
- Regex used in static contexts where input length is bounded
- Simple patterns without quantifier nesting
- Patterns using non-greedy/lazy quantifiers safely
- Code already using safe regex libraries (re2, safe-regex, etc.)
- Regex with obvious length limits on input beforehand

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
