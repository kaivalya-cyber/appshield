"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.idorRule = void 0;
exports.idorRule = {
    id: 'idor',
    name: 'Insecure Direct Object Reference (IDOR)',
    severity: 'high',
    description: 'Detects IDOR vulnerabilities where user-supplied IDs are used to fetch records without ownership checks, missing authorization after authentication, and raw route params used without validation.',
    cwe: 'CWE-639',
    owasp: 'A01:2021',
    fileExtensions: ['.ts', '.js', '.py', '.php', '.rb', '.java', '.go'],
    prompt: `You are a security code reviewer specializing in Insecure Direct Object Reference (IDOR) detection.
Your job is to analyze the provided code and identify IDOR vulnerabilities only.

Look specifically for:
- Using user-supplied IDs (req.params.id, request.args.get('id'), etc.) to fetch database records without verifying the requesting user owns or has access to that record
- API endpoints that fetch resources by ID without any authorization check beyond authentication
- Missing ownership validation (e.g. findById(req.params.id) without checking record.userId === req.user.id)
- Routes that allow modifying or deleting resources using user-provided IDs without access control
- File download endpoints that use user-supplied filenames/paths without authorization
- Endpoints where changing an ID in the URL could expose another user's data

Do NOT flag:
- Public resources that are intentionally accessible to all users
- Admin-only routes with proper role checks
- Routes that already filter by the authenticated user's ID

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
//# sourceMappingURL=idor.js.map