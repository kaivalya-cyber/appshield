import { Rule } from '../types';

export const weakCryptoRule: Rule = {
  id: 'weak-crypto',
  name: 'Weak Cryptography',
  severity: 'high',
  description: 'Detects use of weak, broken, or deprecated cryptographic algorithms including MD5, SHA1 for security, RC4, DES, ECB mode, and hardcoded encryption keys.',
  cwe: 'CWE-327',
  owasp: 'A02:2021',
  fileExtensions: ['.ts', '.js', '.py', '.php', '.rb', '.java', '.go', '.cs', '.kt', '.swift'],
  prompt: `You are a security code reviewer specializing in Weak Cryptography detection.
Your job is to analyze the provided code and identify use of weak or broken cryptographic algorithms only.

Look specifically for:
- MD5 used for any security purpose (hashing passwords, integrity checks, signatures)
- SHA1 used for security-sensitive operations (SHA1 is broken for collision resistance)
- RC4, DES, 3DES, Blowfish used for encryption
- ECB (Electronic Codebook) mode for block ciphers
- RSA with key sizes < 2048 bits
- ECC with curves < 256 bits
- Hardcoded encryption keys, IVs, or salts in source code
- Predictable or weak random number generation for crypto: Math.random(), rand(), mt_rand()
- Missing proper IV/nonce generation (static or repeated IVs)
- Passwords hashed with a single iteration (no bcrypt, scrypt, argon2, or PBKDF2)
- crypto.createHash() used for password storage instead of crypto.pbkdf2/scrypt
- PKCS#1 v1.5 padding instead of OAEP for RSA encryption
- Using deprecated crypto constants or algorithms

Do NOT flag:
- MD5/SHA1 used for non-security purposes (checksums, hash tables, deduplication)
- HMAC with MD5/SHA1 for message authentication
- Cryptographically secure random functions (crypto.randomBytes, secrets module, os.urandom)
- Proper use of bcrypt, scrypt, argon2, PBKDF2 for passwords
- AES-GCM, ChaCha20-Poly1305, or other modern authenticated encryption

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
