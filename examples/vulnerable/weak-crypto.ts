/**
 * Example: Weak Cryptography (CWE-327)
 *
 * This file contains intentionally vulnerable code for testing AppShield.
 * DO NOT USE THIS CODE IN PRODUCTION.
 */

import * as crypto from 'crypto';

// VULNERABLE: MD5 used for password hashing
export function hashPasswordMD5(password: string): string {
  return crypto.createHash('md5').update(password).digest('hex');
  // ❌ MD5 is broken — use bcrypt, scrypt, or argon2
}

// VULNERABLE: SHA1 for security
export function hashToken(token: string): string {
  return crypto.createHash('sha1').update(token).digest('hex');
  // ❌ SHA1 is collision-vulnerable — use SHA-256 or SHA-3
}

// VULNERABLE: ECB mode encryption
export function encryptECB(data: string, key: Buffer): Buffer {
  const cipher = crypto.createCipheriv('aes-128-ecb', key, Buffer.alloc(0));
  return Buffer.concat([cipher.update(data), cipher.final()]);
  // ❌ ECB mode leaks patterns — use GCM or CBC with random IV
}

// VULNERABLE: Weak random for crypto
export function generateToken(): string {
  return Math.random().toString(36).substring(2);
  // ❌ Math.random() is not cryptographically secure — use crypto.randomBytes()
}

// VULNERABLE: Hardcoded encryption key
const ENCRYPTION_KEY = "my-static-key-123";
const IV = "1234567890abcdef";

export function encrypt(data: string): string {
  const cipher = crypto.createCipheriv('aes-128-cbc', ENCRYPTION_KEY, IV);
  return cipher.update(data, 'utf-8', 'hex') + cipher.final('hex');
  // ❌ Static key and IV in source code
}
