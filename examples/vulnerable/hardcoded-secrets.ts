/**
 * Example: Hardcoded Secrets (CWE-798)
 *
 * This file contains intentionally vulnerable code for testing AppShield.
 * DO NOT USE THIS CODE IN PRODUCTION.
 * These are fake credentials for demonstration purposes only.
 */

// VULNERABLE: Hardcoded API keys
const STRIPE_SECRET_KEY = "sk_live_REPLACE_WITH_YOUR_KEY";
const AWS_ACCESS_KEY = "AKIA_REPLACE_WITH_YOUR_KEY";
const GITHUB_TOKEN = "ghp_REPLACE_WITH_YOUR_TOKEN";

// VULNERABLE: Hardcoded passwords
const DB_PASSWORD = "admin123!";
const JWT_SECRET = "my-super-secret-key-that-should-be-in-env";

// VULNERABLE: Connection strings with credentials
const MONGO_URI = "mongodb://admin:password123@localhost:27017/mydb";

// VULNERABLE: Private key in source
const PRIVATE_KEY = `-----BEGIN RSA PRIVATE KEY-----
REPLACE_WITH_YOUR_PRIVATE_KEY
-----END RSA PRIVATE KEY-----`;

// VULNERABLE: Base64 encoded secret (decodes to "password")
const ENCODED_SECRET = "cGFzc3dvcmQ=";
