/**
 * Example: IDOR (CWE-639) & Broken Authentication (CWE-287)
 *
 * This file contains intentionally vulnerable code for testing AppShield.
 * DO NOT USE THIS CODE IN PRODUCTION.
 */

import { Request, Response, NextFunction } from 'express';

// ─── IDOR Vulnerabilities ─────────────────────────────────────────────────

// VULNERABLE: Fetching records without ownership check
export async function getInvoice(req: Request, res: Response) {
  const invoiceId = req.params.id;
  const invoice = await db.findById('invoices', invoiceId);
  // ❌ No check that invoice.userId === req.user.id
  res.json(invoice);
}

// VULNERABLE: Deleting records without authorization
export async function deleteDocument(req: Request, res: Response) {
  const docId = req.params.id;
  await db.deleteOne('documents', docId);
  // ❌ Any authenticated user can delete any document
  res.json({ success: true });
}

// ─── Broken Authentication ─────────────────────────────────────────────────

// VULNERABLE: Weak session token generation
export function generateSessionToken(): string {
  return Math.random().toString(36).substring(2, 15);
  // ❌ Predictable, not cryptographically random
}

// VULNERABLE: No rate limiting on login
export async function login(req: Request, res: Response) {
  const { username, password } = req.body;
  const user = await db.findUser(username);
  if (user && user.password === password) {
    // ❌ Plaintext password comparison (timing attack + no hashing)
    req.session.userId = user.id;
    res.json({ token: generateSessionToken() });
  }
}

// VULNERABLE: No auth middleware on sensitive route
export function getUserData(req: Request, res: Response) {
  const userData = db.getAllUsers();
  // ❌ No authentication check — anyone can access
  res.json(userData);
}

// VULNERABLE: JWT without expiration
export function createToken(userId: string): string {
  return jwt.sign({ userId }, JWT_SECRET);
  // ❌ No exp claim — token never expires
}
