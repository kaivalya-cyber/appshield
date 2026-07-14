/**
 * Example: CSRF (CWE-352) & SSRF (CWE-918)
 *
 * This file contains intentionally vulnerable code for testing AppShield.
 * DO NOT USE THIS CODE IN PRODUCTION.
 */

import { Request, Response } from 'express';
import axios from 'axios';
import * as http from 'http';

// ─── CSRF Vulnerabilities ──────────────────────────────────────────────────

// VULNERABLE: State-changing endpoint without CSRF protection
export function transferMoney(req: Request, res: Response) {
  const { to, amount } = req.body;
  // ❌ No CSRF token validation — attacker can forge requests
  processTransfer(req.user.id, to, amount);
  res.json({ success: true });
}

// VULNERABLE: Form without CSRF token
export function renderTransferForm(res: Response) {
  res.send(`
    <form method="POST" action="/transfer">
      <input name="to" />
      <input name="amount" />
      <button type="submit">Transfer</button>
    </form>
  `);
  // ❌ Missing CSRF token in form
}

// ─── SSRF Vulnerabilities ──────────────────────────────────────────────────

// VULNERABLE: Fetching user-supplied URL
export async function fetchWebhook(req: Request, res: Response) {
  const url = req.query.url as string;
  const response = await axios.get(url);
  // ❌ Attacker input: "http://169.254.169.254/latest/meta-data/"
  res.json(response.data);
}

// VULNERABLE: Image proxy without URL validation
export function proxyImage(req: Request, res: Response) {
  const imageUrl = req.query.src as string;
  http.get(imageUrl, (imageRes) => {
    imageRes.pipe(res);
  });
  // ❌ Attacker can probe internal network services
}
