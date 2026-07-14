/**
 * Example: SQL Injection (CWE-89)
 * 
 * This file contains intentionally vulnerable code for testing AppShield.
 * DO NOT USE THIS CODE IN PRODUCTION.
 */

import { Request, Response } from 'express';

// VULNERABLE: String concatenation in SQL query
export function getUserById(req: Request, res: Response) {
  const id = req.params.id;
  const query = "SELECT * FROM users WHERE id = " + id;
  db.execute(query); // ❌ Attacker input: "1 OR 1=1" dumps all users
}

// VULNERABLE: Template literal in SQL query
export function searchUsers(req: Request, res: Response) {
  const term = req.query.q;
  const query = `SELECT * FROM users WHERE name LIKE '%${term}%'`;
  db.query(query); // ❌ Attacker input: "'; DROP TABLE users; --"
}

// VULNERABLE: ORM escape bypass
export function getByStatus(req: Request, res: Response) {
  const status = req.query.status;
  const results = db.raw(`SELECT * FROM orders WHERE status = '${status}'`);
  // ❌ Raw query with unsanitized input
}
