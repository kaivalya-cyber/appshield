// Fixture: deliberately vulnerable code for integration testing
// Do not use this code in production!

import express from 'express';

const app = express();

// SQL Injection vulnerability (CWE-89)
app.get('/users/:id', (req, res) => {
  const query = "SELECT * FROM users WHERE id = " + req.params.id;
  // Vulnerable: user input concatenated directly into SQL query
  db.query(query);
  res.json({ status: 'ok' });
});

// Hardcoded Secret (CWE-798)
const API_KEY = "sk-live-abc123def456ghi789jkl012mno345pqr678stu";

// XSS vulnerability (CWE-79)
app.get('/search', (req, res) => {
  const term = req.query.q;
  res.send(`<div>Results for: ${term}</div>`);
  // Vulnerable: user input rendered directly in HTML without escaping
});

// Weak Cryptography (CWE-327)
import crypto from 'crypto';
const hash = crypto.createHash('md5').update('password123').digest('hex');

export default app;
