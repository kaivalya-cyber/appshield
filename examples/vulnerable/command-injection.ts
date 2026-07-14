/**
 * Example: Command Injection & Path Traversal (CWE-78, CWE-22)
 *
 * This file contains intentionally vulnerable code for testing AppShield.
 * DO NOT USE THIS CODE IN PRODUCTION.
 */

import { exec, execSync } from 'child_process';
import * as fs from 'fs';
import { Request, Response } from 'express';

// VULNERABLE: Command injection via exec with user input
export function pingHost(req: Request, res: Response) {
  const host = req.query.host;
  exec(`ping -c 4 ${host}`, (err, stdout) => {
    res.send(stdout);
  });
  // ❌ Attacker input: "8.8.8.8; rm -rf /"
}

// VULNERABLE: execSync with user-controlled arguments
export function convertImage(req: Request, res: Response) {
  const filename = req.query.file;
  const output = execSync(`convert ${filename} output.png`);
  // ❌ Attacker input: "image.jpg; cat /etc/passwd"
}

// VULNERABLE: Path traversal in file read
export function readFile(req: Request, res: Response) {
  const filename = req.query.file;
  const content = fs.readFileSync(`./uploads/${filename}`, 'utf-8');
  // ❌ Attacker input: "../../../etc/passwd"
}

// VULNERABLE: eval with user input
export function calculate(req: Request, res: Response) {
  const expression = req.query.expr;
  const result = eval(expression as string);
  // ❌ Attacker input: "process.exit()" or "require('child_process').exec('rm -rf /')"
}
