/**
 * Example: Cross-Site Scripting — XSS (CWE-79)
 *
 * This file contains intentionally vulnerable code for testing AppShield.
 * DO NOT USE THIS CODE IN PRODUCTION.
 */

import React from 'react';

// VULNERABLE: dangerouslySetInnerHTML with user input
export function UserProfile({ bio }: { bio: string }) {
  return <div dangerouslySetInnerHTML={{ __html: bio }} />;
  // ❌ Attacker input: "<img src=x onerror=alert(document.cookie)>"
}

// VULNERABLE: innerHTML with user data
export function renderComment(comment: string) {
  document.getElementById('comments')!.innerHTML += comment;
  // ❌ Attacker input: "<script>stealCookies()</script>"
}

// VULNERABLE: document.write with URL params
export function renderSearch() {
  const term = new URLSearchParams(location.search).get('q');
  document.write(`<div>Results for: ${term}</div>`);
  // ❌ Reflected XSS via URL parameter
}

// VULNERABLE: Vue v-html directive equivalent
export function renderTemplate(userInput: string) {
  return { __html: userInput };
  // ❌ Unescaped HTML rendering
}
