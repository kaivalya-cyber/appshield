import { allRules, getRuleById, getRulesByIds, getApplicableRules } from '../rules';
import { Rule } from '../types';

describe('Security Rules', () => {
  describe('allRules', () => {
    it('should contain exactly 14 rules', () => {
      expect(allRules).toHaveLength(14);
    });

    it('every rule should have a unique id', () => {
      const ids = allRules.map(r => r.id);
      expect(new Set(ids).size).toBe(allRules.length);
    });

    it('every rule should have required fields', () => {
      for (const rule of allRules) {
        expect(rule.id).toBeTruthy();
        expect(rule.name).toBeTruthy();
        expect(['critical', 'high', 'medium', 'low', 'info']).toContain(rule.severity);
        expect(rule.description).toBeTruthy();
        expect(rule.prompt).toBeTruthy();
        expect(rule.fileExtensions.length).toBeGreaterThan(0);
      }
    });

    it('every rule should have a CWE reference', () => {
      for (const rule of allRules) {
        expect(rule.cwe).toBeTruthy();
        expect(rule.cwe).toMatch(/^CWE-\d+$/);
      }
    });

    it('every rule should have an OWASP reference', () => {
      for (const rule of allRules) {
        expect(rule.owasp).toBeTruthy();
        expect(rule.owasp).toMatch(/^A\d{2}:2021$/);
      }
    });

    it('new rules (csrf, ssrf, open-redirect, prototype-pollution, redos, weak-crypto, insecure-deserialization) should exist', () => {
      const newRuleIds = [
        'csrf', 'ssrf', 'open-redirect', 'prototype-pollution',
        'redos', 'weak-crypto', 'insecure-deserialization',
      ];
      for (const id of newRuleIds) {
        const rule = allRules.find(r => r.id === id);
        expect(rule).toBeDefined();
      }
    });
  });

  describe('getRuleById', () => {
    it('should return undefined for non-existent rule', () => {
      expect(getRuleById('nonexistent')).toBeUndefined();
    });

    it('should return the correct rule by id', () => {
      const rule = getRuleById('sql-injection');
      expect(rule).toBeDefined();
      expect(rule!.id).toBe('sql-injection');
    });
  });

  describe('getRulesByIds', () => {
    it('should return all rules when given empty array', () => {
      expect(getRulesByIds([])).toHaveLength(allRules.length);
    });

    it('should return only the specified rules', () => {
      const result = getRulesByIds(['xss', 'csrf']);
      expect(result).toHaveLength(2);
      expect(result.map(r => r.id).sort()).toEqual(['csrf', 'xss']);
    });

    it('should skip non-existent rule ids', () => {
      const result = getRulesByIds(['xss', 'nonexistent']);
      expect(result).toHaveLength(1);
      expect(result[0].id).toBe('xss');
    });
  });

  describe('getApplicableRules', () => {
    it('should include rules with .* (match-all) extension', () => {
      const secretsRule = allRules.find(r => r.id === 'secrets')!;
      expect(secretsRule.fileExtensions).toContain('.*');
      const applicable = getApplicableRules('.xyz', [secretsRule]);
      expect(applicable).toHaveLength(1);
    });

    it('should filter rules by extension', () => {
      const sqlRule = allRules.find(r => r.id === 'sql-injection')!;
      const xssRule = allRules.find(r => r.id === 'xss')!;

      // SQL applies to .ts, XSS also applies to .tsx
      const tsxApplicable = getApplicableRules('.tsx', [sqlRule, xssRule]);
      expect(tsxApplicable).toHaveLength(1);
      expect(tsxApplicable[0].id).toBe('xss');
    });

    it('should return empty when no rules match', () => {
      const sqlRule = allRules.find(r => r.id === 'sql-injection')!;
      const applicable = getApplicableRules('.css', [sqlRule]);
      expect(applicable).toHaveLength(0);
    });
  });

  describe('rule prompts', () => {
    it('every prompt should contain JSON array instructions', () => {
      for (const rule of allRules) {
        expect(rule.prompt).toContain('JSON array');
        expect(rule.prompt).toContain('empty array []');
      }
    });

    it('every prompt should specify the output shape', () => {
      for (const rule of allRules) {
        expect(rule.prompt).toContain('"title"');
        expect(rule.prompt).toContain('"description"');
        expect(rule.prompt).toContain('"snippet"');
        expect(rule.prompt).toContain('"fix"');
      }
    });
  });

  describe('severity levels across all rules', () => {
    it('should have at least one critical rule', () => {
      const criticalRules = allRules.filter(r => r.severity === 'critical');
      expect(criticalRules.length).toBeGreaterThanOrEqual(3);
    });

    it('should have at least one high rule', () => {
      const highRules = allRules.filter(r => r.severity === 'high');
      expect(highRules.length).toBeGreaterThanOrEqual(5);
    });

    it('should have at least one medium rule', () => {
      const mediumRules = allRules.filter(r => r.severity === 'medium');
      expect(mediumRules.length).toBeGreaterThanOrEqual(2);
    });
  });
});
