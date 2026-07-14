import { Rule } from '../types';
import { sqlInjectionRule } from './sql';
import { xssRule } from './xss';
import { secretsRule } from './secrets';
import { authRule } from './auth';
import { idorRule } from './idor';
import { injectionRule } from './injection';
import { headersRule } from './headers';
import { csrfRule } from './csrf';
import { ssrfRule } from './ssrf';
import { openRedirectRule } from './open_redirect';
import { prototypePollutionRule } from './prototype_pollution';
import { redosRule } from './redos';
import { weakCryptoRule } from './weak_crypto';
import { insecureDeserializationRule } from './insecure_deserialization';

export const allRules: Rule[] = [
  sqlInjectionRule,
  xssRule,
  secretsRule,
  authRule,
  idorRule,
  injectionRule,
  headersRule,
  csrfRule,
  ssrfRule,
  openRedirectRule,
  prototypePollutionRule,
  redosRule,
  weakCryptoRule,
  insecureDeserializationRule,
];

export function getRuleById(id: string): Rule | undefined {
  return allRules.find(r => r.id === id);
}

export function getRulesByIds(ids: string[]): Rule[] {
  if (ids.length === 0) return allRules;
  return allRules.filter(r => ids.includes(r.id));
}

export function getApplicableRules(fileExtension: string, selectedRules: Rule[]): Rule[] {
  return selectedRules.filter(rule => {
    if (rule.fileExtensions.includes('.*')) return true;
    return rule.fileExtensions.includes(fileExtension);
  });
}

export {
  sqlInjectionRule,
  xssRule,
  secretsRule,
  authRule,
  idorRule,
  injectionRule,
  headersRule,
  csrfRule,
  ssrfRule,
  openRedirectRule,
  prototypePollutionRule,
  redosRule,
  weakCryptoRule,
  insecureDeserializationRule,
};
