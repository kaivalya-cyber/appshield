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
export declare const allRules: Rule[];
export declare function getRuleById(id: string): Rule | undefined;
export declare function getRulesByIds(ids: string[]): Rule[];
/** Named presets that select rule subsets */
export declare const RULESET_PRESETS: Record<string, string[]>;
export declare function resolvePreset(preset: string): string[] | undefined;
export declare function getApplicableRules(fileExtension: string, selectedRules: Rule[]): Rule[];
export { sqlInjectionRule, xssRule, secretsRule, authRule, idorRule, injectionRule, headersRule, csrfRule, ssrfRule, openRedirectRule, prototypePollutionRule, redosRule, weakCryptoRule, insecureDeserializationRule, };
//# sourceMappingURL=index.d.ts.map