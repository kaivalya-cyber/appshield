import { Rule } from '../types';
import { sqlInjectionRule } from './sql';
import { xssRule } from './xss';
import { secretsRule } from './secrets';
import { authRule } from './auth';
import { idorRule } from './idor';
import { injectionRule } from './injection';
import { headersRule } from './headers';
export declare const allRules: Rule[];
export declare function getRuleById(id: string): Rule | undefined;
export declare function getRulesByIds(ids: string[]): Rule[];
export declare function getApplicableRules(fileExtension: string, selectedRules: Rule[]): Rule[];
export { sqlInjectionRule, xssRule, secretsRule, authRule, idorRule, injectionRule, headersRule, };
//# sourceMappingURL=index.d.ts.map