"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.insecureDeserializationRule = exports.weakCryptoRule = exports.redosRule = exports.prototypePollutionRule = exports.openRedirectRule = exports.ssrfRule = exports.csrfRule = exports.headersRule = exports.injectionRule = exports.idorRule = exports.authRule = exports.secretsRule = exports.xssRule = exports.sqlInjectionRule = exports.RULESET_PRESETS = exports.allRules = void 0;
exports.getRuleById = getRuleById;
exports.getRulesByIds = getRulesByIds;
exports.resolvePreset = resolvePreset;
exports.getApplicableRules = getApplicableRules;
const sql_1 = require("./sql");
Object.defineProperty(exports, "sqlInjectionRule", { enumerable: true, get: function () { return sql_1.sqlInjectionRule; } });
const xss_1 = require("./xss");
Object.defineProperty(exports, "xssRule", { enumerable: true, get: function () { return xss_1.xssRule; } });
const secrets_1 = require("./secrets");
Object.defineProperty(exports, "secretsRule", { enumerable: true, get: function () { return secrets_1.secretsRule; } });
const auth_1 = require("./auth");
Object.defineProperty(exports, "authRule", { enumerable: true, get: function () { return auth_1.authRule; } });
const idor_1 = require("./idor");
Object.defineProperty(exports, "idorRule", { enumerable: true, get: function () { return idor_1.idorRule; } });
const injection_1 = require("./injection");
Object.defineProperty(exports, "injectionRule", { enumerable: true, get: function () { return injection_1.injectionRule; } });
const headers_1 = require("./headers");
Object.defineProperty(exports, "headersRule", { enumerable: true, get: function () { return headers_1.headersRule; } });
const csrf_1 = require("./csrf");
Object.defineProperty(exports, "csrfRule", { enumerable: true, get: function () { return csrf_1.csrfRule; } });
const ssrf_1 = require("./ssrf");
Object.defineProperty(exports, "ssrfRule", { enumerable: true, get: function () { return ssrf_1.ssrfRule; } });
const open_redirect_1 = require("./open_redirect");
Object.defineProperty(exports, "openRedirectRule", { enumerable: true, get: function () { return open_redirect_1.openRedirectRule; } });
const prototype_pollution_1 = require("./prototype_pollution");
Object.defineProperty(exports, "prototypePollutionRule", { enumerable: true, get: function () { return prototype_pollution_1.prototypePollutionRule; } });
const redos_1 = require("./redos");
Object.defineProperty(exports, "redosRule", { enumerable: true, get: function () { return redos_1.redosRule; } });
const weak_crypto_1 = require("./weak_crypto");
Object.defineProperty(exports, "weakCryptoRule", { enumerable: true, get: function () { return weak_crypto_1.weakCryptoRule; } });
const insecure_deserialization_1 = require("./insecure_deserialization");
Object.defineProperty(exports, "insecureDeserializationRule", { enumerable: true, get: function () { return insecure_deserialization_1.insecureDeserializationRule; } });
exports.allRules = [
    sql_1.sqlInjectionRule,
    xss_1.xssRule,
    secrets_1.secretsRule,
    auth_1.authRule,
    idor_1.idorRule,
    injection_1.injectionRule,
    headers_1.headersRule,
    csrf_1.csrfRule,
    ssrf_1.ssrfRule,
    open_redirect_1.openRedirectRule,
    prototype_pollution_1.prototypePollutionRule,
    redos_1.redosRule,
    weak_crypto_1.weakCryptoRule,
    insecure_deserialization_1.insecureDeserializationRule,
];
function getRuleById(id) {
    return exports.allRules.find(r => r.id === id);
}
function getRulesByIds(ids) {
    if (ids.length === 0)
        return exports.allRules;
    return exports.allRules.filter(r => ids.includes(r.id));
}
/** Named presets that select rule subsets */
exports.RULESET_PRESETS = {
    'owasp-top10': [
        'sql-injection', 'xss', 'injection', 'insecure-deserialization',
        'secrets', 'auth', 'idor', 'csrf', 'ssrf', 'weak-crypto',
    ],
    'critical-only': ['sql-injection', 'xss', 'injection', 'insecure-deserialization'],
    'web-app': [
        'sql-injection', 'xss', 'injection', 'secrets', 'auth',
        'idor', 'csrf', 'ssrf', 'headers', 'open-redirect',
    ],
};
function resolvePreset(preset) {
    return exports.RULESET_PRESETS[preset];
}
function getApplicableRules(fileExtension, selectedRules) {
    return selectedRules.filter(rule => {
        if (rule.fileExtensions.includes('.*'))
            return true;
        return rule.fileExtensions.includes(fileExtension);
    });
}
//# sourceMappingURL=index.js.map