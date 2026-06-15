"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.headersRule = exports.injectionRule = exports.idorRule = exports.authRule = exports.secretsRule = exports.xssRule = exports.sqlInjectionRule = exports.allRules = void 0;
exports.getRuleById = getRuleById;
exports.getRulesByIds = getRulesByIds;
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
exports.allRules = [
    sql_1.sqlInjectionRule,
    xss_1.xssRule,
    secrets_1.secretsRule,
    auth_1.authRule,
    idor_1.idorRule,
    injection_1.injectionRule,
    headers_1.headersRule,
];
function getRuleById(id) {
    return exports.allRules.find(r => r.id === id);
}
function getRulesByIds(ids) {
    if (ids.length === 0)
        return exports.allRules;
    return exports.allRules.filter(r => ids.includes(r.id));
}
function getApplicableRules(fileExtension, selectedRules) {
    return selectedRules.filter(rule => {
        if (rule.fileExtensions.includes('.*'))
            return true;
        return rule.fileExtensions.includes(fileExtension);
    });
}
//# sourceMappingURL=index.js.map