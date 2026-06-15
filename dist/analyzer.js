"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.analyzeCode = analyzeCode;
const sdk_1 = __importDefault(require("@anthropic-ai/sdk"));
let client = null;
function getClient() {
    if (!client) {
        const apiKey = process.env.ANTHROPIC_API_KEY;
        if (!apiKey || apiKey === 'your_key_here') {
            console.error('\n❌ Missing ANTHROPIC_API_KEY.\n\n' +
                '   1. Copy .env.example to .env\n' +
                '   2. Replace "your_key_here" with your actual API key\n' +
                '   3. Get a key at https://console.anthropic.com/\n');
            process.exit(1);
        }
        client = new sdk_1.default({ apiKey });
    }
    return client;
}
/**
 * Analyze a code chunk against a specific rule using Claude.
 * Returns an array of vulnerabilities found.
 */
async function analyzeCode(code, filePath, rule, debug = false, retryCount = 0) {
    const anthropic = getClient();
    const userMessage = `File: ${filePath}\n\n<code>\n${code}\n</code>`;
    try {
        const response = await anthropic.messages.create({
            model: 'claude-sonnet-4-20250514',
            max_tokens: 4096,
            system: rule.prompt,
            messages: [
                { role: 'user', content: userMessage }
            ],
        });
        const content = response.content[0];
        if (content.type !== 'text') {
            if (debug) {
                console.error(`[DEBUG] Non-text response for ${filePath} + ${rule.id}`);
            }
            return { vulnerabilities: [], tokensUsed: 0 };
        }
        const rawText = content.text.trim();
        const tokensUsed = (response.usage?.input_tokens || 0) + (response.usage?.output_tokens || 0);
        // Try to extract JSON from the response
        let findings;
        try {
            findings = JSON.parse(rawText);
        }
        catch {
            // Try to extract JSON array from surrounding text
            const jsonMatch = rawText.match(/\[[\s\S]*\]/);
            if (jsonMatch) {
                try {
                    findings = JSON.parse(jsonMatch[0]);
                }
                catch {
                    if (debug) {
                        console.error(`[DEBUG] Malformed JSON response for ${filePath} + ${rule.id}:`);
                        console.error(rawText.substring(0, 500));
                    }
                    return { vulnerabilities: [], tokensUsed };
                }
            }
            else {
                if (debug) {
                    console.error(`[DEBUG] No JSON found in response for ${filePath} + ${rule.id}:`);
                    console.error(rawText.substring(0, 500));
                }
                return { vulnerabilities: [], tokensUsed };
            }
        }
        if (!Array.isArray(findings)) {
            if (debug) {
                console.error(`[DEBUG] Response is not an array for ${filePath} + ${rule.id}`);
            }
            return { vulnerabilities: [], tokensUsed };
        }
        // Validate and transform findings into Vulnerability objects
        const vulnerabilities = [];
        let counter = 1;
        for (const finding of findings) {
            if (!finding.title || !finding.description || !finding.snippet || !finding.fix) {
                if (debug) {
                    console.error(`[DEBUG] Skipping malformed finding:`, JSON.stringify(finding).substring(0, 200));
                }
                continue;
            }
            const id = `${rule.id.toUpperCase().replace(/-/g, '_')}_${String(counter).padStart(3, '0')}`;
            vulnerabilities.push({
                id,
                rule: rule.id,
                severity: rule.severity,
                title: finding.title,
                description: finding.description,
                file: filePath,
                line: typeof finding.line === 'number' ? finding.line : undefined,
                snippet: finding.snippet,
                fix: finding.fix,
                cwe: rule.cwe,
                owasp: rule.owasp,
            });
            counter++;
        }
        return { vulnerabilities, tokensUsed };
    }
    catch (error) {
        // Handle rate limiting with exponential backoff
        if (error?.status === 429 && retryCount < 3) {
            const delay = Math.pow(2, retryCount) * 1000; // 1s, 2s, 4s
            if (debug) {
                console.error(`[DEBUG] Rate limited on ${filePath} + ${rule.id}. Retrying in ${delay}ms (attempt ${retryCount + 1}/3)`);
            }
            await sleep(delay);
            return analyzeCode(code, filePath, rule, debug, retryCount + 1);
        }
        // Handle network timeouts with single retry
        if ((error?.code === 'ETIMEDOUT' || error?.code === 'ECONNRESET' || error?.message?.includes('timeout')) && retryCount < 1) {
            if (debug) {
                console.error(`[DEBUG] Network timeout on ${filePath} + ${rule.id}. Retrying once...`);
            }
            await sleep(2000);
            return analyzeCode(code, filePath, rule, debug, retryCount + 1);
        }
        // Rate limit exhausted after retries
        if (error?.status === 429) {
            console.warn(`⚠ Rate limit: skipping ${filePath} (${rule.name}) after 3 retries`);
            return { vulnerabilities: [], tokensUsed: 0 };
        }
        // API errors
        if (error?.status) {
            console.warn(`⚠ API error (${error.status}): skipping ${filePath} (${rule.name})`);
            if (debug) {
                console.error(`[DEBUG] Full error:`, error.message);
            }
            return { vulnerabilities: [], tokensUsed: 0 };
        }
        // Network errors
        console.warn(`⚠ Network error: skipping ${filePath} (${rule.name}) — ${error?.message || 'unknown error'}`);
        return { vulnerabilities: [], tokensUsed: 0 };
    }
}
function sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
}
//# sourceMappingURL=analyzer.js.map