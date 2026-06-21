"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.ContextSafety = void 0;
class ContextSafety {
    injectionPatterns = [
        /ignore\s+previous\s+instructions/i,
        /system\s+override/i,
        /you\s+are\s+now\s+an\s+attacker/i,
        /do\s+not\s+block/i
    ];
    sanitizeLogData(logLine, maxLength = 2000) {
        let sanitized = logLine;
        // Check and flag prompt injection attempts
        for (const pattern of this.injectionPatterns) {
            if (pattern.test(sanitized)) {
                sanitized = sanitized.replace(pattern, "[PROMPT INJECTION ATTEMPT BLOCKED]");
            }
        }
        // Cap length
        if (sanitized.length > maxLength) {
            sanitized = sanitized.substring(0, maxLength) + "... [TRUNCATED FOR SAFETY]";
        }
        return sanitized;
    }
    wrapUntrustedData(source, data) {
        const cleanData = this.sanitizeLogData(data);
        return `<UNTRUSTED_DATA_SOURCE source="${source}">\n${cleanData}\n</UNTRUSTED_DATA_SOURCE>`;
    }
}
exports.ContextSafety = ContextSafety;
