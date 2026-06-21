"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.AuditLogger = void 0;
class AuditLogger {
    logFile = ".pi/logs/audit.log";
    log(sessionId, event, data) {
        const entry = {
            timestamp: new Date().toISOString(),
            session_id: sessionId,
            event,
            data: this.redactSecrets(data)
        };
        // In actual node runtime, this would write to self.logFile
        return entry;
    }
    redactSecrets(data) {
        if (typeof data !== "object" || data === null) {
            return data;
        }
        const copy = { ...data };
        const secretKeys = ["key", "password", "token", "secret"];
        for (const key of Object.keys(copy)) {
            if (secretKeys.some(sk => key.toLowerCase().includes(sk))) {
                copy[key] = "[REDACTED]";
            }
            else if (typeof copy[key] === "object") {
                copy[key] = this.redactSecrets(copy[key]);
            }
        }
        return copy;
    }
}
exports.AuditLogger = AuditLogger;
