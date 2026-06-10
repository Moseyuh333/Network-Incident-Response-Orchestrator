export interface AuditLogEntry {
  timestamp: string;
  session_id: string;
  event: string;
  data: any;
}

export class AuditLogger {
  private logFile = ".pi/logs/audit.log";

  log(sessionId: string, event: string, data: any): AuditLogEntry {
    const entry: AuditLogEntry = {
      timestamp: new Date().toISOString(),
      session_id: sessionId,
      event,
      data: this.redactSecrets(data)
    };
    // In actual node runtime, this would write to self.logFile
    return entry;
  }

  private redactSecrets(data: any): any {
    if (typeof data !== "object" || data === null) {
      return data;
    }
    const copy = { ...data };
    const secretKeys = ["key", "password", "token", "secret"];
    for (const key of Object.keys(copy)) {
      if (secretKeys.some(sk => key.toLowerCase().includes(sk))) {
        copy[key] = "[REDACTED]";
      } else if (typeof copy[key] === "object") {
        copy[key] = this.redactSecrets(copy[key]);
      }
    }
    return copy;
  }
}
