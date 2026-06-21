export class ContextSafety {
  private injectionPatterns = [
    /ignore\s+previous\s+instructions/i,
    /system\s+override/i,
    /you\s+are\s+now\s+an\s+attacker/i,
    /do\s+not\s+block/i
  ];

  sanitizeLogData(logLine: string, maxLength = 2000): string {
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

  wrapUntrustedData(source: string, data: string): string {
    const cleanData = this.sanitizeLogData(data);
    return `<UNTRUSTED_DATA_SOURCE source="${source}">\n${cleanData}\n</UNTRUSTED_DATA_SOURCE>`;
  }
}

export default function contextSafetyExtension(pi: any) {
  const safety = new ContextSafety();
  pi.registerCommand("niro-sanitize", {
    description: "Sanitize untrusted incident text before it is used as agent context.",
    handler: async (args: string, ctx: any) => {
      const text = args.trim();
      if (!text) {
        ctx.ui.notify("Usage: /niro-sanitize <untrusted text>", "warning");
        return;
      }
      const sanitized = safety.sanitizeLogData(text);
      ctx.ui.notify(sanitized === text ? "Context is safe" : "Unsafe context was sanitized", sanitized === text ? "info" : "warning");
    },
  });
}
