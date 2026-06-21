export interface PermissionDecision {
  action: string;
  allowed: boolean;
  reason: string;
}

export class SecurityPermissionGate {
  private protectedCidrs = ["127.0.0.0/8", "10.0.0.1", "192.168.1.1"];
  
  evaluate(action: string, target: string): PermissionDecision {
    if (!action.startsWith("simulate_")) {
      return {
        action,
        allowed: false,
        reason: "Only simulated actions are allowed in lab mode."
      };
    }

    if (this.protectedCidrs.some(cidr => target.includes(cidr))) {
      return {
        action,
        allowed: false,
        reason: `Target ${target} is a protected asset or management address.`
      };
    }

    const requiresApproval = ["simulate_block_ip", "simulate_quarantine_host", "simulate_disable_user"];
    if (requiresApproval.includes(action)) {
      return {
        action,
        allowed: true,
        reason: "Simulated action allowed but requires human operator approval."
      };
    }

    return {
      action,
      allowed: true,
      reason: "Action is low risk and automatically approved."
    };
  }
}

export default function securityPermissionGateExtension(pi: any) {
  const gate = new SecurityPermissionGate();
  pi.registerCommand("niro-check-target", {
    description: "Check a simulated containment action against protected assets: /niro-check-target <action> <target>",
    handler: async (args: string, ctx: any) => {
      const [action, target] = args.trim().split(/\s+/, 2);
      if (!action || !target) {
        ctx.ui.notify("Usage: /niro-check-target <action> <target>", "warning");
        return;
      }
      const decision = gate.evaluate(action, target);
      ctx.ui.notify(`${decision.allowed ? "ALLOWED" : "BLOCKED"}: ${decision.reason}`, decision.allowed ? "info" : "warning");
    },
  });
}
