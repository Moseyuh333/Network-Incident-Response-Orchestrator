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
