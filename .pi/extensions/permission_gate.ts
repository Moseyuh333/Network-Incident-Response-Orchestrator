export type GateDecision = {
  action: string;
  decision: "allowed" | "blocked";
  reason: string;
};

export function evaluateContainmentAction(action: string): GateDecision {
  if (action.startsWith("simulate_")) {
    return {
      action,
      decision: "allowed",
      reason: "Simulated lab action; no real infrastructure change.",
    };
  }

  return {
    action,
    decision: "blocked",
    reason: "Real containment requires explicit lab approval.",
  };
}

export default function permissionGateExtension(pi: any) {
  pi.registerCommand("niro-check-action", {
    description: "Check whether a N.I.R.O. containment action is permitted in lab mode.",
    handler: async (args: string, ctx: any) => {
      const action = args.trim();
      if (!action) {
        ctx.ui.notify("Usage: /niro-check-action <action>", "warning");
        return;
      }
      const decision = evaluateContainmentAction(action);
      ctx.ui.notify(`${decision.decision.toUpperCase()}: ${decision.reason}`, decision.decision === "allowed" ? "info" : "warning");
    },
  });
}
