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
