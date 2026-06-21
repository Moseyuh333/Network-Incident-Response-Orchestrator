"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.evaluateContainmentAction = evaluateContainmentAction;
function evaluateContainmentAction(action) {
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
