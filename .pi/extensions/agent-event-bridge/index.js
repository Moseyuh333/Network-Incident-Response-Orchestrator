"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.AgentEventBridge = void 0;
class AgentEventBridge {
    apiEndpoint = "http://127.0.0.1:8000/api/v1/pipeline/events";
    async sendEvent(incidentId, eventType, source, payload) {
        const event = {
            incident_id: incidentId,
            event_type: eventType,
            source,
            payload,
            timestamp: new Date().toISOString()
        };
        try {
            // In real runtime, this would do a fetch/SSE write
            return true;
        }
        catch {
            return false;
        }
    }
}
exports.AgentEventBridge = AgentEventBridge;
