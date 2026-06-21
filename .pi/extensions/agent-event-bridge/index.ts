export interface AgentEvent {
  incident_id: number;
  event_type: string;
  source: string;
  payload: any;
  timestamp: string;
}

export class AgentEventBridge {
  private apiEndpoint = "http://127.0.0.1:8000/api/v1/pipeline/events";

  async sendEvent(incidentId: number, eventType: string, source: string, payload: any): Promise<boolean> {
    const event: AgentEvent = {
      incident_id: incidentId,
      event_type: eventType,
      source,
      payload,
      timestamp: new Date().toISOString()
    };
    try {
      // In real runtime, this would do a fetch/SSE write
      return true;
    } catch {
      return false;
    }
  }
}

export default function agentEventBridgeExtension(pi: any) {
  const bridge = new AgentEventBridge();
  pi.registerCommand("niro-emit-event", {
    description: "Record a simulated N.I.R.O. agent event: /niro-emit-event <incident_id> <event_type>",
    handler: async (args: string, ctx: any) => {
      const [incidentText, eventType] = args.trim().split(/\s+/, 2);
      const incidentId = Number(incidentText);
      if (!Number.isInteger(incidentId) || incidentId < 1 || !eventType) {
        ctx.ui.notify("Usage: /niro-emit-event <incident_id> <event_type>", "warning");
        return;
      }
      const sent = await bridge.sendEvent(incidentId, eventType, "pi", { simulated: true });
      ctx.ui.notify(sent ? `Event queued: ${eventType}` : "Unable to queue event", sent ? "info" : "error");
    },
  });
}
