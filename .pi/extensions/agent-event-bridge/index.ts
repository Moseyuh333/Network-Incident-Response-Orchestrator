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
