import React, { useCallback, useEffect, useMemo, useState } from "react";
import { createRoot } from "react-dom/client";
import {
  Activity,
  Bot,
  CheckCircle2,
  FileCode2,
  Network,
  Play,
  RefreshCw,
  RotateCcw,
  ShieldAlert,
  Wrench
} from "lucide-react";
import {
  Area,
  AreaChart,
  Bar,
  BarChart,
  CartesianGrid,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis
} from "recharts";
import cytoscape from "cytoscape";
import "./styles.css";

type StatusPayload = {
  app: string;
  version: string;
  llm: { provider: string; model: string; configured: boolean };
  sample_alert: Record<string, unknown>;
  resources: ResourceIndex;
};

type DashboardStats = {
  total_events: number;
  events_last_24h: number;
  total_incidents: number;
  open_incidents: number;
  pending_approvals: number;
  findings: number;
  audit_entries: number;
};

type Incident = {
  id: number;
  public_id: string;
  title: string;
  incident_type: string;
  severity: string;
  confidence: number;
  status: string;
  source_ip?: string;
  destination_ip?: string;
  summary?: string;
  llm_summary?: string;
  llm_report?: string;
  evidence?: Array<Record<string, unknown>>;
  updated_at?: string;
};

type Action = {
  id: number;
  incident_id: number;
  action_type: string;
  risk: string;
  status: string;
  requires_approval: boolean;
  arguments?: Record<string, unknown>;
};

type ResourceIndex = {
  skills: Array<{ name: string; path: string }>;
  plugins: Array<{ name: string; path: string }>;
};

type ChatMessage = {
  role: "operator" | "agent";
  body: string;
  meta?: string;
};

type LiveSnapshot = {
  stats: DashboardStats;
  incidents: Incident[];
  actions: Action[];
};

const severityOrder: Record<string, number> = { critical: 4, high: 3, medium: 2, low: 1 };

async function api<T>(url: string, init?: RequestInit): Promise<T> {
  const response = await fetch(url, {
    headers: { "Content-Type": "application/json" },
    ...init
  });
  if (!response.ok) {
    const text = await response.text();
    throw new Error(text || response.statusText);
  }
  return response.json() as Promise<T>;
}

function App() {
  const [status, setStatus] = useState<StatusPayload | null>(null);
  const [stats, setStats] = useState<DashboardStats | null>(null);
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [actions, setActions] = useState<Action[]>([]);
  const [selectedIncidentId, setSelectedIncidentId] = useState<number | null>(null);
  const [messages, setMessages] = useState<ChatMessage[]>([
    {
      role: "agent",
      body: "Ready. Analyze an alert, run the agent on an incident, or review pending approvals."
    }
  ]);
  const [command, setCommand] = useState("agent incident 1 contain source in simulation mode");
  const [alertInput, setAlertInput] = useState("{}");
  const [resourceKind, setResourceKind] = useState<"skills" | "plugins">("skills");
  const [resourceName, setResourceName] = useState("");
  const [resourceBody, setResourceBody] = useState("");
  const [busy, setBusy] = useState(false);

  const selectedIncident = incidents.find((incident) => incident.id === selectedIncidentId) ?? incidents[0];
  const pendingActions = actions.filter((action) => action.status === "awaiting_approval");

  const refresh = useCallback(async () => {
    const [nextStatus, nextStats, nextIncidents, nextActions] = await Promise.all([
      api<StatusPayload>("/api/status"),
      api<DashboardStats>("/api/v1/dashboard/stats"),
      api<Incident[]>("/api/v1/incidents"),
      api<Action[]>("/api/v1/actions")
    ]);
    setStatus(nextStatus);
    setStats(nextStats);
    setIncidents(nextIncidents);
    setActions(nextActions);
    setAlertInput(JSON.stringify(nextStatus.sample_alert, null, 2));
    if (!selectedIncidentId && nextIncidents[0]) {
      setSelectedIncidentId(nextIncidents[0].id);
      setCommand(`agent incident ${nextIncidents[0].id} contain source in simulation mode`);
    }
  }, [selectedIncidentId]);

  useEffect(() => {
    refresh().catch((error) => {
      setMessages((current) => [...current, { role: "agent", body: error.message, meta: "load error" }]);
    });
  }, [refresh]);

  useEffect(() => {
    const stream = new EventSource("/api/v1/live/events");
    stream.addEventListener("snapshot", (event) => {
      const snapshot = JSON.parse((event as MessageEvent).data) as LiveSnapshot;
      setStats(snapshot.stats);
      setIncidents(snapshot.incidents);
      setActions(snapshot.actions);
    });
    stream.onerror = () => {
      stream.close();
    };
    return () => stream.close();
  }, []);

  useEffect(() => {
    if (!selectedIncident) return;
    const container = document.getElementById("graph");
    if (!container) return;
    const graph = cytoscape({
      container,
      elements: [
        { data: { id: "incident", label: selectedIncident.public_id || `INC-${selectedIncident.id}` } },
        { data: { id: "source", label: selectedIncident.source_ip || "unknown source" } },
        { data: { id: "dest", label: selectedIncident.destination_ip || "unknown target" } },
        { data: { id: "src-edge", source: "source", target: "incident" } },
        { data: { id: "dst-edge", source: "incident", target: "dest" } }
      ],
      style: [
        {
          selector: "node",
          style: {
            "background-color": "#0f766e",
            label: "data(label)",
            color: "#101828",
            "font-size": "10px",
            "text-wrap": "wrap",
            "text-max-width": "90px"
          }
        },
        {
          selector: "edge",
          style: { width: 2, "line-color": "#94a3b8", "target-arrow-color": "#94a3b8" }
        }
      ],
      layout: { name: "grid", rows: 1 }
    });
    return () => graph.destroy();
  }, [selectedIncident]);

  const chartData = useMemo(() => {
    const buckets = new Map<string, number>();
    for (const incident of incidents) {
      buckets.set(incident.severity, (buckets.get(incident.severity) ?? 0) + 1);
    }
    return ["critical", "high", "medium", "low"].map((severity) => ({
      severity,
      count: buckets.get(severity) ?? 0
    }));
  }, [incidents]);

  const trendData = useMemo(
    () => [
      { name: "Events", value: stats?.total_events ?? 0 },
      { name: "Findings", value: stats?.findings ?? 0 },
      { name: "Incidents", value: stats?.total_incidents ?? 0 },
      { name: "Approvals", value: stats?.pending_approvals ?? 0 }
    ],
    [stats]
  );

  async function sendCommand() {
    if (!command.trim()) return;
    setBusy(true);
    setMessages((current) => [...current, { role: "operator", body: command }]);
    try {
      let parsedAlert: Record<string, unknown> | null = null;
      if (alertInput.trim()) parsedAlert = JSON.parse(alertInput);
      const result = await api<Record<string, unknown>>("/api/chat", {
        method: "POST",
        body: JSON.stringify({ command, alert: parsedAlert })
      });
      setMessages((current) => [
        ...current,
        {
          role: "agent",
          body: String(result.assistant ?? "Command completed."),
          meta: String(result.mode ?? "chat")
        }
      ]);
      await refresh();
    } catch (error) {
      setMessages((current) => [
        ...current,
        { role: "agent", body: error instanceof Error ? error.message : String(error), meta: "error" }
      ]);
    } finally {
      setBusy(false);
    }
  }

  async function loadResource(kind: "skills" | "plugins", name: string) {
    const resource = await api<{ content: string }>(`/api/resources/${kind}/${encodeURIComponent(name)}`);
    setResourceKind(kind);
    setResourceName(name);
    setResourceBody(resource.content);
  }

  async function saveResource() {
    if (!resourceName.trim()) return;
    await api(`/api/resources/${resourceKind}/${encodeURIComponent(resourceName)}`, {
      method: "PUT",
      body: JSON.stringify({ name: resourceName, content: resourceBody })
    });
    await refresh();
  }

  async function actionCommand(action: Action, commandName: "approve" | "execute" | "rollback") {
    await api(`/api/v1/actions/${action.id}/${commandName}`, { method: "POST" });
    await refresh();
  }

  return (
    <main className="app-shell">
      <aside className="nav">
        <div className="brand">
          <div className="brand-mark">NI</div>
          <div>
            <h1>NIRO SOC</h1>
            <p>{status?.llm.configured ? "Live LLM configured" : "Fallback mode"}</p>
          </div>
        </div>
        <button className="nav-action" onClick={() => void refresh()}>
          <RefreshCw size={16} /> Refresh
        </button>
        <section>
          <h2>Queue</h2>
          <div className="queue-list">
            {incidents.slice(0, 9).map((incident) => (
              <button
                key={incident.id}
                className={incident.id === selectedIncident?.id ? "incident active" : "incident"}
                onClick={() => {
                  setSelectedIncidentId(incident.id);
                  setCommand(`agent incident ${incident.id} contain source in simulation mode`);
                }}
              >
                <span>{incident.public_id || `INC-${incident.id}`}</span>
                <strong>{incident.severity}</strong>
              </button>
            ))}
          </div>
        </section>
      </aside>

      <section className="workspace">
        <header className="topbar">
          <div>
            <h2>Incident Command Workspace</h2>
            <p>{status?.llm.provider ?? "provider"} / {status?.llm.model ?? "model"}</p>
          </div>
          <div className="status-chip">
            <Activity size={16} />
            {stats?.open_incidents ?? 0} open
          </div>
        </header>

        <section className="cards">
          <Metric icon={<Network size={18} />} label="Events" value={stats?.total_events ?? 0} />
          <Metric icon={<ShieldAlert size={18} />} label="Findings" value={stats?.findings ?? 0} />
          <Metric icon={<Bot size={18} />} label="Incidents" value={stats?.total_incidents ?? 0} />
          <Metric icon={<CheckCircle2 size={18} />} label="Approvals" value={pendingActions.length} />
        </section>

        <section className="work-grid">
          <Panel title="Agent Chat" icon={<Bot size={17} />} className="chat-panel">
            <div className="messages">
              {messages.map((message, index) => (
                <div key={`${message.role}-${index}`} className={`msg ${message.role}`}>
                  <span>{message.role === "operator" ? "Operator" : "Pi agent"} {message.meta ? `· ${message.meta}` : ""}</span>
                  <p>{message.body}</p>
                </div>
              ))}
            </div>
            <div className="composer">
              <textarea value={command} onChange={(event) => setCommand(event.target.value)} />
              <button onClick={() => void sendCommand()} disabled={busy}>
                <Play size={16} /> Send
              </button>
            </div>
          </Panel>

          <Panel title="Incident Detail" icon={<ShieldAlert size={17} />}>
            {selectedIncident ? (
              <div className="detail">
                <div className="detail-head">
                  <h3>{selectedIncident.title}</h3>
                  <span className={`badge ${selectedIncident.severity}`}>{selectedIncident.severity}</span>
                </div>
                <dl>
                  <div><dt>Status</dt><dd>{selectedIncident.status}</dd></div>
                  <div><dt>Type</dt><dd>{selectedIncident.incident_type}</dd></div>
                  <div><dt>Source</dt><dd>{selectedIncident.source_ip ?? "-"}</dd></div>
                  <div><dt>Target</dt><dd>{selectedIncident.destination_ip ?? "-"}</dd></div>
                </dl>
                <p className="summary">{selectedIncident.llm_summary || selectedIncident.summary || "No summary yet."}</p>
                <div id="graph" className="graph" />
              </div>
            ) : (
              <p className="empty">No incident selected.</p>
            )}
          </Panel>

          <Panel title="Detection Mix" icon={<Activity size={17} />}>
            <ResponsiveContainer width="100%" height={210}>
              <BarChart data={chartData}>
                <CartesianGrid strokeDasharray="3 3" vertical={false} />
                <XAxis dataKey="severity" />
                <YAxis allowDecimals={false} />
                <Tooltip />
                <Bar dataKey="count" fill="#0f766e" radius={[4, 4, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </Panel>

          <Panel title="SOC Load" icon={<Activity size={17} />}>
            <ResponsiveContainer width="100%" height={210}>
              <AreaChart data={trendData}>
                <CartesianGrid strokeDasharray="3 3" vertical={false} />
                <XAxis dataKey="name" />
                <YAxis allowDecimals={false} />
                <Tooltip />
                <Area dataKey="value" stroke="#1d4ed8" fill="#bfdbfe" />
              </AreaChart>
            </ResponsiveContainer>
          </Panel>
        </section>
      </section>

      <aside className="right-rail">
        <Panel title="Approval Queue" icon={<CheckCircle2 size={17} />}>
          <div className="approval-list">
            {pendingActions.map((action) => (
              <div key={action.id} className="approval">
                <strong>{action.action_type}</strong>
                <span>{action.risk} risk · incident {action.incident_id}</span>
                <div className="approval-actions">
                  <button onClick={() => void actionCommand(action, "approve")}>Approve</button>
                  <button onClick={() => void actionCommand(action, "execute")}>Execute</button>
                </div>
              </div>
            ))}
            {!pendingActions.length && <p className="empty">No pending approvals.</p>}
          </div>
        </Panel>

        <Panel title="Skills & Plugins" icon={<Wrench size={17} />}>
          <div className="resource-tabs">
            <button className={resourceKind === "skills" ? "active" : ""} onClick={() => setResourceKind("skills")}>Skills</button>
            <button className={resourceKind === "plugins" ? "active" : ""} onClick={() => setResourceKind("plugins")}>Plugins</button>
          </div>
          <div className="resource-list">
            {(status?.resources[resourceKind] ?? []).map((resource) => (
              <button key={resource.name} onClick={() => void loadResource(resourceKind, resource.name)}>
                <FileCode2 size={14} /> {resource.name}
              </button>
            ))}
          </div>
          <input value={resourceName} onChange={(event) => setResourceName(event.target.value)} placeholder="manifest.json" />
          <textarea value={resourceBody} onChange={(event) => setResourceBody(event.target.value)} />
          <button onClick={() => void saveResource()}>Save resource</button>
        </Panel>

        <Panel title="Alert Input" icon={<ShieldAlert size={17} />}>
          <textarea className="alert-input" value={alertInput} onChange={(event) => setAlertInput(event.target.value)} />
        </Panel>
      </aside>
    </main>
  );
}

function Metric({ icon, label, value }: { icon: React.ReactNode; label: string; value: number }) {
  return (
    <div className="metric">
      <span>{icon}</span>
      <div>
        <p>{label}</p>
        <strong>{value}</strong>
      </div>
    </div>
  );
}

function Panel({
  title,
  icon,
  className = "",
  children
}: {
  title: string;
  icon: React.ReactNode;
  className?: string;
  children: React.ReactNode;
}) {
  return (
    <section className={`panel ${className}`}>
      <header>
        <span>{icon}</span>
        <h3>{title}</h3>
      </header>
      {children}
    </section>
  );
}

createRoot(document.getElementById("root")!).render(<App />);
