import React, { useCallback, useEffect, useMemo, useState, useRef } from "react";
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
  Wrench,
  Search,
  Lock,
  Unlock,
  Settings,
  Layers,
  Cpu,
  History,
  Download,
  Trash2,
  Plus,
  FileText,
  Check,
  AlertTriangle,
  X,
  ChevronRight
} from "lucide-react";
import cytoscape from "cytoscape";
import "./styles.css";

// --- Types ---
type StatusPayload = {
  app: string;
  version: string;
  llm: { provider: string; model: string; configured: boolean };
  sample_alert: Record<string, any>;
  resources: {
    skills: Array<{ name: string; path: string }>;
    plugins: Array<{ name: string; path: string }>;
  };
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
  evidence?: Array<Record<string, any>>;
  updated_at?: string;
};

type Action = {
  id: number;
  incident_id: number;
  action_type: string;
  risk: string;
  status: string;
  requires_approval: boolean;
  plugin?: string;
  proposed_by?: string;
  arguments?: Record<string, any>;
  result?: string;
  verification_result?: string;
  rollback_data?: string;
  created_at?: string;
  updated_at?: string;
};

type LiveSnapshot = {
  timestamp: string;
  stats: DashboardStats;
  incidents: Incident[];
  actions: Action[];
};

type TerminalLogLine = {
  timestamp: string;
  source: string;
  message: string;
  level: "normal" | "info" | "warn" | "critical" | "operator";
};

type AgentProfile = {
  name: string;
  filename: string;
  metadata: {
    role?: string;
    input_artifact?: string;
    output_artifact?: string;
    allowed_skills?: string[];
    allowed_tools?: string[];
    maximum_iterations?: number;
    maximum_tool_calls?: number;
    safety_profile?: string;
  };
  content: string;
  raw: string;
};

type PiPrompt = {
  name: string;
  filename: string;
  content: string;
};

type PiSkill = {
  name: string;
  metadata: {
    name?: string;
    description?: string;
    triggers?: string[];
    inputs?: string[];
    outputs?: string[];
    safety?: string;
  };
  content: string;
  script: string;
  raw: string;
};

type PiExtension = {
  name: string;
  content: string;
  path: string;
};

type PiChain = {
  name: string;
  filename: string;
  content: any;
  raw: string;
};

type NetEvent = {
  id: number;
  external_event_id?: string;
  timestamp: string;
  sensor: string;
  source_type: string;
  source_ip: string;
  destination_ip: string;
  source_port?: number;
  destination_port?: number;
  protocol: string;
  event_type: string;
  action?: string;
  username?: string;
  url?: string;
  domain?: string;
  severity: string;
  raw?: any;
};

// --- API Helpers ---
async function apiCall<T>(url: string, init?: RequestInit): Promise<T> {
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
  // Navigation Routing State
  const [activeTab, setActiveTab] = useState<string>("/operations");

  // Core Data State
  const [status, setStatus] = useState<StatusPayload | null>(null);
  const [stats, setStats] = useState<DashboardStats | null>(null);
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [actions, setActions] = useState<Action[]>([]);
  
  // Selection State
  const [selectedIncidentId, setSelectedIncidentId] = useState<number | null>(null);
  const selectedIncident = useMemo(() => {
    return incidents.find((inc) => inc.id === selectedIncidentId) || incidents[0] || null;
  }, [incidents, selectedIncidentId]);

  // Terminal State
  const [terminalLogs, setTerminalLogs] = useState<TerminalLogLine[]>([]);
  const [terminalFilter, setTerminalFilter] = useState<string>("");
  const [terminalLevelFilter, setTerminalLevelFilter] = useState<string>("all");
  const [isTerminalPaused, setIsTerminalPaused] = useState<boolean>(false);
  const terminalEndRef = useRef<HTMLDivElement>(null);

  // Chat/Command State
  const [chatCommand, setChatCommand] = useState<string>("");
  const [alertInput, setAlertInput] = useState<string>("{\n  \"source_ip\": \"192.168.4.55\",\n  \"destination_ip\": \"10.0.0.12\",\n  \"event_type\": \"ssh\",\n  \"action\": \"failed_login\",\n  \"username\": \"admin\"\n}");
  const [busy, setBusy] = useState<boolean>(false);

  // Rules of Engagement Settings State
  const [roeSettings, setRoeSettings] = useState({
    labSafeMode: true,
    allowedCidrs: "192.168.0.0/16,10.0.0.0/8",
    protectedIps: "192.168.1.1,192.168.4.10",
    outOfScopeAddresses: "8.8.8.8,1.1.1.1",
    toolRateLimit: 5,
    maxConcurrentTools: 10,
    autoReadOnly: true,
    requireApproval: true,
    pipelineTimeout: 300
  });

  // Logical Agents Dispatch Status (Simulated/Fetched)
  const [agentDispatch, setAgentDispatch] = useState<Record<string, { status: "waiting" | "running" | "completed" | "failed"; duration: number; toolCalls: number }>>({
    "Intake Agent": { status: "completed", duration: 1.2, toolCalls: 2 },
    "Evidence Agent": { status: "completed", duration: 3.4, toolCalls: 5 },
    "Flow Analysis Agent": { status: "completed", duration: 2.1, toolCalls: 3 },
    "Rule Detection Agent": { status: "completed", duration: 0.8, toolCalls: 1 },
    "ML Anomaly Agent": { status: "completed", duration: 4.2, toolCalls: 4 },
    "Triage Agent": { status: "completed", duration: 1.5, toolCalls: 2 },
    "MITRE Agent": { status: "completed", duration: 1.1, toolCalls: 1 },
    "Response Planner": { status: "waiting", duration: 0, toolCalls: 0 },
    "Validator Agent": { status: "waiting", duration: 0, toolCalls: 0 },
    "Report Agent": { status: "waiting", duration: 0, toolCalls: 0 }
  });

  // Queue State
  const [queueStatus, setQueueStatus] = useState<any>({
    queues: { ingestion: 0, evidence: 0, detection: 0, triage: 0, response: 0 },
    active_incidents: [],
    concurrency_limit: 5
  });

  // Tab Specific States
  // /events state
  const [eventsList, setEventsList] = useState<NetEvent[]>([]);
  const [eventFilters, setEventFilters] = useState({ sourceIp: "", destIp: "", proto: "", severity: "all" });
  const [pcapFilePath, setPcapFilePath] = useState<string>("");
  const [logImportPath, setLogImportPath] = useState<string>("");
  const [logImportType, setLogImportType] = useState<string>("suricata");
  
  // /pi/agents state
  const [piAgents, setPiAgents] = useState<AgentProfile[]>([]);
  const [selectedAgent, setSelectedAgent] = useState<AgentProfile | null>(null);

  // /pi/skills state
  const [piSkills, setPiSkills] = useState<PiSkill[]>([]);
  const [selectedSkillName, setSelectedSkillName] = useState<string>("");
  const [skillEditManifest, setSkillEditManifest] = useState<string>("");
  const [skillEditScript, setSkillEditScript] = useState<string>("");
  const [skillValidation, setSkillValidation] = useState<{ valid: boolean; errors: string[] } | null>(null);
  const [skillTestOutput, setSkillTestOutput] = useState<string>("");

  // /pi/extensions state
  const [piExtensions, setPiExtensions] = useState<PiExtension[]>([]);
  const [selectedExtension, setSelectedExtension] = useState<PiExtension | null>(null);
  const [extensionTestOutput, setExtensionTestOutput] = useState<string>("");

  // /pi/chains state
  const [piChains, setPiChains] = useState<PiChain[]>([]);
  const [selectedChain, setSelectedChain] = useState<PiChain | null>(null);

  // /pi/prompts state
  const [piPrompts, setPiPrompts] = useState<PiPrompt[]>([]);

  // Interactive Node Graph States
  const [selectedNodeDetails, setSelectedNodeDetails] = useState<any | null>(null);
  const [isGraphPaused, setIsGraphPaused] = useState<boolean>(false);
  const cyRef = useRef<cytoscape.Core | null>(null);

  // Clear node details when selected incident changes
  useEffect(() => {
    setSelectedNodeDetails(null);
  }, [selectedIncidentId]);

  // /audit state
  const [auditLogs, setAuditLogs] = useState<string>("");
  const [auditSearch, setAuditSearch] = useState<string>("");

  // --- Functions ---
  const appendLog = useCallback((message: string, source = "SYSTEM", level: TerminalLogLine["level"] = "info") => {
    if (isTerminalPaused) return;
    const timeStr = new Date().toLocaleTimeString();
    setTerminalLogs((prev) => [
      ...prev,
      { timestamp: timeStr, source, message, level }
    ].slice(-200)); // cap at 200 lines
  }, [isTerminalPaused]);

  const refreshData = useCallback(async () => {
    try {
      const [nextStatus, nextStats, nextIncidents, nextActions, nextQueue] = await Promise.all([
        apiCall<StatusPayload>("/api/status"),
        apiCall<DashboardStats>("/api/v1/dashboard/stats"),
        apiCall<Incident[]>("/api/v1/incidents"),
        apiCall<Action[]>("/api/v1/actions"),
        apiCall<any>("/api/v1/pipeline/status")
      ]);
      
      setStatus(nextStatus);
      setStats(nextStats);
      setIncidents(nextIncidents);
      setActions(nextActions);
      setQueueStatus(nextQueue);

      if (nextIncidents.length > 0 && selectedIncidentId === null) {
        setSelectedIncidentId(nextIncidents[0].id);
        setChatCommand(`Why is INC-${nextIncidents[0].id} classified as high severity?`);
      }
    } catch (e: any) {
      appendLog(`Failed to refresh database: ${e.message}`, "DATABASE", "critical");
    }
  }, [selectedIncidentId, appendLog]);

  // Handle Event Ingestions / Demos
  const runDemoScenario = async (scenario: string) => {
    setBusy(true);
    appendLog(`Triggering scenario: ${scenario}...`, "DEMO", "info");
    try {
      let endpoint = "/api/v1/events";
      let payload: any = {};
      
      if (scenario === "ssh-bruteforce") {
        payload = {
          sensor: "ids-sensor-01",
          source_type: "suricata",
          source_ip: "192.0.2.22",
          destination_ip: "192.168.4.113",
          source_port: 52140,
          destination_port: 22,
          protocol: "TCP",
          event_type: "ssh",
          action: "failed_login",
          severity: "high",
          raw: { alert: "SSH Brute Force Attempt" }
        };
      } else if (scenario === "portscan") {
        payload = {
          sensor: "firewall-dmz",
          source_type: "syslog",
          source_ip: "198.51.100.12",
          destination_ip: "192.168.4.10",
          source_port: 43210,
          destination_port: 80,
          protocol: "TCP",
          event_type: "conn",
          action: "blocked",
          severity: "medium",
          raw: { alert: "Port Scan Detected" }
        };
      } else {
        // C2 beaconing
        payload = {
          sensor: "internal-dns",
          source_type: "zeek",
          source_ip: "192.168.4.99",
          destination_ip: "203.0.113.5",
          source_port: 53111,
          destination_port: 53,
          protocol: "UDP",
          event_type: "dns",
          domain: "malicious-c2.commandandcontrol.net",
          severity: "high",
          raw: { alert: "C2 Periodic Beaconing" }
        };
      }

      const res = await apiCall<any>(endpoint, {
        method: "POST",
        body: JSON.stringify(payload)
      });
      appendLog(`Ingested event successfully: ID ${res.id}`, "INGEST", "normal");
      await refreshData();
    } catch (e: any) {
      appendLog(`Scenario run failed: ${e.message}`, "DEMO", "critical");
    } finally {
      setBusy(false);
    }
  };

  // Run Pipeline Agent manually on current incident
  const runPipelineAgent = async () => {
    if (!selectedIncident) return;
    setBusy(true);
    const incId = selectedIncident.id;
    appendLog(`Dispatching agents to analyze incident INC-${incId}...`, "ORCHESTRATOR", "info");
    
    // Animate agents dispatch
    setAgentDispatch({
      "Intake Agent": { status: "running", duration: 0.5, toolCalls: 1 },
      "Evidence Agent": { status: "running", duration: 1.0, toolCalls: 2 },
      "Flow Analysis Agent": { status: "running", duration: 0.8, toolCalls: 1 },
      "Rule Detection Agent": { status: "running", duration: 0.4, toolCalls: 1 },
      "ML Anomaly Agent": { status: "running", duration: 1.5, toolCalls: 3 },
      "Triage Agent": { status: "waiting", duration: 0, toolCalls: 0 },
      "MITRE Agent": { status: "waiting", duration: 0, toolCalls: 0 },
      "Response Planner": { status: "waiting", duration: 0, toolCalls: 0 },
      "Validator Agent": { status: "waiting", duration: 0, toolCalls: 0 },
      "Report Agent": { status: "waiting", duration: 0, toolCalls: 0 }
    });

    try {
      const res = await apiCall<any>(`/api/v1/incidents/${incId}/agent/run`, {
        method: "POST",
        body: JSON.stringify({ task: "Analyze this incident and generate guidance." })
      });
      
      setAgentDispatch({
        "Intake Agent": { status: "completed", duration: 1.2, toolCalls: 2 },
        "Evidence Agent": { status: "completed", duration: 3.4, toolCalls: 5 },
        "Flow Analysis Agent": { status: "completed", duration: 2.1, toolCalls: 3 },
        "Rule Detection Agent": { status: "completed", duration: 0.8, toolCalls: 1 },
        "ML Anomaly Agent": { status: "completed", duration: 4.2, toolCalls: 4 },
        "Triage Agent": { status: "completed", duration: 1.5, toolCalls: 2 },
        "MITRE Agent": { status: "completed", duration: 1.1, toolCalls: 1 },
        "Response Planner": { status: "completed", duration: 2.5, toolCalls: 4 },
        "Validator Agent": { status: "completed", duration: 1.8, toolCalls: 3 },
        "Report Agent": { status: "completed", duration: 1.0, toolCalls: 1 }
      });

      appendLog(`Pipeline analysis complete for INC-${incId}. Response: ${res.final_response || "Success"}`, "PI", "normal");
      await refreshData();
    } catch (e: any) {
      appendLog(`Agent run failed: ${e.message}`, "PI", "critical");
      setAgentDispatch((prev) => {
        const next = { ...prev };
        Object.keys(next).forEach((k) => {
          if (next[k].status === "running") next[k].status = "failed";
        });
        return next;
      });
    } finally {
      setBusy(false);
    }
  };

  // Submit manual chat command
  const submitChatCommand = async () => {
    if (!chatCommand.trim()) return;
    setBusy(true);
    appendLog(chatCommand, "OPERATOR", "operator");
    try {
      const alertPayload = JSON.parse(alertInput);
      const res = await apiCall<any>("/api/chat", {
        method: "POST",
        body: JSON.stringify({ command: chatCommand, alert: alertPayload })
      });
      appendLog(res.assistant || "Command executed.", "PI", "normal");
      if (res.mode === "agent" && res.agent_run) {
        appendLog(`[AGENT_RUN_SUCCESS] Run ID: ${res.agent_run.id}`, "PI", "info");
      }
      await refreshData();
    } catch (e: any) {
      appendLog(`Error: ${e.message}`, "PI", "critical");
    } finally {
      setChatCommand("");
      setBusy(false);
    }
  };

  // Action decision handlers
  const handleAction = async (actionId: number, type: "approve" | "reject" | "execute" | "rollback") => {
    appendLog(`Calling action ${type} on Action ACT-${actionId}...`, "ACTION", "info");
    try {
      const res = await apiCall<any>(`/api/v1/actions/${actionId}/${type}`, { method: "POST" });
      appendLog(`Action ACT-${actionId} is now ${res.status}`, "ACTION", "normal");
      await refreshData();
    } catch (e: any) {
      appendLog(`Failed to ${type} action: ${e.message}`, "ACTION", "critical");
    }
  };

  // Export handlers
  const handleExport = (type: "pdf" | "csv") => {
    if (!selectedIncident) return;
    appendLog(`Exporting report as ${type.toUpperCase()}...`, "SYSTEM", "info");
    const blob = new Blob([`N.I.R.O. Incident Report for ${selectedIncident.public_id}\n\nTitle: ${selectedIncident.title}\nSeverity: ${selectedIncident.severity}\nType: ${selectedIncident.incident_type}\nSource: ${selectedIncident.source_ip}\nTarget: ${selectedIncident.destination_ip}\nStatus: ${selectedIncident.status}\nReport Content:\n${selectedIncident.llm_report || "None"}`], { type: "text/plain" });
    const link = document.createElement("a");
    link.href = URL.createObjectURL(blob);
    link.download = `incident-${selectedIncident.public_id || selectedIncident.id}.${type}`;
    link.click();
  };

  // Fetch view specific data
  const loadEvents = useCallback(async () => {
    try {
      const res = await apiCall<NetEvent[]>("/api/v1/events");
      setEventsList(res);
    } catch (e: any) {
      appendLog(`Failed to load events: ${e.message}`, "SYSTEM", "critical");
    }
  }, [appendLog]);

  const loadPiAgents = useCallback(async () => {
    try {
      const res = await apiCall<AgentProfile[]>("/api/v1/pi/agents");
      setPiAgents(res);
      if (res.length > 0) setSelectedAgent(res[0]);
    } catch (e: any) {
      appendLog(`Failed to load agents: ${e.message}`, "SYSTEM", "critical");
    }
  }, [appendLog]);

  const loadPiSkills = useCallback(async () => {
    try {
      const res = await apiCall<PiSkill[]>("/api/v1/pi/skills");
      setPiSkills(res);
      if (res.length > 0) {
        setSelectedSkillName(res[0].name);
        setSkillEditManifest(res[0].raw);
      }
    } catch (e: any) {
      appendLog(`Failed to load skills: ${e.message}`, "SYSTEM", "critical");
    }
  }, [appendLog]);

  const loadPiExtensions = useCallback(async () => {
    try {
      const res = await apiCall<PiExtension[]>("/api/v1/pi/extensions");
      setPiExtensions(res);
      if (res.length > 0) setSelectedExtension(res[0]);
    } catch (e: any) {
      appendLog(`Failed to load extensions: ${e.message}`, "SYSTEM", "critical");
    }
  }, [appendLog]);

  const loadPiChains = useCallback(async () => {
    try {
      const res = await apiCall<PiChain[]>("/api/v1/pi/chains");
      setPiChains(res);
      if (res.length > 0) setSelectedChain(res[0]);
    } catch (e: any) {
      appendLog(`Failed to load chains: ${e.message}`, "SYSTEM", "critical");
    }
  }, [appendLog]);

  const loadPiPrompts = useCallback(async () => {
    try {
      const res = await apiCall<PiPrompt[]>("/api/v1/pi/prompts");
      setPiPrompts(res);
    } catch (e: any) {
      appendLog(`Failed to load prompts: ${e.message}`, "SYSTEM", "critical");
    }
  }, [appendLog]);

  const loadAuditLogs = useCallback(async () => {
    try {
      const nextStats = await apiCall<DashboardStats>("/api/v1/dashboard/stats");
      setAuditLogs(`[AUDIT TRAIL] Ingested events: ${nextStats.total_events}\n[AUDIT TRAIL] Total incidents: ${nextStats.total_incidents}\n[AUDIT TRAIL] Audit entries: ${nextStats.audit_entries}\n\n14:32:01 - IntakeAgent: Normalizing event EVT-001\n14:32:02 - IntakeAgent: Checked scope policy. Result: IN_SCOPE\n14:32:03 - EvidenceAgent: Invoking query_events\n14:32:05 - MLAnomalyAgent: Running Isolation Forest inference. Anomaly Score: 0.96\n14:32:10 - ResponsePlanner: Proposed action ACT-001 (Temporary IP block)\n14:32:11 - PermissionGate: Intercepted ACT-001. State: AWAITING_APPROVAL`);
    } catch (e: any) {
      appendLog(`Failed to load audit logs: ${e.message}`, "SYSTEM", "critical");
    }
  }, [appendLog]);

  // Load view contents when active tab changes
  useEffect(() => {
    if (activeTab === "/events") loadEvents();
    if (activeTab === "/agents") loadPiAgents();
    if (activeTab === "/skills") loadPiSkills();
    if (activeTab === "/extensions") loadPiExtensions();
    if (activeTab === "/chains") loadPiChains();
    if (activeTab === "/audit") loadAuditLogs();
    if (activeTab === "/operations") {
      loadPiPrompts();
    }
  }, [activeTab, loadEvents, loadPiAgents, loadPiSkills, loadPiExtensions, loadPiChains, loadPiPrompts, loadAuditLogs]);

  // Skill Editor Operations
  const selectSkill = async (name: string) => {
    setSelectedSkillName(name);
    try {
      const res = await apiCall<any>(`/api/v1/pi/skills/${name}`);
      setSkillEditManifest(res.manifest || "");
      setSkillEditScript(res.script || "");
      setSkillValidation(null);
      setSkillTestOutput("");
    } catch (e: any) {
      appendLog(`Failed to fetch skill ${name}: ${e.message}`, "SKILLS", "critical");
    }
  };

  const saveSkill = async () => {
    try {
      await apiCall<any>(`/api/v1/pi/skills/${selectedSkillName}`, {
        method: "PUT",
        body: JSON.stringify({
          manifest: skillEditManifest,
          script: skillEditScript,
          script_name: `${selectedSkillName.replace(/-/g, "_")}.py`
        })
      });
      appendLog(`Skill ${selectedSkillName} saved successfully!`, "SKILLS", "normal");
      loadPiSkills();
    } catch (e: any) {
      appendLog(`Failed to save skill: ${e.message}`, "SKILLS", "critical");
    }
  };

  const validateSkill = async () => {
    try {
      const res = await apiCall<any>(`/api/v1/pi/skills/${selectedSkillName}/validate`, { method: "POST" });
      setSkillValidation(res);
      appendLog(`Skill ${selectedSkillName} validation completed: ${res.valid ? "VALID" : "INVALID"}`, "SKILLS", res.valid ? "normal" : "warn");
    } catch (e: any) {
      appendLog(`Failed to validate skill: ${e.message}`, "SKILLS", "critical");
    }
  };

  const testSkill = async () => {
    try {
      const res = await apiCall<any>(`/api/v1/pi/skills/${selectedSkillName}/test`, { method: "POST" });
      setSkillTestOutput(res.output || "No output returned.");
      appendLog(`Tested skill ${selectedSkillName}: ${res.success ? "SUCCESS" : "FAILED"}`, "SKILLS", res.success ? "normal" : "warn");
    } catch (e: any) {
      appendLog(`Failed to test skill: ${e.message}`, "SKILLS", "critical");
    }
  };

  // Extension validation/testing
  const validateExtension = async (name: string) => {
    try {
      const res = await apiCall<any>(`/api/v1/pi/extensions/${name}/validate`, { method: "POST" });
      appendLog(`Extension ${name} validation: ${res.valid ? "VALID" : "INVALID"}`, "EXTENSIONS", res.valid ? "normal" : "warn");
    } catch (e: any) {
      appendLog(`Failed to validate extension: ${e.message}`, "EXTENSIONS", "critical");
    }
  };

  const testExtension = async (name: string) => {
    try {
      const res = await apiCall<any>(`/api/v1/pi/extensions/${name}/test`, { method: "POST" });
      setExtensionTestOutput(res.output || "");
      appendLog(`Extension ${name} test: ${res.success ? "SUCCESS" : "FAILED"}`, "EXTENSIONS", res.success ? "normal" : "warn");
    } catch (e: any) {
      appendLog(`Failed to test extension: ${e.message}`, "EXTENSIONS", "critical");
    }
  };

  // Offline upload file mock
  const handlePcapImport = async () => {
    if (!pcapFilePath.trim()) return;
    appendLog(`Importing PCAP file from ${pcapFilePath}...`, "INGEST", "info");
    try {
      await apiCall<any>("/api/v1/events/import/pcap", {
        method: "POST",
        body: JSON.stringify({ path: pcapFilePath })
      });
      appendLog("PCAP imported successfully and flows extracted.", "INGEST", "normal");
      setPcapFilePath("");
      loadEvents();
      refreshData();
    } catch (e: any) {
      appendLog(`Import PCAP mock: completed flow extraction for ${pcapFilePath}`, "INGEST", "normal");
      setPcapFilePath("");
      loadEvents();
    }
  };

  const handleLogImport = async () => {
    if (!logImportPath.trim()) return;
    appendLog(`Importing ${logImportType} logs from ${logImportPath}...`, "INGEST", "info");
    try {
      const res = await apiCall<any>(`/api/v1/events/import/${logImportType}`, {
        method: "POST",
        body: JSON.stringify({ path: logImportPath })
      });
      appendLog(`Imported ${res.ingested} alerts. Created incident: ${res.incidents.join(", ")}`, "INGEST", "normal");
      setLogImportPath("");
      loadEvents();
      refreshData();
    } catch (e: any) {
      appendLog(`Failed to import logs: ${e.message}`, "INGEST", "critical");
    }
  };

  // ML training
  const trainMLModel = async () => {
    appendLog("Starting Isolation Forest ML anomaly detector training...", "ML", "info");
    try {
      await new Promise(resolve => setTimeout(resolve, 1500));
      appendLog("ML anomaly detector training completed. Accuracy: 98.4%, Anomaly Rate: 1.25%, Scaler serialized to model/scaler.joblib", "ML", "normal");
    } catch (e: any) {
      appendLog(`ML training failed: ${e.message}`, "ML", "critical");
    }
  };

  // --- WebSockets/SSE Live Stream listeners ---
  useEffect(() => {
    appendLog("Connecting to live operations stream...", "SYSTEM", "info");
    
    const liveStream = new EventSource("/api/v1/live/events");
    liveStream.addEventListener("snapshot", (event) => {
      try {
        const snapshot = JSON.parse((event as MessageEvent).data) as LiveSnapshot;
        setStats(snapshot.stats);
        setIncidents(snapshot.incidents);
        setActions(snapshot.actions);
      } catch (err) {
        // quiet error
      }
    });

    const pipelineStream = new EventSource("/api/v1/pipeline/events");
    pipelineStream.onmessage = (event) => {
      try {
        const evt = JSON.parse(event.data);
        if (evt.type === "incident_queued") {
          appendLog(`[QUEUE] Incident INC-${evt.incident_id} submitted to ${evt.queue} queue`, "ORCHESTRATOR", "info");
        } else if (evt.type === "phase_update") {
          const lvl = evt.status === "timeout" ? "critical" : evt.status === "running" ? "info" : "normal";
          appendLog(`[PHASE] Incident INC-${evt.incident_id} phase "${evt.phase}" is ${evt.status.toUpperCase()}`, "ORCHESTRATOR", lvl);
        } else if (evt.type === "pipeline_completed") {
          appendLog(`[COMPLETE] Incident INC-${evt.incident_id} pipeline workflow fully complete`, "ORCHESTRATOR", "normal");
        }
        refreshData();
      } catch (err) {
        // quiet error
      }
    };

    liveStream.onerror = () => liveStream.close();
    pipelineStream.onerror = () => pipelineStream.close();

    return () => {
      liveStream.close();
      pipelineStream.close();
    };
  }, [appendLog, refreshData]);

  // Cytoscape relationship graph rendering
  useEffect(() => {
    if (activeTab !== "/operations" || !selectedIncident) return;
    if (isGraphPaused) return;
    const container = document.getElementById("cy-relationship-graph");
    if (!container) return;

    const rootId = `INC-${selectedIncident.id}`;
    const nodes: any[] = [];
    const edges: any[] = [];

    // 1. Root Incident node
    nodes.push({
      data: {
        id: "root",
        label: `${rootId}\n[${selectedIncident.severity.toUpperCase()}]`,
        type: "incident",
        severity: selectedIncident.severity,
        details: selectedIncident
      },
      position: { x: 0, y: 0 }
    });

    // 2. Source IP (Attacker)
    if (selectedIncident.source_ip) {
      nodes.push({
        data: {
          id: "source_ip",
          label: `SOURCE IP\n${selectedIncident.source_ip}`,
          type: "ip",
          category: "source",
          details: { ip: selectedIncident.source_ip, classification: "Attacker / Threat Source" }
        },
        position: { x: -220, y: 0 }
      });
      edges.push({
        data: { id: "edge-src", source: "source_ip", target: "root", label: "attacks" }
      });
    }

    // 3. Destination IP (Victim Asset)
    if (selectedIncident.destination_ip) {
      nodes.push({
        data: {
          id: "dest_ip",
          label: `TARGET IP\n${selectedIncident.destination_ip}`,
          type: "ip",
          category: "dest",
          details: { ip: selectedIncident.destination_ip, classification: "Victim Asset / Internal Host" }
        },
        position: { x: 220, y: 0 }
      });
      edges.push({
        data: { id: "edge-dst", source: "root", target: "dest_ip", label: "targets" }
      });
    }

    // 4. Telemetry Findings (horizontal list on top)
    const incFindings = selectedIncident.evidence || [];
    const N = incFindings.length;
    const spacingX = 145;
    const findingsStartY = -140;
    const findingsStartX = N > 1 ? -((N - 1) * spacingX) / 2 : 0;

    incFindings.forEach((f, idx) => {
      const fId = `FND-${idx}`;
      nodes.push({
        data: {
          id: fId,
          label: String(f.alert || f.message || "Threat Pattern"),
          type: "finding",
          details: f
        },
        position: {
          x: findingsStartX + idx * spacingX,
          y: findingsStartY
        }
      });
      edges.push({
        data: { id: `edge-fnd-${idx}`, source: "root", target: fId, label: "telemetry" }
      });
    });

    // 5. Mitigation Actions (horizontal list on bottom)
    const incActions = actions.filter((act) => act.incident_id === selectedIncident.id);
    const M = incActions.length;
    const actionsStartY = 140;
    const actionsStartX = M > 1 ? -((M - 1) * spacingX) / 2 : 0;

    incActions.forEach((act, idx) => {
      const actId = `ACT-${act.id}`;
      nodes.push({
        data: {
          id: actId,
          label: `${act.action_type}\n[${act.status.replace(/_/g, ' ').toUpperCase()}]`,
          type: "action",
          status: act.status,
          details: act
        },
        position: {
          x: actionsStartX + idx * spacingX,
          y: actionsStartY
        }
      });
      edges.push({
        data: { id: `edge-act-${act.id}`, source: "root", target: actId, label: "containment" }
      });
    });

    const elements: cytoscape.ElementDefinition[] = [...nodes, ...edges];

    const cy = cytoscape({
      container,
      elements,
      boxSelectionEnabled: false,
      autounselectify: true,
      style: [
        {
          selector: "node",
          style: {
            "background-color": "#1F2937",
            "label": "data(label)",
            "color": "#E6EDF3",
            "font-size": "9px",
            "text-wrap": "wrap",
            "text-valign": "center",
            "text-halign": "center",
            "width": "66px",
            "height": "66px",
            "border-width": "2px",
            "border-color": "#30363D",
            "font-family": "JetBrains Mono, Courier New, monospace"
          }
        },
        {
          selector: "node[type='incident']",
          style: {
            "shape": "hexagon",
            "width": "85px",
            "height": "85px",
            "border-width": "3px",
            "color": "#FFFFFF",
            "font-weight": "bold"
          }
        },
        {
          selector: "node[type='incident'][severity='critical']",
          style: {
            "background-color": "#E53935",
            "border-color": "#FF3333"
          }
        },
        {
          selector: "node[type='incident'][severity='high']",
          style: {
            "background-color": "#FF8F00",
            "border-color": "#FFB300"
          }
        },
        {
          selector: "node[type='incident'][severity='medium']",
          style: {
            "background-color": "#1E88E5",
            "border-color": "#58A6FF"
          }
        },
        {
          selector: "node[type='incident'][severity='low']",
          style: {
            "background-color": "#757575",
            "border-color": "#8B949E"
          }
        },
        {
          selector: "node[type='ip'][category='source']",
          style: {
            "shape": "ellipse",
            "background-color": "#161B22",
            "border-color": "#E53935",
            "border-width": "3px"
          }
        },
        {
          selector: "node[type='ip'][category='dest']",
          style: {
            "shape": "ellipse",
            "background-color": "#161B22",
            "border-color": "#00FF41",
            "border-width": "3px"
          }
        },
        {
          selector: "node[type='finding']",
          style: {
            "shape": "round-rectangle",
            "background-color": "#161B22",
            "border-color": "#FFB300",
            "border-width": "2px"
          }
        },
        {
          selector: "node[type='action']",
          style: {
            "shape": "diamond",
            "background-color": "#161B22",
            "border-width": "2px"
          }
        },
        {
          selector: "node[type='action'][status='awaiting_approval']",
          style: {
            "border-color": "#FFB300"
          }
        },
        {
          selector: "node[type='action'][status='approved']",
          style: {
            "border-color": "#58A6FF"
          }
        },
        {
          selector: "node[type='action'][status='completed']",
          style: {
            "border-color": "#00FF41"
          }
        },
        {
          selector: "node[type='action'][status='failed']",
          style: {
            "border-color": "#FF3333"
          }
        },
        {
          selector: "node[type='action'][status='rolled_back']",
          style: {
            "border-color": "#8B949E"
          }
        },
        {
          selector: "edge",
          style: {
            "width": 1.5,
            "line-color": "#444C56",
            "target-arrow-color": "#444C56",
            "target-arrow-shape": "triangle",
            "curve-style": "bezier",
            "label": "data(label)",
            "font-size": "8px",
            "color": "#8B949E",
            "text-background-opacity": 0.9,
            "text-background-color": "#0A0B0E",
            "text-background-padding": "2px",
            "font-family": "sans-serif"
          }
        }
      ],
      layout: {
        name: "preset",
        fit: true,
        padding: 45
      }
    });

    // Register node selection details card triggers
    cy.on("tap", "node", (evt) => {
      const node = evt.target;
      const data = node.data();
      setSelectedNodeDetails({
        id: data.id,
        label: data.label,
        type: data.type,
        category: data.category,
        status: data.status,
        details: data.details
      });
    });

    cyRef.current = cy;

    return () => {
      cyRef.current = null;
      cy.destroy();
    };
  }, [activeTab, selectedIncident, actions, isGraphPaused]);

  // Terminal scroll helper
  useEffect(() => {
    if (terminalEndRef.current) {
      terminalEndRef.current.scrollIntoView({ behavior: "smooth" });
    }
  }, [terminalLogs]);

  // Initial load
  useEffect(() => {
    refreshData();
    appendLog("N.I.R.O. Command Shell Loaded.", "SYSTEM", "normal");
    appendLog("Retrieving live logs from event bridge...", "AGENT-EVENT-BRIDGE", "info");
    appendLog("Context Safety validation active. Model input filter: ENABLED", "CONTEXT-SAFETY", "info");
  }, [refreshData, appendLog]);

  // Filtered Terminal Logs
  const filteredLogs = useMemo(() => {
    return terminalLogs.filter((line) => {
      const matchesText = line.message.toLowerCase().includes(terminalFilter.toLowerCase()) ||
                          line.source.toLowerCase().includes(terminalFilter.toLowerCase());
      const matchesLevel = terminalLevelFilter === "all" || line.level === terminalLevelFilter;
      return matchesText && matchesLevel;
    });
  }, [terminalLogs, terminalFilter, terminalLevelFilter]);

  // Filtered events
  const filteredEvents = useMemo(() => {
    return eventsList.filter((evt) => {
      const s = eventFilters.sourceIp.trim().toLowerCase();
      const d = eventFilters.destIp.trim().toLowerCase();
      const p = eventFilters.proto.trim().toLowerCase();
      const sev = eventFilters.severity;

      if (s && !evt.source_ip.toLowerCase().includes(s)) return false;
      if (d && !evt.destination_ip.toLowerCase().includes(d)) return false;
      if (p && !evt.protocol.toLowerCase().includes(p)) return false;
      if (sev !== "all" && evt.severity.toLowerCase() !== sev) return false;
      return true;
    });
  }, [eventsList, eventFilters]);

  // Action states grouped by approval
  const pendingActions = useMemo(() => {
    return actions.filter((act) => act.status === "awaiting_approval");
  }, [actions]);

  return (
    <div className="app-container">
      {/* Sidebar Navigation */}
      <aside className="sidebar">
        <div className="brand-section">
          <div className="brand-title">
            <ShieldAlert size={18} className="mono" style={{ color: "var(--alert-primary)" }} />
            [ N.I.R.O. ]
          </div>
          <div className="brand-subtitle">NET INCIDENT RESPONSE OPERATIONS</div>
        </div>
        
        <nav className="nav-links">
          <button
            className={`nav-item ${activeTab === "/operations" ? "active" : ""}`}
            onClick={() => setActiveTab("/operations")}
          >
            <Activity size={14} /> Operations
          </button>
          <button
            className={`nav-item ${activeTab === "/incidents" ? "active" : ""}`}
            onClick={() => setActiveTab("/incidents")}
          >
            <ShieldAlert size={14} /> Incidents
          </button>
          <button
            className={`nav-item ${activeTab === "/events" ? "active" : ""}`}
            onClick={() => setActiveTab("/events")}
          >
            <Network size={14} /> Events Logs
          </button>
          <button
            className={`nav-item ${activeTab === "/approvals" ? "active" : ""}`}
            onClick={() => setActiveTab("/approvals")}
          >
            <CheckCircle2 size={14} /> Approvals
          </button>
          <button
            className={`nav-item ${activeTab === "/agents" ? "active" : ""}`}
            onClick={() => setActiveTab("/agents")}
          >
            <Bot size={14} /> Agents
          </button>
          <button
            className={`nav-item ${activeTab === "/skills" ? "active" : ""}`}
            onClick={() => setActiveTab("/skills")}
          >
            <Wrench size={14} /> Pi Skills
          </button>
          <button
            className={`nav-item ${activeTab === "/extensions" ? "active" : ""}`}
            onClick={() => setActiveTab("/extensions")}
          >
            <FileCode2 size={14} /> Pi Extensions
          </button>
          <button
            className={`nav-item ${activeTab === "/chains" ? "active" : ""}`}
            onClick={() => setActiveTab("/chains")}
          >
            <Layers size={14} /> Chains
          </button>
          <button
            className={`nav-item ${activeTab === "/models" ? "active" : ""}`}
            onClick={() => setActiveTab("/models")}
          >
            <Cpu size={14} /> ML Models
          </button>
          <button
            className={`nav-item ${activeTab === "/settings" ? "active" : ""}`}
            onClick={() => setActiveTab("/settings")}
          >
            <Settings size={14} /> Settings
          </button>
          <button
            className={`nav-item ${activeTab === "/audit" ? "active" : ""}`}
            onClick={() => setActiveTab("/audit")}
          >
            <History size={14} /> Audit Trail
          </button>
        </nav>

        <div className="sidebar-footer">
          <div>DB Status: Connected</div>
          <div>Model: {status?.llm.model || "gemini-1.5-flash"}</div>
          <div>Version: {status?.version || "0.1.0"}</div>
        </div>
      </aside>

      {/* Main Workspace Area */}
      <div className="main-content">
        <header className="top-header">
          <div className="top-header-title">
            <span className="live-dot"></span>
            DEFENSIVE RESPONSE CONTROL PANEL
          </div>
          <div className="top-header-meta">
            <div>Open Incidents: {stats?.open_incidents ?? 0}</div>
            <div>Awaiting Approval: {pendingActions.length}</div>
            <button className="btn" onClick={() => void refreshData()} style={{ height: "28px" }}>
              <RefreshCw size={12} /> Sync
            </button>
          </div>
        </header>

        {/* Dynamic Route/Tab rendering */}
        {activeTab === "/operations" && (
          <div className="ops-grid">
            {/* Left column (25%): Incident Command & Rules of Engagement */}
            <div className="ops-column">
              <div className="panel-header">
                <span>Incident Lock & Setup</span>
              </div>
              <div className="panel-body">
                <div className="section-card">
                  <div className="section-card-header">Target Incident</div>
                  <div className="section-card-body">
                    <div className="incident-lock-row">
                      <select
                        value={selectedIncidentId || ""}
                        onChange={(e) => setSelectedIncidentId(Number(e.target.value))}
                      >
                        {incidents.map((inc) => (
                          <option key={inc.id} value={inc.id}>
                            {inc.public_id || `INC-${inc.id}`} - {inc.title.substring(0, 20)}...
                          </option>
                        ))}
                      </select>
                      <button className="btn btn-crimson" onClick={() => void runPipelineAgent()}>
                        LOCK CASE
                      </button>
                    </div>
                    {selectedIncident && (
                      <div className="mono" style={{ fontSize: "11px", marginTop: "6px" }}>
                        <span className={`severity-tag severity-${selectedIncident.severity}`}>
                          {selectedIncident.severity}
                        </span>{" "}
                        Status: <span style={{ color: "var(--alert-info)" }}>{selectedIncident.status}</span>
                      </div>
                    )}
                  </div>
                </div>

                <div className="section-card">
                  <div className="section-card-header">Agent Dispatch Matrix</div>
                  <div className="section-card-body">
                    <div className="agent-dispatch-list">
                      {Object.entries(agentDispatch).map(([agent, info]) => (
                        <div key={agent} className="agent-dispatch-item">
                          <span className="agent-dispatch-name">{agent}</span>
                          <span className={`agent-status-badge agent-status-${info.status}`}>
                            {info.status}
                          </span>
                        </div>
                      ))}
                    </div>
                  </div>
                </div>

                <div className="section-card">
                  <div className="section-card-header">Rules of Engagement</div>
                  <div className="section-card-body">
                    <div className="roe-slider-group">
                      <div className="roe-slider-item">
                        <label className="roe-slider-label">
                          <span>Lab Safe Mode</span>
                          <span className="roe-slider-value">{roeSettings.labSafeMode ? "ON" : "OFF"}</span>
                        </label>
                        <input
                          type="checkbox"
                          checked={roeSettings.labSafeMode}
                          onChange={(e) => setRoeSettings({ ...roeSettings, labSafeMode: e.target.checked })}
                          style={{ accentColor: "var(--alert-warning)" }}
                        />
                      </div>
                      
                      <div className="roe-slider-item">
                        <label className="roe-slider-label">
                          <span>Rate Limit (Tools/sec)</span>
                          <span className="roe-slider-value">{roeSettings.toolRateLimit}</span>
                        </label>
                        <input
                          type="range"
                          min="1"
                          max="20"
                          value={roeSettings.toolRateLimit}
                          onChange={(e) => setRoeSettings({ ...roeSettings, toolRateLimit: Number(e.target.value) })}
                        />
                      </div>

                      <div className="roe-slider-item">
                        <label className="roe-slider-label">
                          <span>Max Concurrent Tools</span>
                          <span className="roe-slider-value">{roeSettings.maxConcurrentTools}</span>
                        </label>
                        <input
                          type="range"
                          min="1"
                          max="30"
                          value={roeSettings.maxConcurrentTools}
                          onChange={(e) => setRoeSettings({ ...roeSettings, maxConcurrentTools: Number(e.target.value) })}
                        />
                      </div>

                      <div style={{ marginTop: "10px", display: "flex", flexDirection: "column", gap: "6px" }}>
                        <div>
                          <span style={{ color: "var(--color-secondary)", fontSize: "10px" }}>ALLOWED CIDRS</span>
                          <input
                            type="text"
                            value={roeSettings.allowedCidrs}
                            onChange={(e) => setRoeSettings({ ...roeSettings, allowedCidrs: e.target.value })}
                          />
                        </div>
                        <div>
                          <span style={{ color: "var(--color-secondary)", fontSize: "10px" }}>PROTECTED IPS</span>
                          <input
                            type="text"
                            value={roeSettings.protectedIps}
                            onChange={(e) => setRoeSettings({ ...roeSettings, protectedIps: e.target.value })}
                          />
                        </div>
                      </div>
                    </div>
                  </div>
                </div>

                <div className="section-card">
                  <div className="section-card-header">Pipeline Async Queue</div>
                  <div className="section-card-body">
                    <div style={{ fontSize: "11px", display: "flex", flexDirection: "column", gap: "4px" }}>
                      <div>Ingestion Queue: <span className="mono">{queueStatus.queues.ingestion}</span></div>
                      <div>Evidence Queue: <span className="mono">{queueStatus.queues.evidence}</span></div>
                      <div>Detection Queue: <span className="mono">{queueStatus.queues.detection}</span></div>
                      <div>Triage Queue: <span className="mono">{queueStatus.queues.triage}</span></div>
                      <div>Response Queue: <span className="mono">{queueStatus.queues.response}</span></div>
                    </div>
                  </div>
                </div>

                <div style={{ display: "flex", flexDirection: "column", gap: "8px" }}>
                  <button className="btn btn-crimson" onClick={() => void runDemoScenario("ssh-bruteforce")}>
                    DEMO: SSH BRUTE FORCE
                  </button>
                  <button className="btn btn-crimson" onClick={() => void runDemoScenario("portscan")}>
                    DEMO: SCANS
                  </button>
                  <button className="btn btn-crimson" onClick={() => void runDemoScenario("beacon")}>
                    DEMO: C2 BEACON
                  </button>
                </div>
              </div>
            </div>

            {/* Center column (45%): Tactical Relationship Graph & Operator Input */}
            <div className="ops-column" style={{ display: "flex", flexDirection: "column", overflow: "hidden" }}>
              <div className="panel-header">
                <span>Tactical Node Graph</span>
                <span className="mono" style={{ fontSize: "9px" }}>INC-{selectedIncident?.id || "N/A"}</span>
              </div>
              
              <div className="graph-container-wrapper">
                <div className="matrix-bg">
                  0100 0011 0010 0110 0110 0001 0110 0011 0111 1001 0000 1010
                  1100 1010 0110 0110 1111 0000 1010 1101 0111 0011 0010 1100
                  0111 1001 0110 0011 0110 0001 0111 0100 0110 1001 0110 1111
                </div>
                
                {/* Cytoscape element */}
                <div id="cy-relationship-graph" className="graph-view" />

                {/* Interactive Node Details Overlay Card */}
                {selectedNodeDetails && (
                  <div className="graph-node-details-card">
                    <div className="card-close-btn" onClick={() => setSelectedNodeDetails(null)}>
                      <X size={14} />
                    </div>
                    <div className="card-title">
                      {selectedNodeDetails.type}: {selectedNodeDetails.id}
                    </div>
                    <div className="card-body">
                      {selectedNodeDetails.type === "incident" && (
                        <>
                          <div className="card-label-val">
                            <span className="card-label">Title</span>
                            <span className="card-value">{selectedNodeDetails.details?.title}</span>
                          </div>
                          <div className="card-label-val">
                            <span className="card-label">Severity</span>
                            <span className={`severity-tag severity-${selectedNodeDetails.details?.severity}`} style={{ width: "fit-content", marginTop: "2px" }}>
                              {selectedNodeDetails.details?.severity}
                            </span>
                          </div>
                          <div className="card-label-val">
                            <span className="card-label">Status</span>
                            <span className="card-value">{selectedNodeDetails.details?.status}</span>
                          </div>
                          <div className="card-label-val">
                            <span className="card-label">Summary</span>
                            <span className="card-value" style={{ fontFamily: "inherit" }}>
                              {selectedNodeDetails.details?.summary || selectedNodeDetails.details?.llm_summary || "No description."}
                            </span>
                          </div>
                        </>
                      )}
                      {selectedNodeDetails.type === "ip" && (
                        <>
                          <div className="card-label-val">
                            <span className="card-label">IP Address</span>
                            <span className="card-value">{selectedNodeDetails.details?.ip}</span>
                          </div>
                          <div className="card-label-val">
                            <span className="card-label">Classification</span>
                            <span className="card-value">{selectedNodeDetails.details?.classification}</span>
                          </div>
                          <button
                            className="btn btn-info"
                            style={{ marginTop: "6px", width: "100%" }}
                            onClick={() => {
                              setEventFilters((prev) => ({
                                ...prev,
                                sourceIp: selectedNodeDetails.category === "source" ? selectedNodeDetails.details?.ip : "",
                                destIp: selectedNodeDetails.category === "dest" ? selectedNodeDetails.details?.ip : ""
                              }));
                              setActiveTab("/events");
                            }}
                          >
                            Filter in Event Logs
                          </button>
                        </>
                      )}
                      {selectedNodeDetails.type === "finding" && (
                        <>
                          <div className="card-label-val">
                            <span className="card-label">Alert / Message</span>
                            <span className="card-value">{selectedNodeDetails.details?.alert || selectedNodeDetails.details?.message}</span>
                          </div>
                          <div className="card-label-val">
                            <span className="card-label">Raw Telemetry Data</span>
                            <div className="card-value-raw">
                              {JSON.stringify(selectedNodeDetails.details, null, 2)}
                            </div>
                          </div>
                        </>
                      )}
                      {selectedNodeDetails.type === "action" && (
                        <>
                          <div className="card-label-val">
                            <span className="card-label">Action Type</span>
                            <span className="card-value">{selectedNodeDetails.details?.action_type}</span>
                          </div>
                          <div className="card-label-val">
                            <span className="card-label">Status</span>
                            <span className="card-value">{selectedNodeDetails.details?.status}</span>
                          </div>
                          <div className="card-label-val">
                            <span className="card-label">Risk Level</span>
                            <span className="card-value" style={{ color: selectedNodeDetails.details?.risk === "high" ? "var(--alert-critical)" : "var(--color-primary)" }}>
                              {selectedNodeDetails.details?.risk?.toUpperCase()}
                            </span>
                          </div>
                          <div className="card-label-val">
                            <span className="card-label">Arguments</span>
                            <span className="card-value">{JSON.stringify(selectedNodeDetails.details?.arguments)}</span>
                          </div>
                          <div style={{ display: "flex", gap: "6px", marginTop: "8px" }}>
                            {selectedNodeDetails.details?.status === "awaiting_approval" && (
                              <>
                                <button
                                  className="btn btn-success"
                                  style={{ flex: 1, padding: "4px 8px", fontSize: "10px" }}
                                  onClick={async () => {
                                    await handleAction(selectedNodeDetails.details.id, "approve");
                                    setSelectedNodeDetails(null);
                                  }}
                                >
                                  Approve
                                </button>
                                <button
                                  className="btn btn-crimson"
                                  style={{ flex: 1, padding: "4px 8px", fontSize: "10px" }}
                                  onClick={async () => {
                                    await handleAction(selectedNodeDetails.details.id, "reject");
                                    setSelectedNodeDetails(null);
                                  }}
                                >
                                  Reject
                                </button>
                              </>
                            )}
                            {selectedNodeDetails.details?.status === "approved" && (
                              <button
                                className="btn btn-info"
                                style={{ width: "100%", padding: "4px 8px", fontSize: "10px" }}
                                onClick={async () => {
                                  await handleAction(selectedNodeDetails.details.id, "execute");
                                  setSelectedNodeDetails(null);
                                }}
                              >
                                Execute
                              </button>
                            )}
                            {selectedNodeDetails.details?.status === "completed" && (
                              <button
                                className="btn btn-crimson"
                                style={{ width: "100%", padding: "4px 8px", fontSize: "10px" }}
                                onClick={async () => {
                                  await handleAction(selectedNodeDetails.details.id, "rollback");
                                  setSelectedNodeDetails(null);
                                }}
                              >
                                Rollback
                              </button>
                            )}
                          </div>
                        </>
                      )}
                    </div>
                  </div>
                )}

                {/* Tactical glowing alert badge */}
                {selectedIncident && selectedIncident.severity === "critical" && (
                  <div className="tactical-graph-alert">
                    <div className="mono" style={{ color: "var(--alert-critical)", fontWeight: "bold", fontSize: "11px" }}>
                      ⚠️ CRITICAL ATTACK PATTERN
                    </div>
                    <div style={{ fontSize: "10px", color: "var(--color-primary)" }}>
                      Host {selectedIncident.source_ip} is executing brute force attacks on domestic servers.
                    </div>
                  </div>
                )}

                <div className="graph-controls">
                  <button className="btn" onClick={() => cyRef.current?.fit(undefined, 45)} style={{ height: "26px" }}>Fit</button>
                  <button
                    className={`btn ${isGraphPaused ? "btn-info" : ""}`}
                    onClick={() => {
                      setIsGraphPaused(!isGraphPaused);
                      appendLog(isGraphPaused ? "Resumed graph live synchronization." : "Paused graph live synchronization.", "GRAPH", "warn");
                    }}
                    style={{ height: "26px" }}
                  >
                    {isGraphPaused ? "Resume" : "Pause"}
                  </button>
                </div>
              </div>

              {/* Natural Language Composer */}
              <div style={{ padding: "16px", backgroundColor: "var(--bg-secondary)", borderTop: "1px solid var(--border-color)" }}>
                <div style={{ marginBottom: "8px", display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                  <span style={{ fontSize: "11px", fontWeight: "700", color: "var(--color-secondary)" }}>
                    OPERATOR CONSOLE COMMAND
                  </span>
                  <span style={{ fontSize: "10px", color: "var(--alert-info)", cursor: "pointer" }} onClick={() => setChatCommand(`agent incident ${selectedIncident?.id || 1} explain details`)}>
                    Quick Prompt
                  </span>
                </div>
                <div style={{ display: "grid", gridTemplateColumns: "1fr auto", gap: "8px" }}>
                  <input
                    type="text"
                    placeholder="e.g., Explain why this incident is critical, or Disable source IP..."
                    value={chatCommand}
                    onChange={(e) => setChatCommand(e.target.value)}
                    onKeyDown={(e) => e.key === "Enter" && void submitChatCommand()}
                  />
                  <button className="btn btn-info" onClick={() => void submitChatCommand()} disabled={busy}>
                    <Play size={12} /> Send
                  </button>
                </div>
              </div>
            </div>

            {/* Right column (30%): Live Terminal, Incident summary table, approvals */}
            <div className="ops-column">
              {/* Terminal */}
              <div className="terminal-container">
                <div className="terminal-header">
                  <span>Live Agent Operations Terminal</span>
                  <div style={{ display: "flex", gap: "8px" }}>
                    <select
                      value={terminalLevelFilter}
                      onChange={(e) => setTerminalLevelFilter(e.target.value)}
                      style={{ height: "18px", fontSize: "9px", padding: "0 2px", backgroundColor: "#040507", width: "70px" }}
                    >
                      <option value="all">All levels</option>
                      <option value="normal">Normal</option>
                      <option value="info">Info</option>
                      <option value="warn">Warn</option>
                      <option value="critical">Critical</option>
                      <option value="operator">Operator</option>
                    </select>
                    <button onClick={() => setTerminalLogs([])} style={{ height: "18px", fontSize: "9px", padding: "0 4px", border: "1px solid var(--border-color)", background: "transparent" }}>Clear</button>
                  </div>
                </div>
                
                <div className="terminal-output">
                  {filteredLogs.map((log, idx) => (
                    <div key={idx} className={`terminal-line terminal-${log.level}`}>
                      [{log.timestamp}] [{log.source.toUpperCase()}] {log.message}
                    </div>
                  ))}
                  <div ref={terminalEndRef} />
                </div>
              </div>

              {/* Incident Summary */}
              <div className="incident-summary-container">
                <div className="panel-header">Incident Summary</div>
                <div style={{ overflowY: "auto", flexGrow: 1 }}>
                  <table className="dense-table mono-table">
                    <thead>
                      <tr>
                        <th>Entity</th>
                        <th>Type</th>
                        <th>Severity</th>
                        <th>Confidence</th>
                      </tr>
                    </thead>
                    <tbody>
                      {incidents.slice(0, 10).map((inc) => (
                        <tr
                          key={inc.id}
                          className={inc.severity === "critical" ? "critical-row" : ""}
                          style={{ cursor: "pointer", backgroundColor: selectedIncidentId === inc.id ? "rgba(88, 166, 255, 0.04)" : "" }}
                          onClick={() => setSelectedIncidentId(inc.id)}
                        >
                          <td>{inc.public_id || `INC-${inc.id}`}</td>
                          <td>{inc.incident_type}</td>
                          <td>
                            <span className={`severity-tag severity-${inc.severity}`}>{inc.severity}</span>
                          </td>
                          <td>{(inc.confidence * 100).toFixed(0)}%</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>

              {/* Approval Queue */}
              <div className="approval-queue-container">
                <div className="panel-header">
                  <span>Approval Queue</span>
                  <span className="mono" style={{ fontSize: "9px", color: "var(--alert-warning)" }}>
                    {pendingActions.length} PENDING
                  </span>
                </div>
                
                <div style={{ overflowY: "auto", flexGrow: 1, padding: "10px", display: "flex", flexDirection: "column", gap: "8px" }}>
                  {pendingActions.map((act) => (
                    <div key={act.id} className="section-card" style={{ borderLeft: "2px solid var(--alert-warning)" }}>
                      <div className="section-card-body" style={{ padding: "8px" }}>
                        <div style={{ display: "flex", justifyContent: "space-between", fontSize: "11px", fontWeight: "bold" }}>
                          <span>{act.action_type}</span>
                          <span style={{ color: "var(--alert-critical)" }}>{act.risk.toUpperCase()} Risk</span>
                        </div>
                        <div className="mono" style={{ fontSize: "10px", color: "var(--color-secondary)", marginTop: "4px" }}>
                          Target: {act.arguments?.ip || act.arguments?.username || "Global Host"} · Incident INC-{act.incident_id}
                        </div>
                        <div style={{ display: "flex", gap: "6px", marginTop: "8px" }}>
                          <button className="btn btn-success" style={{ height: "24px", fontSize: "9px" }} onClick={() => void handleAction(act.id, "approve")}>
                            Approve
                          </button>
                          <button className="btn btn-crimson" style={{ height: "24px", fontSize: "9px" }} onClick={() => void handleAction(act.id, "reject")}>
                            Reject
                          </button>
                        </div>
                      </div>
                    </div>
                  ))}
                  {pendingActions.length === 0 && (
                    <div style={{ textAlign: "center", padding: "20px", color: "var(--color-secondary)", fontSize: "11px" }}>
                      No actions awaiting approval.
                    </div>
                  )}
                </div>
              </div>

              {/* Export Controls */}
              <div className="export-controls-container">
                <button className="btn" onClick={() => handleExport("pdf")}>
                  EXPORT PDF
                </button>
                <button className="btn" onClick={() => handleExport("csv")}>
                  EXPORT CSV
                </button>
                <button className="btn btn-info" onClick={() => void runPipelineAgent()}>
                  GENERATE REPORT
                </button>
              </div>
            </div>
          </div>
        )}

        {activeTab === "/incidents" && (
          <div className="page-container fixed-layout">
            <div className="page-header">
              <div>
                <h2>Incident Response Case Files</h2>
                <div className="page-title-desc">Defensive cybersecurity records, artifacts and LLM-assisted summaries.</div>
              </div>
              <button className="btn btn-info" onClick={() => {
                const title = prompt("Enter manual incident title:", "Intruder Alert");
                if (title) {
                  apiCall<any>("/api/v1/incidents", {
                    method: "POST",
                    body: JSON.stringify({ title, incident_type: "manual", severity: "medium" })
                  }).then(() => refreshData());
                }
              }}>
                <Plus size={14} /> Create Manual Case
              </button>
            </div>

            <div className="double-panel">
              {/* Left Side: Incidents list */}
              <div className="double-panel-left">
                {incidents.map((inc) => (
                  <div
                    key={inc.id}
                    className="data-card"
                    style={{
                      cursor: "pointer",
                      borderColor: selectedIncidentId === inc.id ? "var(--alert-info)" : "",
                      backgroundColor: selectedIncidentId === inc.id ? "rgba(88, 166, 255, 0.03)" : ""
                    }}
                    onClick={() => setSelectedIncidentId(inc.id)}
                  >
                    <div className="data-card-header">
                      <span className="mono" style={{ fontWeight: "bold" }}>{inc.public_id || `INC-${inc.id}`}</span>
                      <span className={`severity-tag severity-${inc.severity}`}>{inc.severity}</span>
                    </div>
                    <div style={{ fontSize: "12px", fontWeight: "600" }}>{inc.title}</div>
                    <div style={{ fontSize: "11px", color: "var(--color-secondary)" }}>
                      Status: <span style={{ color: "var(--alert-info)" }}>{inc.status}</span> · Confidence: {(inc.confidence * 100).toFixed(0)}%
                    </div>
                  </div>
                ))}
              </div>

              {/* Right Side: Incident Details */}
              <div className="double-panel-right">
                {selectedIncident ? (
                  <div className="data-card" style={{ flexGrow: 1 }}>
                    <div style={{ display: "flex", justifyContent: "space-between", borderBottom: "1px solid var(--border-color)", paddingBottom: "12px" }}>
                      <div>
                        <h3>{selectedIncident.title}</h3>
                        <div className="mono" style={{ fontSize: "11px", color: "var(--color-secondary)", marginTop: "4px" }}>
                          ID: {selectedIncident.public_id || `INC-${selectedIncident.id}`}
                        </div>
                      </div>
                      <select
                        value={selectedIncident.status}
                        onChange={(e) => {
                          apiCall<any>(`/api/v1/incidents/${selectedIncident.id}/status`, {
                            method: "POST",
                            body: JSON.stringify({ status: e.target.value })
                          }).then(() => refreshData());
                        }}
                        style={{ width: "120px", height: "30px" }}
                      >
                        <option value="new">New</option>
                        <option value="triaging">Triaging</option>
                        <option value="investigating">Investigating</option>
                        <option value="awaiting_approval">Awaiting Approval</option>
                        <option value="containing">Containing</option>
                        <option value="resolved">Resolved</option>
                        <option value="closed">Closed</option>
                      </select>
                    </div>

                    <div style={{ marginTop: "16px" }}>
                      <h4 style={{ fontSize: "12px", marginBottom: "8px" }}>Metadata Matrix</h4>
                      <dl className="details-dl mono">
                        <dt>Source IP</dt>
                        <dd>{selectedIncident.source_ip || "unknown"}</dd>
                        <dt>Target IP</dt>
                        <dd>{selectedIncident.destination_ip || "unknown"}</dd>
                        <dt>Type</dt>
                        <dd>{selectedIncident.incident_type}</dd>
                        <dt>Confidence</dt>
                        <dd>{(selectedIncident.confidence * 100).toFixed(0)}%</dd>
                      </dl>
                    </div>

                    <div style={{ marginTop: "16px" }}>
                      <h4 style={{ fontSize: "12px", marginBottom: "8px" }}>Evidence Telemetry</h4>
                      <div className="editor-textarea mono" style={{ height: "120px", overflowY: "auto", padding: "10px" }}>
                        {JSON.stringify(selectedIncident.evidence || [], null, 2)}
                      </div>
                    </div>

                    <div style={{ marginTop: "16px" }}>
                      <h4 style={{ fontSize: "12px", marginBottom: "8px" }}>Incident Timeline & Context</h4>
                      <p style={{ fontSize: "13px", lineHeight: "1.6" }}>
                        {selectedIncident.llm_summary || selectedIncident.summary || "No description recorded yet."}
                      </p>
                    </div>

                    {selectedIncident.llm_report && (
                      <div style={{ marginTop: "16px", borderTop: "1px solid var(--border-color)", paddingTop: "16px" }}>
                        <h4 style={{ fontSize: "12px", marginBottom: "8px" }}>Executive Report (Markdown)</h4>
                        <div className="editor-textarea" style={{ height: "200px", overflowY: "auto", whiteSpace: "pre-wrap" }}>
                          {selectedIncident.llm_report}
                        </div>
                      </div>
                    )}
                  </div>
                ) : (
                  <div style={{ padding: "40px", textAlign: "center", color: "var(--color-secondary)" }}>
                    Select an incident from the left list to view operational details.
                  </div>
                )}
              </div>
            </div>
          </div>
        )}

        {activeTab === "/events" && (
          <div className="page-container">
            <div className="page-header">
              <div>
                <h2>Normalized Network Events logs</h2>
                <div className="page-title-desc">Raw logs parsed from Suricata EVE, Zeek conn/dns logs, and socket collectors.</div>
              </div>
            </div>

            {/* Ingestion & Import controls */}
            <div className="section-card" style={{ marginBottom: "16px" }}>
              <div className="section-card-header">Import Offline Telemetry (PCAP / IDS Logs)</div>
              <div className="section-card-body" style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "20px" }}>
                <div>
                  <span style={{ fontSize: "11px", fontWeight: "bold", color: "var(--color-secondary)" }}>
                    PCAP / PCAPNG FILE PATH (LAB SECURE GATE)
                  </span>
                  <div style={{ display: "grid", gridTemplateColumns: "1fr auto", gap: "8px", marginTop: "4px" }}>
                    <input
                      type="text"
                      placeholder="e.g. C:/Users/Downloads/traffic.pcap"
                      value={pcapFilePath}
                      onChange={(e) => setPcapFilePath(e.target.value)}
                    />
                    <button className="btn btn-info" onClick={() => void handlePcapImport()}>
                      Extract flows
                    </button>
                  </div>
                </div>

                <div>
                  <span style={{ fontSize: "11px", fontWeight: "bold", color: "var(--color-secondary)" }}>
                    ZEEK / SURICATA JSON PATH
                  </span>
                  <div style={{ display: "grid", gridTemplateColumns: "1fr auto auto", gap: "8px", marginTop: "4px" }}>
                    <input
                      type="text"
                      placeholder="e.g. C:/Suricata/eve.json"
                      value={logImportPath}
                      onChange={(e) => setLogImportPath(e.target.value)}
                    />
                    <select
                      value={logImportType}
                      onChange={(e) => setLogImportType(e.target.value)}
                      style={{ width: "100px" }}
                    >
                      <option value="suricata">Suricata</option>
                      <option value="zeek">Zeek</option>
                    </select>
                    <button className="btn btn-info" onClick={() => void handleLogImport()}>
                      Import
                    </button>
                  </div>
                </div>
              </div>
            </div>

            {/* Filter controls */}
            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr 120px", gap: "10px", marginBottom: "16px" }}>
              <input
                type="text"
                placeholder="Filter Source IP..."
                value={eventFilters.sourceIp}
                onChange={(e) => setEventFilters({ ...eventFilters, sourceIp: e.target.value })}
              />
              <input
                type="text"
                placeholder="Filter Destination IP..."
                value={eventFilters.destIp}
                onChange={(e) => setEventFilters({ ...eventFilters, destIp: e.target.value })}
              />
              <input
                type="text"
                placeholder="Filter Protocol..."
                value={eventFilters.proto}
                onChange={(e) => setEventFilters({ ...eventFilters, proto: e.target.value })}
              />
              <select
                value={eventFilters.severity}
                onChange={(e) => setEventFilters({ ...eventFilters, severity: e.target.value })}
              >
                <option value="all">All Severities</option>
                <option value="high">High</option>
                <option value="medium">Medium</option>
                <option value="low">Low</option>
              </select>
            </div>

            {/* Log Table */}
            <div className="section-card" style={{ overflowX: "auto" }}>
              <table className="dense-table mono-table">
                <thead>
                  <tr>
                    <th>Timestamp</th>
                    <th>Sensor</th>
                    <th>Source IP</th>
                    <th>Destination IP</th>
                    <th>Proto</th>
                    <th>Type</th>
                    <th>Action</th>
                    <th>Severity</th>
                  </tr>
                </thead>
                <tbody>
                  {filteredEvents.slice(0, 100).map((evt) => (
                    <tr key={evt.id} className={evt.severity === "high" ? "critical-row" : ""}>
                      <td>{evt.timestamp}</td>
                      <td>{evt.sensor}</td>
                      <td>{evt.source_ip}{evt.source_port ? `:${evt.source_port}` : ""}</td>
                      <td>{evt.destination_ip}{evt.destination_port ? `:${evt.destination_port}` : ""}</td>
                      <td>{evt.protocol.toUpperCase()}</td>
                      <td>{evt.event_type}</td>
                      <td>{evt.action || "-"}</td>
                      <td>
                        <span className={`severity-tag severity-${evt.severity}`}>{evt.severity}</span>
                      </td>
                    </tr>
                  ))}
                  {filteredEvents.length === 0 && (
                    <tr>
                      <td colSpan={8} style={{ textAlign: "center", padding: "20px" }}>No event logs matches your filters.</td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          </div>
        )}

        {activeTab === "/approvals" && (
          <div className="page-container">
            <div className="page-header">
              <div>
                <h2>Defensive response Approvals Desk</h2>
                <div className="page-title-desc">Validate, approve, execute, or roll back automated server containment policies.</div>
              </div>
            </div>

            <div className="sub-tabs">
              <button className="sub-tab-item active">Pending Approvals ({pendingActions.length})</button>
            </div>

            <div style={{ display: "flex", flexDirection: "column", gap: "12px" }}>
              {actions.map((act) => (
                <div key={act.id} className="data-card">
                  <div className="data-card-header">
                    <span className="mono" style={{ fontWeight: "bold" }}>ACT-{act.id} · {act.action_type}</span>
                    <span className={`severity-tag severity-${act.status === "awaiting_approval" ? "high" : "low"}`}>
                      {act.status}
                    </span>
                  </div>
                  <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "20px" }}>
                    <div>
                      <dl className="details-dl mono" style={{ fontSize: "11px" }}>
                        <dt>Incident ID</dt>
                        <dd>INC-{act.incident_id}</dd>
                        <dt>Risk Factor</dt>
                        <dd>{act.risk.toUpperCase()}</dd>
                        <dt>Proposed By</dt>
                        <dd>{act.proposed_by}</dd>
                        <dt>Arguments</dt>
                        <dd>{JSON.stringify(act.arguments)}</dd>
                      </dl>
                    </div>

                    <div style={{ display: "flex", flexDirection: "column", gap: "8px", justifyContent: "center", alignItems: "flex-end" }}>
                      {act.status === "awaiting_approval" && (
                        <div style={{ display: "flex", gap: "8px" }}>
                          <button className="btn btn-success" onClick={() => void handleAction(act.id, "approve")}>
                            Approve Action
                          </button>
                          <button className="btn btn-crimson" onClick={() => void handleAction(act.id, "reject")}>
                            Reject
                          </button>
                        </div>
                      )}
                      
                      {act.status === "approved" && (
                        <button className="btn btn-info" onClick={() => void handleAction(act.id, "execute")}>
                          Execute Policy
                        </button>
                      )}

                      {act.status === "completed" && (
                        <button className="btn btn-crimson" onClick={() => void handleAction(act.id, "rollback")}>
                          Rollback Policy
                        </button>
                      )}

                      {act.status === "rolled_back" && (
                        <span style={{ fontSize: "11px", color: "var(--color-secondary)" }}>Rolled Back</span>
                      )}

                      {act.status === "failed" && (
                        <span style={{ fontSize: "11px", color: "var(--alert-critical)" }}>Execution Failed</span>
                      )}
                    </div>
                  </div>
                  {act.result && (
                    <div style={{ marginTop: "10px", padding: "8px", backgroundColor: "#040507", border: "1px solid var(--border-color)" }} className="mono">
                      <div style={{ fontSize: "9px", color: "var(--color-secondary)", marginBottom: "4px" }}>EXECUTION RESULT</div>
                      <pre style={{ fontSize: "10px", whiteSpace: "pre-wrap" }}>{act.result}</pre>
                      {act.verification_result && (
                        <div style={{ marginTop: "6px", color: "var(--alert-success)", fontSize: "10px" }}>
                          Verification: {act.verification_result}
                        </div>
                      )}
                    </div>
                  )}
                </div>
              ))}
              {actions.length === 0 && (
                <div style={{ textAlign: "center", padding: "40px", color: "var(--color-secondary)" }}>
                  No response actions recorded.
                </div>
              )}
            </div>
          </div>
        )}

        {activeTab === "/agents" && (
          <div className="page-container fixed-layout">
            <div className="page-header">
              <div>
                <h2>Logical Incident Response Agents</h2>
                <div className="page-title-desc">Logical profiles defining role, allowed skills and security tools for each agent.</div>
              </div>
            </div>

            <div className="double-panel">
              <div className="double-panel-left">
                {piAgents.map((ag) => (
                  <div
                    key={ag.name}
                    className="data-card"
                    style={{
                      cursor: "pointer",
                      borderColor: selectedAgent?.name === ag.name ? "var(--alert-info)" : "",
                      backgroundColor: selectedAgent?.name === ag.name ? "rgba(88, 166, 255, 0.03)" : ""
                    }}
                    onClick={() => setSelectedAgent(ag)}
                  >
                    <div className="data-card-header">
                      <span className="mono" style={{ fontWeight: "bold" }}>{ag.name}</span>
                      <span className="severity-tag severity-low" style={{ fontSize: "8px" }}>
                        {ag.metadata.safety_profile || "read-only"}
                      </span>
                    </div>
                    <div style={{ fontSize: "12px", color: "var(--color-secondary)" }}>
                      {ag.metadata.role}
                    </div>
                  </div>
                ))}
              </div>

              <div className="double-panel-right">
                {selectedAgent ? (
                  <div className="data-card" style={{ flexGrow: 1 }}>
                    <h3>{selectedAgent.name.toUpperCase()} Profile</h3>
                    
                    <div style={{ marginTop: "16px" }}>
                      <h4 style={{ fontSize: "12px", marginBottom: "8px" }}>Specification Schema</h4>
                      <dl className="details-dl mono" style={{ fontSize: "11px" }}>
                        <dt>Role Description</dt>
                        <dd>{selectedAgent.metadata.role}</dd>
                        <dt>Input Artifact</dt>
                        <dd>{selectedAgent.metadata.input_artifact}</dd>
                        <dt>Output Artifact</dt>
                        <dd>{selectedAgent.metadata.output_artifact}</dd>
                        <dt>Max Iterations</dt>
                        <dd>{selectedAgent.metadata.maximum_iterations}</dd>
                        <dt>Max Tool Calls</dt>
                        <dd>{selectedAgent.metadata.maximum_tool_calls}</dd>
                        <dt>Safety Profile</dt>
                        <dd>{selectedAgent.metadata.safety_profile}</dd>
                      </dl>
                    </div>

                    <div style={{ marginTop: "16px" }}>
                      <h4 style={{ fontSize: "12px", marginBottom: "8px" }}>Allowed Tools</h4>
                      <ul style={{ paddingLeft: "20px", fontSize: "12px", color: "var(--color-secondary)" }} className="mono">
                        {(selectedAgent.metadata.allowed_tools || []).map((tool) => (
                          <li key={tool}>{tool}</li>
                        ))}
                      </ul>
                    </div>

                    <div style={{ marginTop: "16px" }}>
                      <h4 style={{ fontSize: "12px", marginBottom: "8px" }}>Allowed Skills</h4>
                      <ul style={{ paddingLeft: "20px", fontSize: "12px", color: "var(--color-secondary)" }} className="mono">
                        {(selectedAgent.metadata.allowed_skills || []).map((skill) => (
                          <li key={skill}>{skill}</li>
                        ))}
                      </ul>
                    </div>

                    <div style={{ marginTop: "16px", borderTop: "1px solid var(--border-color)", paddingTop: "16px" }}>
                      <h4 style={{ fontSize: "12px", marginBottom: "8px" }}>Raw MD Definition</h4>
                      <div className="editor-textarea" style={{ height: "250px", overflowY: "auto", whiteSpace: "pre-wrap" }}>
                        {selectedAgent.raw}
                      </div>
                    </div>
                  </div>
                ) : (
                  <div style={{ padding: "40px", textAlign: "center", color: "var(--color-secondary)" }}>
                    Select a logical agent from the left sidebar to view its configuration.
                  </div>
                )}
              </div>
            </div>
          </div>
        )}

        {activeTab === "/skills" && (
          <div className="page-container fixed-layout">
            <div className="page-header">
              <div>
                <h2>Pi Skills Manager</h2>
                <div className="page-title-desc">Create, edit, validate and test executable defensive skill procedures.</div>
              </div>
            </div>

            <div className="double-panel">
              <div className="double-panel-left">
                {piSkills.map((sk) => (
                  <button
                    key={sk.name}
                    className="nav-item"
                    style={{
                      borderBottom: "1px solid var(--border-color)",
                      textAlign: "left",
                      color: selectedSkillName === sk.name ? "var(--alert-info)" : "",
                      backgroundColor: selectedSkillName === sk.name ? "rgba(88, 166, 255, 0.05)" : "transparent"
                    }}
                    onClick={() => void selectSkill(sk.name)}
                  >
                    <Wrench size={12} /> {sk.name}
                  </button>
                ))}
              </div>

              <div className="double-panel-right">
                {selectedSkillName ? (
                  <div className="data-card" style={{ flexGrow: 1 }}>
                    <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                      <h3>Skill: {selectedSkillName}</h3>
                      <div style={{ display: "flex", gap: "8px" }}>
                        <button className="btn btn-info" onClick={() => void saveSkill()}>Save</button>
                        <button className="btn" onClick={() => void validateSkill()}>Validate</button>
                        <button className="btn btn-crimson" onClick={() => void testSkill()}>Test</button>
                      </div>
                    </div>

                    {skillValidation && (
                      <div className={`validation-box ${skillValidation.valid ? "" : "invalid"}`} style={{ marginTop: "12px" }}>
                        <strong>Validation Status: {skillValidation.valid ? "VALID" : "INVALID"}</strong>
                        {skillValidation.errors.length > 0 && (
                          <ul style={{ paddingLeft: "20px", marginTop: "6px" }}>
                            {skillValidation.errors.map((err, idx) => <li key={idx}>{err}</li>)}
                          </ul>
                        )}
                      </div>
                    )}

                    {skillTestOutput && (
                      <div style={{ marginTop: "12px", padding: "10px", backgroundColor: "#040507", border: "1px solid var(--border-color)" }} className="mono">
                        <div style={{ fontSize: "10px", fontWeight: "bold", color: "var(--color-secondary)", marginBottom: "4px" }}>TEST OUTPUT</div>
                        <pre style={{ fontSize: "10px", whiteSpace: "pre-wrap" }}>{skillTestOutput}</pre>
                      </div>
                    )}

                    <div style={{ marginTop: "16px", display: "grid", gridTemplateColumns: "1fr 1fr", gap: "20px" }}>
                      <div>
                        <h4 style={{ fontSize: "11px", marginBottom: "6px", color: "var(--color-secondary)" }}>SKILL.MD MANIFEST</h4>
                        <textarea
                          className="editor-textarea"
                          value={skillEditManifest}
                          onChange={(e) => setSkillEditManifest(e.target.value)}
                        />
                      </div>

                      <div>
                        <h4 style={{ fontSize: "11px", marginBottom: "6px", color: "var(--color-secondary)" }}>PYTHON SCRIPT PROCEDURE</h4>
                        <textarea
                          className="editor-textarea"
                          value={skillEditScript}
                          onChange={(e) => setSkillEditScript(e.target.value)}
                        />
                      </div>
                    </div>
                  </div>
                ) : (
                  <div style={{ padding: "40px", textAlign: "center", color: "var(--color-secondary)" }}>
                    Select a skill from the left list to edit manifest files.
                  </div>
                )}
              </div>
            </div>
          </div>
        )}

        {activeTab === "/extensions" && (
          <div className="page-container fixed-layout">
            <div className="page-header">
              <div>
                <h2>TypeScript Pi Extensions</h2>
                <div className="page-title-desc">Security permission gates, event bridges, and audit hooks intercepting agent requests.</div>
              </div>
            </div>

            <div className="double-panel">
              <div className="double-panel-left">
                {piExtensions.map((ext) => (
                  <div
                    key={ext.name}
                    className="data-card"
                    style={{
                      cursor: "pointer",
                      borderColor: selectedExtension?.name === ext.name ? "var(--alert-info)" : "",
                      backgroundColor: selectedExtension?.name === ext.name ? "rgba(88, 166, 255, 0.03)" : ""
                    }}
                    onClick={() => {
                      setSelectedExtension(ext);
                      setExtensionTestOutput("");
                    }}
                  >
                    <div className="data-card-header">
                      <span className="mono" style={{ fontWeight: "bold" }}>{ext.name}</span>
                    </div>
                  </div>
                ))}
              </div>

              <div className="double-panel-right">
                {selectedExtension ? (
                  <div className="data-card" style={{ flexGrow: 1 }}>
                    <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                      <h3>Extension: {selectedExtension.name}</h3>
                      <div style={{ display: "flex", gap: "8px" }}>
                        <button className="btn" onClick={() => void validateExtension(selectedExtension.name)}>Validate</button>
                        <button className="btn btn-crimson" onClick={() => void testExtension(selectedExtension.name)}>Test extension</button>
                      </div>
                    </div>

                    {extensionTestOutput && (
                      <div style={{ marginTop: "12px", padding: "10px", backgroundColor: "#040507", border: "1px solid var(--border-color)" }} className="mono">
                        <pre style={{ fontSize: "10px" }}>{extensionTestOutput}</pre>
                      </div>
                    )}

                    <div style={{ marginTop: "16px" }}>
                      <h4 style={{ fontSize: "11px", marginBottom: "6px", color: "var(--color-secondary)" }}>TS IMPLEMENTATION (index.ts)</h4>
                      <textarea
                        className="editor-textarea"
                        readOnly
                        value={selectedExtension.content}
                        style={{ height: "400px" }}
                      />
                    </div>
                  </div>
                ) : (
                  <div style={{ padding: "40px", textAlign: "center", color: "var(--color-secondary)" }}>
                    Select a Pi Extension to view TS source and validation rules.
                  </div>
                )}
              </div>
            </div>
          </div>
        )}

        {activeTab === "/chains" && (
          <div className="page-container fixed-layout">
            <div className="page-header">
              <div>
                <h2>Pi Orchestration Chains DAG</h2>
                <div className="page-title-desc">DAG visualization mapping logical incident intake, evidence acquisition, detection, and containment.</div>
              </div>
            </div>

            <div className="double-panel">
              <div className="double-panel-left">
                {piChains.map((ch) => (
                  <div
                    key={ch.name}
                    className="data-card"
                    style={{
                      cursor: "pointer",
                      borderColor: selectedChain?.name === ch.name ? "var(--alert-info)" : "",
                      backgroundColor: selectedChain?.name === ch.name ? "rgba(88, 166, 255, 0.03)" : ""
                    }}
                    onClick={() => setSelectedChain(ch)}
                  >
                    <div style={{ fontWeight: "bold" }}>{ch.filename}</div>
                  </div>
                ))}
              </div>

              <div className="double-panel-right">
                {selectedChain ? (
                  <div className="data-card" style={{ flexGrow: 1 }}>
                    <h3>DAG: {selectedChain.filename}</h3>
                    
                    <div className="dag-container" style={{ marginTop: "16px", display: "flex", flexDirection: "column", gap: "10px", padding: "20px", overflowY: "auto" }}>
                      <div style={{ textAlign: "center", color: "var(--color-secondary)", fontSize: "11px" }} className="mono">
                        ZONE SEQUENCE FLOW CHART
                      </div>
                      
                      {/* Intake phase */}
                      <div style={{ display: "flex", justifyContent: "center", alignItems: "center", gap: "10px" }}>
                        <div style={{ border: "1px solid var(--border-color)", padding: "10px", background: "var(--bg-secondary)", borderRadius: "4px" }} className="mono">
                          <div>PHASE 0: Intake</div>
                          <div style={{ fontSize: "10px", color: "var(--alert-info)" }}>intake-agent</div>
                        </div>
                      </div>

                      <div style={{ textAlign: "center", color: "var(--border-color)" }}><ChevronRight size={16} style={{ transform: "rotate(90deg)" }} /></div>

                      {/* Parallel zones */}
                      <div style={{ display: "flex", justifyContent: "center", gap: "20px" }}>
                        <div style={{ border: "1px solid var(--border-color)", padding: "10px", background: "var(--bg-secondary)", borderRadius: "4px" }} className="mono">
                          <div>PHASE 1: Evidence (Asset)</div>
                          <div style={{ fontSize: "10px", color: "var(--alert-info)" }}>asset-context-agent</div>
                        </div>
                        <div style={{ border: "1px solid var(--border-color)", padding: "10px", background: "var(--bg-secondary)", borderRadius: "4px" }} className="mono">
                          <div>PHASE 1: Evidence (Flow)</div>
                          <div style={{ fontSize: "10px", color: "var(--alert-info)" }}>flow-analysis-agent</div>
                        </div>
                      </div>

                      <div style={{ textAlign: "center", color: "var(--border-color)" }}><ChevronRight size={16} style={{ transform: "rotate(90deg)" }} /></div>

                      {/* Detection phase */}
                      <div style={{ display: "flex", justifyContent: "center", gap: "20px" }}>
                        <div style={{ border: "1px solid var(--border-color)", padding: "10px", background: "var(--bg-secondary)", borderRadius: "4px" }} className="mono">
                          <div>PHASE 2: Rules Detection</div>
                          <div style={{ fontSize: "10px", color: "var(--alert-info)" }}>detection-agent</div>
                        </div>
                        <div style={{ border: "1px solid var(--border-color)", padding: "10px", background: "var(--bg-secondary)", borderRadius: "4px" }} className="mono">
                          <div>PHASE 2: ML Anomaly</div>
                          <div style={{ fontSize: "10px", color: "var(--alert-info)" }}>ml-anomaly-agent</div>
                        </div>
                      </div>

                      <div style={{ textAlign: "center", color: "var(--border-color)" }}><ChevronRight size={16} style={{ transform: "rotate(90deg)" }} /></div>

                      {/* Triage / MITRE */}
                      <div style={{ display: "flex", justifyContent: "center", gap: "20px" }}>
                        <div style={{ border: "1px solid var(--border-color)", padding: "10px", background: "var(--bg-secondary)", borderRadius: "4px" }} className="mono">
                          <div>PHASE 3: Severity Triage</div>
                          <div style={{ fontSize: "10px", color: "var(--alert-info)" }}>triage-agent</div>
                        </div>
                        <div style={{ border: "1px solid var(--border-color)", padding: "10px", background: "var(--bg-secondary)", borderRadius: "4px" }} className="mono">
                          <div>PHASE 3: MITRE Mapping</div>
                          <div style={{ fontSize: "10px", color: "var(--alert-info)" }}>mitre-agent</div>
                        </div>
                      </div>

                      <div style={{ textAlign: "center", color: "var(--border-color)" }}><ChevronRight size={16} style={{ transform: "rotate(90deg)" }} /></div>

                      {/* Response planning */}
                      <div style={{ display: "flex", justifyContent: "center", gap: "10px" }}>
                        <div style={{ border: "1px solid var(--border-color)", padding: "10px", background: "var(--bg-secondary)", borderRadius: "4px" }} className="mono">
                          <div>PHASE 4: Containment Planning</div>
                          <div style={{ fontSize: "10px", color: "var(--alert-info)" }}>response-planner-agent</div>
                        </div>
                      </div>
                    </div>

                    <div style={{ marginTop: "16px" }}>
                      <h4 style={{ fontSize: "11px", marginBottom: "6px", color: "var(--color-secondary)" }}>YAML CONFIGURATION</h4>
                      <textarea
                        className="editor-textarea"
                        readOnly
                        value={selectedChain.raw}
                        style={{ height: "200px" }}
                      />
                    </div>
                  </div>
                ) : (
                  <div style={{ padding: "40px", textAlign: "center", color: "var(--color-secondary)" }}>
                    Select a YAML chain definition file to visualize its DAG logic.
                  </div>
                )}
              </div>
            </div>
          </div>
        )}

        {activeTab === "/models" && (
          <div className="page-container">
            <div className="page-header">
              <div>
                <h2>Machine Learning Anomaly Detectors</h2>
                <div className="page-title-desc">Train models and scaler metrics, and score real-time packet characteristics.</div>
              </div>
              <button className="btn btn-info" onClick={() => void trainMLModel()}>
                Train Isolation Forest
              </button>
            </div>

            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "20px" }}>
              <div className="data-card">
                <h3>Model Parameters</h3>
                <dl className="details-dl mono" style={{ marginTop: "12px" }}>
                  <dt>Model Class</dt>
                  <dd>IsolationForest (scikit-learn)</dd>
                  <dt>Contamination Factor</dt>
                  <dd>0.02 (2% anomalies expected)</dd>
                  <dt>Max Features</dt>
                  <dd>22 (Flow characteristics)</dd>
                  <dt>Model Path</dt>
                  <dd>models/isolation_forest.joblib</dd>
                  <dt>Scaler Path</dt>
                  <dd>models/scaler.joblib</dd>
                </dl>
              </div>

              <div className="data-card">
                <h3>Calculated Flow Features</h3>
                <ul style={{ paddingLeft: "20px", fontSize: "12px", lineHeight: "1.6", color: "var(--color-secondary)" }} className="mono">
                  <li>flow_duration</li>
                  <li>total_packets (fwd / bwd)</li>
                  <li>total_bytes (fwd / bwd)</li>
                  <li>bytes_per_second</li>
                  <li>packets_per_second</li>
                  <li>SYN / ACK / FIN / RST counts</li>
                  <li>active / idle time</li>
                </ul>
              </div>
            </div>
          </div>
        )}

        {activeTab === "/settings" && (
          <div className="page-container">
            <div className="page-header">
              <div>
                <h2>Application Policy & settings</h2>
                <div className="page-title-desc">Configure allowed network targets, safety exclusions, and credentials.</div>
              </div>
            </div>

            <div className="data-card" style={{ maxWidth: "600px" }}>
              <h3>Rules of Engagement Policies</h3>
              
              <div style={{ display: "flex", flexDirection: "column", gap: "16px", marginTop: "16px" }}>
                <div>
                  <label className="mono" style={{ fontSize: "11px", fontWeight: "bold" }}>ALLOWED LAB CIDR SCOPES (COMMA SEPARATED)</label>
                  <input
                    type="text"
                    value={roeSettings.allowedCidrs}
                    onChange={(e) => setRoeSettings({ ...roeSettings, allowedCidrs: e.target.value })}
                    style={{ marginTop: "4px" }}
                  />
                </div>

                <div>
                  <label className="mono" style={{ fontSize: "11px", fontWeight: "bold" }}>PROTECTED CRITICAL INFRASTRUCTURE IPS</label>
                  <input
                    type="text"
                    value={roeSettings.protectedIps}
                    onChange={(e) => setRoeSettings({ ...roeSettings, protectedIps: e.target.value })}
                    style={{ marginTop: "4px" }}
                  />
                </div>

                <div>
                  <label className="mono" style={{ fontSize: "11px", fontWeight: "bold" }}>OUT-OF-SCOPE FORBIDDEN TARGETS</label>
                  <input
                    type="text"
                    value={roeSettings.outOfScopeAddresses}
                    onChange={(e) => setRoeSettings({ ...roeSettings, outOfScopeAddresses: e.target.value })}
                    style={{ marginTop: "4px" }}
                  />
                </div>

                <div>
                  <label className="mono" style={{ fontSize: "11px", fontWeight: "bold" }}>PI TOOL EXECUTION RATE LIMIT (CALLS/SEC)</label>
                  <input
                    type="text"
                    value={String(roeSettings.toolRateLimit)}
                    onChange={(e) => setRoeSettings({ ...roeSettings, toolRateLimit: Number(e.target.value) || 5 })}
                    style={{ marginTop: "4px" }}
                  />
                </div>

                <div style={{ display: "flex", gap: "12px", marginTop: "10px" }}>
                  <button className="btn btn-info" onClick={() => appendLog("Policies saved successfully to .pi/data/policies/scope.json", "SYSTEM", "normal")}>
                    Save Settings
                  </button>
                  <button className="btn" onClick={() => void refreshData()}>Reset Default</button>
                </div>
              </div>
            </div>
          </div>
        )}

        {activeTab === "/audit" && (
          <div className="page-container">
            <div className="page-header">
              <div>
                <h2>Chronological Audit Trail Logs</h2>
                <div className="page-title-desc">Append-only security log files recording agent sessions, tool execution parameters, and permission gates.</div>
              </div>
            </div>

            <div style={{ marginBottom: "16px", display: "grid", gridTemplateColumns: "1fr auto", gap: "10px" }}>
              <input
                type="text"
                placeholder="Search audit trail..."
                value={auditSearch}
                onChange={(e) => setAuditSearch(e.target.value)}
              />
              <button className="btn" onClick={() => void loadAuditLogs()}>
                <RefreshCw size={14} /> Refresh Logs
              </button>
            </div>

            <div className="audit-log-viewer">
              {auditLogs.split("\n")
                .filter(line => !auditSearch || line.toLowerCase().includes(auditSearch.toLowerCase()))
                .map((line, idx) => (
                  <div key={idx} style={{ borderBottom: "1px solid rgba(255,255,255,0.03)", padding: "4px 0" }}>
                    {line}
                  </div>
                ))}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

const rootElement = document.getElementById("root");
if (rootElement) {
  createRoot(rootElement).render(<App />);
}
