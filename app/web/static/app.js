const state = {
  sampleAlert: null,
  selectedResource: null,
};

const $ = (id) => document.getElementById(id);

function addMessage(role, text, meta = "") {
  const node = document.createElement("div");
  node.className = `message ${role}`;
  node.innerHTML = `
    <div class="message-role">${role === "user" ? "You" : "Pi agent"}${meta ? ` · ${meta}` : ""}</div>
    <div class="message-body"></div>
  `;
  node.querySelector(".message-body").textContent = text;
  $("chatStream").appendChild(node);
  $("chatStream").scrollTop = $("chatStream").scrollHeight;
}

function setBusy(isBusy) {
  $("sendButton").disabled = isBusy;
  $("latestButton").disabled = isBusy;
  $("sendButton").textContent = isBusy ? "Running..." : "Send";
}

async function requestJson(url, options = {}) {
  const response = await fetch(url, {
    headers: { "Content-Type": "application/json" },
    ...options,
  });
  if (!response.ok) {
    const text = await response.text();
    throw new Error(text || response.statusText);
  }
  return response.json();
}

function parseAlert() {
  const raw = $("alertInput").value.trim();
  if (!raw) return null;
  return JSON.parse(raw);
}

function renderResources(resources) {
  renderResourceList("skillList", "skills", resources.skills || []);
  renderResourceList("pluginList", "plugins", resources.plugins || []);
}

function renderResourceList(targetId, kind, items) {
  const target = $(targetId);
  target.innerHTML = items.length
    ? items.map((item) => `<button class="resource" data-kind="${kind}" data-name="${item.name}">${item.name}</button>`).join("")
    : `<div class="empty">No ${kind} yet.</div>`;
  target.querySelectorAll(".resource").forEach((button) => {
    button.addEventListener("click", () => loadResource(button.dataset.kind, button.dataset.name));
  });
}

async function loadResource(kind, name) {
  const resource = await requestJson(`/api/resources/${kind}/${encodeURIComponent(name)}`);
  state.selectedResource = { kind, name };
  $("editorTitle").textContent = `${kind}: ${name}`;
  $("resourceName").value = name;
  $("resourceEditor").value = resource.content;
  addMessage("assistant", `Loaded ${kind.slice(0, -1)} ${name} for editing.`);
}

async function saveResource() {
  const kind = state.selectedResource?.kind || "skills";
  const name = $("resourceName").value.trim();
  if (!name) {
    addMessage("assistant", "Give the resource a file name first, for example custom-response.md.");
    return;
  }
  await requestJson(`/api/resources/${kind}/${encodeURIComponent(name)}`, {
    method: "PUT",
    body: JSON.stringify({ name, content: $("resourceEditor").value }),
  });
  state.selectedResource = { kind, name };
  addMessage("assistant", `Saved ${kind.slice(0, -1)} ${name}.`);
  await refreshResources();
}

function newResource(kind) {
  state.selectedResource = { kind, name: "" };
  $("editorTitle").textContent = `New ${kind.slice(0, -1)}`;
  $("resourceName").value = kind === "skills" ? "custom-skill.md" : "custom-plugin.json";
  $("resourceEditor").value = kind === "skills"
    ? "---\nname: custom-skill\ndescription: Describe when the Pi agent should use this skill.\n---\n\n# Custom Skill\n\n## Behavior\n\n- Add steps here.\n"
    : "{\n  \"name\": \"custom-plugin\",\n  \"description\": \"Describe the local plugin capability.\",\n  \"commands\": []\n}\n";
}

async function refreshResources() {
  const data = await requestJson("/api/resources");
  renderResources(data);
}

function renderRun(payload) {
  if (!payload.triage) return;
  const triage = payload.triage;
  const classification = triage.classification || {};
  const llm = triage.llm_analysis || {};
  $("classification").textContent = classification.label || "-";
  $("severity").textContent = classification.severity || "-";
  $("llmAvailable").textContent = llm.available ? "Live" : "Fallback";
  $("reportOutput").textContent = payload.report || llm.report || "";
  $("auditLog").textContent = [payload.audit_log, payload.permission_log].filter(Boolean).join("\n");
}

function renderAgentPayload(payload) {
  if (payload.agent_run) {
    $("llmAvailable").textContent = payload.agent_run.provider ? "Agent" : "Fallback";
    $("auditLog").textContent = JSON.stringify(payload.agent_run, null, 2);
  }
  if (payload.incidents) {
    $("auditLog").textContent = JSON.stringify({ incidents: payload.incidents }, null, 2);
  }
}

async function sendChat() {
  const command = $("chatInput").value.trim();
  if (!command) return;
  addMessage("user", command);
  setBusy(true);
  try {
    const data = await requestJson("/api/chat", {
      method: "POST",
      body: JSON.stringify({ command, alert: parseAlert() }),
    });
    addMessage("assistant", data.assistant || "Command completed.", data.mode || "");
    if (data.triage) renderRun(data);
    if (data.agent_run || data.incidents) renderAgentPayload(data);
    if (data.resources) renderResources(data.resources);
  } catch (error) {
    addMessage("assistant", error.message, "error");
  } finally {
    setBusy(false);
  }
}

async function loadLatest() {
  setBusy(true);
  try {
    const data = await requestJson("/api/runs/latest");
    addMessage("assistant", "Loaded latest incident run.", "latest");
    renderRun(data);
  } catch (error) {
    addMessage("assistant", error.message, "error");
  } finally {
    setBusy(false);
  }
}

async function init() {
  $("sendButton").addEventListener("click", sendChat);
  $("latestButton").addEventListener("click", loadLatest);
  $("saveResourceButton").addEventListener("click", saveResource);
  $("newSkillButton").addEventListener("click", () => newResource("skills"));
  $("newPluginButton").addEventListener("click", () => newResource("plugins"));
  $("sampleButton").addEventListener("click", () => {
    $("alertInput").value = JSON.stringify(state.sampleAlert, null, 2);
  });
  $("chatInput").addEventListener("keydown", (event) => {
    if (event.key === "Enter" && (event.ctrlKey || event.metaKey)) sendChat();
  });

  const status = await requestJson("/api/status");
  state.sampleAlert = status.sample_alert;
  $("llmLine").textContent = `${status.llm.configured ? "Live" : "Fallback"} · ${status.llm.model}`;
  $("alertInput").value = JSON.stringify(status.sample_alert, null, 2);
  renderResources(status.resources);
  if (status.latest_run) renderRun(status.latest_run);
  addMessage("assistant", "Ready. Send a command to analyze, triage, list skills/plugins, or edit resources in the workspace.");
}

init().catch((error) => addMessage("assistant", error.message, "error"));
