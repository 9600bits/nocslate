const nativeFetch = globalThis.fetch.bind(globalThis);

function readCookie(name) {
  const prefix = `${encodeURIComponent(name)}=`;
  for (const item of document.cookie.split(";")) {
    const value = item.trim();
    if (value.startsWith(prefix)) return decodeURIComponent(value.slice(prefix.length));
  }
  return "";
}

// All API mutations pass through this local-session boundary. Keeping the wrapper
// in one place also protects older modules that still call `fetch` in this file.
function fetch(input, init = {}) {
  const method = String(init.method || "GET").toUpperCase();
  const headers = new Headers(init.headers || {});
  if (!["GET", "HEAD", "OPTIONS"].includes(method)) {
    const csrf = readCookie("nocslate_csrf");
    if (csrf) headers.set("X-CSRF-Token", csrf);
  }
  return nativeFetch(input, { credentials: "same-origin", ...init, headers });
}

async function unwrap(resp) {
  if (!resp.ok) {
    let msg = `请求失败 (${resp.status})`;
    try {
      const data = await resp.json();
      if (data.detail) msg = data.detail;
    } catch { /* ignore */ }
    throw new Error(msg);
  }
  return resp.json();
}

export function apiRequest(path, options = {}) {
  const init = { ...options };
  if (init.json !== undefined) {
    init.headers = { ...(init.headers || {}), "Content-Type": "application/json" };
    init.body = JSON.stringify(init.json);
    delete init.json;
  }
  return fetch(path, init).then(unwrap);
}

export async function streamApi(path, options, onEvent) {
  const init = { ...options };
  if (init.json !== undefined) {
    init.headers = { ...(init.headers || {}), "Content-Type": "application/json" };
    init.body = JSON.stringify(init.json);
    delete init.json;
  }
  const resp = await fetch(path, init);
  if (!resp.ok || !resp.body) await unwrap(resp);
  const reader = resp.body.getReader();
  const decoder = new TextDecoder();
  let buffer = "";
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      buffer += decoder.decode(value, { stream: true });
      let boundary;
      while ((boundary = buffer.indexOf("\n\n")) >= 0) {
        const block = buffer.slice(0, boundary);
        buffer = buffer.slice(boundary + 2);
        for (const line of block.split("\n")) {
          if (!line.startsWith("data:")) continue;
          const payload = line.slice(5).trim();
          if (!payload || payload === "[DONE]") continue;
          try { onEvent?.(JSON.parse(payload)); } catch { /* malformed upstream chunk */ }
        }
      }
    }
  } finally {
    reader.releaseLock?.();
  }
}

export function fetchRules() {
  return fetch("/api/rules").then(unwrap);
}

export function fetchConfig() {
  return fetch("/api/config").then(unwrap);
}

export function saveConfig(cfg) {
  return fetch("/api/config", {
    method: "PUT",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(cfg),
  }).then(unwrap);
}

export function fetchModels(baseUrl, apiKey) {
  return fetch("/api/ai/models", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ base_url: baseUrl, api_key: apiKey }),
  }).then(unwrap);
}

export function uploadPcap(file) {
  const fd = new FormData();
  fd.append("file", file);
  return fetch("/api/upload", { method: "POST", body: fd }).then(unwrap);
}

export function fetchPackets(params, signal) {
  const query = new URLSearchParams({
    session_id: params.session_id,
    offset: String(params.offset),
    limit: String(params.limit),
  });
  if (params.proto) query.set("proto", params.proto);
  if (params.rule) query.set("rule", params.rule);
  if (params.q) query.set("q", params.q);
  if (params.hits_only) query.set("hits_only", "true");
  return fetch(`/api/packets?${query}`, { signal }).then(unwrap);
}

export function fetchPacketDetail(sessionId, no) {
  return fetch(`/api/packets/${sessionId}/${no}`).then(unwrap);
}

export function fetchOfflineReport(body) {
  return fetch("/api/offline-report", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  }).then(unwrap);
}

export function fetchOfflineProbeReport(body) {
  return fetch("/api/offline-probe-report", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  }).then(unwrap);
}

async function streamEvents(path, body, handlers, signal) {
  const resp = await fetch(path, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
    signal,
  });
  if (!resp.ok || !resp.body) {
    let msg = `请求失败 (${resp.status})`;
    try {
      const data = await resp.json();
      if (data.detail) msg = data.detail;
    } catch { /* ignore */ }
    handlers.onError?.(msg);
    return;
  }

  const reader = resp.body.getReader();
  const decoder = new TextDecoder();
  let buffer = "";
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      buffer += decoder.decode(value, { stream: true });
      let index;
      while ((index = buffer.indexOf("\n\n")) >= 0) {
        const rawEvent = buffer.slice(0, index);
        buffer = buffer.slice(index + 2);
        for (const line of rawEvent.split("\n")) {
          if (!line.startsWith("data:")) continue;
          const payload = line.slice(5).trim();
          if (payload === "[DONE]") return;
          try {
            const event = JSON.parse(payload);
            handlers.onEvent?.(event);
          } catch { /* ignore bad chunk */ }
        }
      }
    }
  } finally {
    reader.releaseLock?.();
  }
}

export function streamAnalyze(body, handlers, signal) {
  return streamEvents("/api/ai/analyze", body, handlers, signal);
}

export function streamProbe(body, handlers, signal) {
  return streamEvents("/api/probes/run", body, handlers, signal);
}

export function streamProbeAnalyze(body, handlers, signal) {
  return streamEvents("/api/ai/analyze-probe", body, handlers, signal);
}

export function streamExposure(body, handlers, signal) {
  return streamEvents("/api/security/exposure/run", body, handlers, signal);
}

export function fetchOfflineExposureReport(body) {
  return fetch("/api/offline-exposure-report", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  }).then(unwrap);
}

export function streamExposureAnalyze(body, handlers, signal) {
  return streamEvents("/api/ai/analyze-exposure", body, handlers, signal);
}

export function uploadConfigAudit(file) {
  const fd = new FormData();
  fd.append("file", file);
  return fetch("/api/security/config-audit/upload", { method: "POST", body: fd }).then(unwrap);
}

export function streamConfigAuditAnalyze(body, handlers, signal) {
  return streamEvents("/api/ai/analyze-config-audit", body, handlers, signal);
}

// ---------- cabinets ----------

export function fetchRooms() {
  return fetch("/api/cabinets/rooms").then(unwrap);
}

export function createRoom(data) {
  return fetch("/api/cabinets/rooms", {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify(data),
  }).then(unwrap);
}

export function fetchCabinets(roomId) {
  return fetch(`/api/cabinets/rooms/${roomId}/cabinets`).then(unwrap);
}

export function createCabinet(roomId, data) {
  return fetch(`/api/cabinets/rooms/${roomId}/cabinets`, {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify(data),
  }).then(unwrap);
}

export function updateCabinet(id, data) {
  return fetch(`/api/cabinets/cabinets/${id}`, {
    method: "PUT", headers: { "Content-Type": "application/json" },
    body: JSON.stringify(data),
  }).then(unwrap);
}

export function deleteCabinet(id) {
  return fetch(`/api/cabinets/cabinets/${id}`, { method: "DELETE" }).then(unwrap);
}

export function duplicateCabinet(id, data) {
  return fetch(`/api/cabinets/cabinets/${id}/duplicate`, {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify(data),
  }).then(unwrap);
}

export function fetchTemplates() {
  return fetch("/api/cabinets/templates").then(unwrap);
}

export function saveTemplate(id, data) {
  return fetch(`/api/cabinets/cabinets/${id}/template`, {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify(data),
  }).then(unwrap);
}

export function applyTemplate(id, data) {
  return fetch(`/api/cabinets/templates/${id}/apply`, {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify(data),
  }).then(unwrap);
}

export function deleteTemplate(id) {
  return fetch(`/api/cabinets/templates/${id}`, { method: "DELETE" }).then(unwrap);
}

export function compareCabinets(leftId, rightId) {
  return fetch(`/api/cabinets/compare/${leftId}/${rightId}`).then(unwrap);
}

export function fetchCabinetLayout(id) {
  return fetch(`/api/cabinets/cabinets/${id}/layout`).then(unwrap);
}

export function createDevice(data, cabinetId) {
  const q = cabinetId ? `?cabinet_id=${cabinetId}` : "";
  return fetch(`/api/cabinets/devices${q}`, {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify(data),
  }).then(unwrap);
}

export function updateDevice(id, data, cabinetId) {
  const q = cabinetId ? `?cabinet_id=${cabinetId}` : "";
  return fetch(`/api/cabinets/devices/${id}${q}`, {
    method: "PUT", headers: { "Content-Type": "application/json" },
    body: JSON.stringify(data),
  }).then(unwrap);
}

export function deleteDevice(id) {
  return fetch(`/api/cabinets/devices/${id}`, { method: "DELETE" }).then(unwrap);
}

export function fetchUnrackedDevices() {
  return fetch("/api/cabinets/devices?unracked_only=true").then(unwrap);
}

export function placeDevice(id, data) {
  return fetch(`/api/cabinets/devices/${id}/placement`, {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify(data),
  }).then(unwrap);
}

export function fetchCapacity() {
  return fetch("/api/cabinets/capacity").then(unwrap);
}

export function createReservation(data, cabinetId) {
  return fetch(`/api/cabinets/reservations?cabinet_id=${cabinetId}`, {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify(data),
  }).then(unwrap);
}

export function deleteReservation(id) {
  return fetch(`/api/cabinets/reservations/${id}`, { method: "DELETE" }).then(unwrap);
}

// ---------- monitor ----------

export function fetchMonitorTasks() {
  return fetch("/api/monitor/tasks").then(unwrap);
}

export function createMonitorTask(data) {
  return fetch("/api/monitor/tasks", {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify(data),
  }).then(unwrap);
}

export function updateMonitorTask(id, data) {
  return fetch(`/api/monitor/tasks/${id}`, {
    method: "PATCH", headers: { "Content-Type": "application/json" },
    body: JSON.stringify(data),
  }).then(unwrap);
}

export function deleteMonitorTask(id) {
  return fetch(`/api/monitor/tasks/${id}`, { method: "DELETE" }).then(unwrap);
}

export function runMonitorTask(id) {
  return fetch(`/api/monitor/tasks/${id}/run`, { method: "POST" }).then(unwrap);
}

export function fetchMonitorRuns(id) {
  return fetch(`/api/monitor/tasks/${id}/runs`).then(unwrap);
}

export function fetchMonitorDiff(id) {
  return fetch(`/api/monitor/tasks/${id}/diff`).then(unwrap);
}

// ---------- infrastructure workspace ----------
export const infra = {
  servers: () => apiRequest("/api/ops/servers"),
  saveServer: (data, id) => apiRequest(id ? `/api/ops/servers/${id}` : "/api/ops/servers", { method: id ? "PUT" : "POST", json: data }),
  deleteServer: (id) => apiRequest(`/api/ops/servers/${id}`, { method: "DELETE" }),
  connections: (serverId) => apiRequest(`/api/ops/connections${serverId ? `?server_id=${serverId}` : ""}`),
  saveConnection: (data, id) => apiRequest(id ? `/api/ops/connections/${id}` : "/api/ops/connections", { method: id ? "PUT" : "POST", json: data }),
  testConnection: (id, trust = false) => apiRequest(`/api/ops/connections/${id}/test`, { method: "POST", json: { trust_host_key: trust } }),
  launchConnection: (id) => apiRequest(`/api/ops/connections/${id}/launch`, { method: "POST" }),
  credentials: () => apiRequest("/api/vault/credentials"),
  saveCredential: (data, id) => apiRequest(id ? `/api/vault/credentials/${id}` : "/api/vault/credentials", { method: id ? "PUT" : "POST", json: data }),
  deleteCredential: (id) => apiRequest(`/api/vault/credentials/${id}`, { method: "DELETE" }),
  inspections: (serverId) => apiRequest(`/api/ops/inspections${serverId ? `?server_id=${serverId}` : ""}`),
  runInspection: (data) => apiRequest("/api/ops/inspections", { method: "POST", json: data }),
  inspectionTasks: () => apiRequest("/api/ops/inspection-tasks"),
  diagnostics: () => apiRequest("/api/diagnostics/runs"),
  createPlan: (data) => apiRequest("/api/diagnostics/plans", { method: "POST", json: data }),
  runPlan: (id) => apiRequest(`/api/diagnostics/plans/${id}/run`, { method: "POST" }),
  documents: () => apiRequest("/api/knowledge/documents"),
  uploadDocument: (file) => { const fd = new FormData(); fd.append("file", file); return fetch("/api/knowledge/documents", { method: "POST", body: fd }).then(unwrap); },
  deleteDocument: (id) => apiRequest(`/api/knowledge/documents/${id}`, { method: "DELETE" }),
  searchKnowledge: (q) => apiRequest(`/api/knowledge/search?q=${encodeURIComponent(q)}`),
  providers: () => apiRequest("/api/ai/providers"),
  saveProvider: (data, id) => apiRequest(id ? `/api/ai/providers/${id}` : "/api/ai/providers", { method: id ? "PUT" : "POST", json: data }),
  contextPreview: (data) => apiRequest("/api/assistant/context-preview", { method: "POST", json: data }),
  events: () => apiRequest("/api/events?status=open"),
  ackEvent: (id) => apiRequest(`/api/events/${id}/ack`, { method: "PATCH" }),
  sshTicket: (connectionId, trust = false) => apiRequest(`/api/ops/ssh/sessions?connection_id=${connectionId}&trust_host_key=${trust}`, { method: "POST" }),
  networkPlans: () => apiRequest("/api/network/plans"),
  saveNetworkPlan: (data, id) => apiRequest(id ? `/api/network/plans/${id}` : "/api/network/plans", { method: id ? "PUT" : "POST", json: data }),
  deleteNetworkPlan: (id) => apiRequest(`/api/network/plans/${id}`, { method: "DELETE" }),
  networkAiPreview: (id, data) => apiRequest(`/api/network/plans/${id}/ai-preview`, { method: "POST", json: data }),
  networkAiDraftPreview: (data) => apiRequest("/api/network/plans/ai-draft/preview", { method: "POST", json: data }),
  networkAiDraftConfirm: (data) => apiRequest("/api/network/plans/ai-draft/confirm", { method: "POST", json: data }),
};
