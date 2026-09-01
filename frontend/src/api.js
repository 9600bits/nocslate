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
