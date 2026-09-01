import React, { useState } from "react";
import { KeyRound, Loader2, ScanSearch } from "lucide-react";
import { fetchModels, saveConfig } from "../api";

export default function ConfigDialog({ cfg, onClose, onSaved }) {
  const [baseUrl, setBaseUrl] = useState(cfg?.base_url || "");
  const [model, setModel] = useState(cfg?.model || "");
  const [apiKey, setApiKey] = useState("");
  const [models, setModels] = useState([]);
  const [scanning, setScanning] = useState(false);
  const [scanError, setScanError] = useState("");
  const [manualModel, setManualModel] = useState(!cfg?.model);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState("");

  const scan = async () => {
    if (!baseUrl || scanning) return;
    setScanning(true);
    setScanError("");
    try {
      const data = await fetchModels(baseUrl, apiKey || "__KEEP__");
      setModels(data.models || []);
      if (data.models?.length && !data.models.includes(model)) setModel(data.models[0]);
      setManualModel(false);
    } catch (err) {
      setModels([]);
      setManualModel(true);
      setScanError(String(err.message || err));
    } finally {
      setScanning(false);
    }
  };

  const submit = async (event) => {
    event.preventDefault();
    setSaving(true);
    setError("");
    try {
      const saved = await saveConfig({
        base_url: baseUrl,
        model,
        api_key: apiKey === "" ? "__KEEP__" : apiKey,
      });
      onSaved(saved);
    } catch (err) {
      setError(String(err.message || err));
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="modal-mask" onClick={onClose}>
      <form className="modal" onClick={(event) => event.stopPropagation()} onSubmit={submit}>
        <h3>AI 接口配置</h3>
        <p className="modal-sub">OpenAI 兼容接口（DeepSeek / GLM / OpenAI / 本地 vLLM 均可）。配置保存在本机 config.json。</p>
        <div className="field">
          <label htmlFor="cfg-base">Base URL</label>
          <input id="cfg-base" className="input" value={baseUrl}
                 onChange={(event) => setBaseUrl(event.target.value)}
                 placeholder="https://api.deepseek.com/v1" />
        </div>
        <div className="field">
          <label htmlFor="cfg-key">API Key</label>
          <input id="cfg-key" className="input" type="password" value={apiKey}
                 onChange={(event) => setApiKey(event.target.value)}
                 placeholder={cfg?.has_key ? `已保存（${cfg.api_key_masked}），留空保持不变` : "尚未配置"} />
          <div className="field-note">留空表示保持现有 Key；填入新值则覆盖。</div>
        </div>
        <div className="field">
          <div className="model-label-row">
            <label htmlFor="cfg-model">Model</label>
            <button type="button" className="btn btn-ghost scan-btn"
                    onClick={scan} disabled={!baseUrl || scanning}>
              {scanning ? <Loader2 size={14} className="spin" /> : <ScanSearch size={14} />}
              {scanning ? "扫描中" : "扫描模型"}
            </button>
          </div>
          {models.length > 0 && !manualModel ? (
            <select id="cfg-model" className="select model-select" value={model}
                    onChange={(event) => setModel(event.target.value)}>
              {models.map((item) => <option key={item} value={item}>{item}</option>)}
            </select>
          ) : (
            <input id="cfg-model" className="input" value={model}
                   onChange={(event) => setModel(event.target.value)}
                   placeholder="deepseek-chat" />
          )}
          {models.length > 0 && (
            <button type="button" className="link-button" onClick={() => setManualModel(true)}>
              手动输入模型名
            </button>
          )}
          {scanError && <div className="field-note scan-error">{scanError}</div>}
        </div>
        {error && <div className="ai-error" style={{ marginBottom: 10 }}>{error}</div>}
        <div className="modal-actions">
          <button type="button" className="btn btn-ghost" onClick={onClose}>取消</button>
          <button type="submit" className="btn btn-primary" disabled={saving}>
            {saving ? <Loader2 size={14} className="spin" /> : <KeyRound size={14} />}
            保存
          </button>
        </div>
      </form>
    </div>
  );
}
