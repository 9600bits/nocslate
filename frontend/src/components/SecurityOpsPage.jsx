import React, { useState } from "react";
import { ArrowLeft, Network, Radar, ShieldAlert, ShieldCheck } from "lucide-react";
import ProbePage from "./ProbePage.jsx";
import SecurityPage from "./SecurityPage.jsx";

const WORK_TABS = [
  { id: "probe", label: "网络探测", icon: <Radar size={15} /> },
  { id: "exposure", label: "暴露面 / 资产发现", icon: <Network size={15} /> },
  { id: "config", label: "设备配置审计", icon: <ShieldAlert size={15} /> },
];

export default function SecurityOpsPage({ cfg, onNavigate, onOpenConfig, initialTab = "probe" }) {
  const [workTab, setWorkTab] = useState(WORK_TABS.some((tab) => tab.id === initialTab)
    ? initialTab
    : "probe");

  return (
    <main className="security-page security-ops-page">
      <div className="page-head">
        <button className="btn btn-ghost" onClick={() => onNavigate("home")}>
          <ArrowLeft size={15} /> 返回首页
        </button>
        <div className="page-title">
          <ShieldCheck size={18} className="accent-iris" />
          <h2>探测与安全</h2>
        </div>
        <span className="legal-note">仅用于你有权测试的网络</span>
      </div>

      <div className="seg tabs page-tabs three" role="tablist" aria-label="探测与安全功能">
        {WORK_TABS.map((tab) => (
          <button key={tab.id} role="tab" aria-selected={workTab === tab.id}
                  className={workTab === tab.id ? "on" : ""}
                  onClick={() => setWorkTab(tab.id)}>
            {tab.icon} {tab.label}
          </button>
        ))}
      </div>

      {workTab === "probe" && (
        <ProbePage cfg={cfg} onNavigate={onNavigate} onOpenConfig={onOpenConfig} embedded />
      )}
      {(workTab === "exposure" || workTab === "config") && (
        <SecurityPage
          cfg={cfg}
          onNavigate={onNavigate}
          onOpenConfig={onOpenConfig}
          embedded
          activeTab={workTab}
          onTabChange={setWorkTab}
        />
      )}
    </main>
  );
}
