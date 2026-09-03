import React from "react";
import { Activity, Radar } from "lucide-react";
import ProbePage from "./ProbePage.jsx";
import WorkspaceShell from "./WorkspaceShell.jsx";

const TABS = [
  { id: "probe", href: "network/probe", label: "探测与监控", icon: Activity },
  { id: "capture", href: "network/capture", label: "抓包分析", icon: Radar },
];

export default function NetworkWorkspace({ route, cfg, onNavigate, onOpenConfig }) {
  const active = route === "capture" ? "capture" : "probe";
  return <WorkspaceShell label="网络分析" tabs={TABS} active={active}>
    {active === "probe" && <ProbePage cfg={cfg} onNavigate={onNavigate} onOpenConfig={onOpenConfig} embedded />}
    {active === "capture" && <div className="workspace-placeholder">抓包分析由主工作区加载。</div>}
  </WorkspaceShell>;
}
