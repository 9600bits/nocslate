import React from "react";
import { Activity, Network, ShieldAlert, ShieldCheck } from "lucide-react";
import SecurityOpsPage from "./SecurityOpsPage.jsx";
import InfraWorkspace from "./InfraWorkspace.jsx";
import WorkspaceShell from "./WorkspaceShell.jsx";

const TABS = [
  { id: "exposure", href: "security/exposure", label: "暴露面发现", icon: Network },
  { id: "config", href: "security/config", label: "设备配置审计", icon: ShieldAlert },
  { id: "events", href: "security/events", label: "事件中心", icon: Activity },
];

export default function SecurityWorkspace({ route, cfg, onNavigate, onOpenConfig }) {
  const active = ["exposure", "config", "events"].includes(route) ? route : "exposure";
  const content = active === "events"
    ? <InfraWorkspace embedded section="infra" route="events" />
    : <SecurityOpsPage cfg={cfg} onNavigate={onNavigate} onOpenConfig={onOpenConfig} initialTab={active} securityOnly />;
  return <WorkspaceShell label="安全中心" tabs={TABS} active={active}>{content}</WorkspaceShell>;
}
