import React from "react";
import { ChevronRight } from "lucide-react";

export default function WorkspaceShell({ label, tabs, active, children }) {
  return <main className="workspace-shell">
    <aside className="workspace-sidebar">
      <div className="workspace-label">{label}</div>
      {tabs.map((tab) => {
        const Icon = tab.icon;
        return <a key={tab.id} className={active === tab.id ? "workspace-tab active" : "workspace-tab"} href={`#/${tab.href}`}>
          {Icon && <Icon size={16} />}<span>{tab.label}</span>{active === tab.id && <ChevronRight size={14} />}
        </a>;
      })}
    </aside>
    <div className="workspace-main">{children}</div>
  </main>;
}
