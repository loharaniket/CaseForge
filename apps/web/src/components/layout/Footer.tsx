"use client";

import React from "react";
import { Terminal, ShieldAlert } from "lucide-react";

export const Footer: React.FC = () => {
  return (
    <footer className="mt-8 border-t border-border py-6 shrink-0">
      <div className="flex flex-col sm:flex-row justify-between items-center max-w-[1600px] mx-auto w-full px-6">
        <div className="flex items-center gap-2 text-xs text-text-muted mb-2 sm:mb-0">
          <Terminal className="w-4 h-4 text-info" />
          <span>CaseForge SOC Investigation Platform — Foundation v0.1.0</span>
        </div>
        <div className="flex items-center gap-2 text-xs text-text-muted">
          <ShieldAlert className="w-4 h-4 text-warning" />
          <span>Restricted Access — Security Operations Center</span>
        </div>
      </div>
    </footer>
  );
};
