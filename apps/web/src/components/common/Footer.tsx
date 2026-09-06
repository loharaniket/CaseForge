import React from "react";
import { Terminal, ShieldAlert } from "lucide-react";

export const Footer: React.FC = () => {
  return (
    <footer className="footer">
      <div className="footer-container">
        <div className="footer-left">
          <Terminal className="w-4 h-4 text-cyan-400" />
          <span>CaseForge SOC Investigation Platform — Foundation v0.1.0</span>
        </div>
        <div className="footer-right">
          <ShieldAlert className="w-4 h-4 text-amber-400" />
          <span>Restricted Access — Security Operations Center</span>
        </div>
      </div>
    </footer>
  );
};
