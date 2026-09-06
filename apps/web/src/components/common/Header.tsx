import React from "react";
import { Shield, Radio, FileCode2 } from "lucide-react";

export const Header: React.FC = () => {
  return (
    <header className="header">
      <div className="header-container">
        <div className="logo-group">
          <div className="logo-icon-box">
            <Shield className="w-6 h-6 text-cyan-400" />
          </div>
          <div>
            <h1 className="logo-title">CaseForge</h1>
            <p className="logo-subtitle">Cybersecurity Email Investigation Platform</p>
          </div>
        </div>

        <div className="header-actions">
          <div className="status-badge">
            <Radio className="w-3.5 h-3.5 text-emerald-400 animate-pulse" />
            <span>SOC Engine Ready</span>
          </div>
          <a
            href="http://localhost:8000/api/v1/docs"
            target="_blank"
            rel="noopener noreferrer"
            className="api-docs-link"
          >
            <FileCode2 className="w-4 h-4" />
            <span>API Docs</span>
          </a>
        </div>
      </div>
    </header>
  );
};
