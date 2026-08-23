"use client";

import React from "react";
import { Shield, Radio, FileCode2, Menu } from "lucide-react";
import { useHealth } from "@/hooks/useHealth";

interface HeaderProps {
  onToggleSidebar?: () => void;
}

export const Header: React.FC<HeaderProps> = ({ onToggleSidebar }) => {
  const { data: health, isLoading, isError } = useHealth();

  return (
    <header className="header">
      <div className="header-container">
        <div className="flex items-center gap-3">
          {onToggleSidebar && (
            <button
              onClick={onToggleSidebar}
              className="sidebar-toggle-btn"
              aria-label="Toggle navigation drawer"
            >
              <Menu className="w-5 h-5 text-gray-300" />
            </button>
          )}

          <div className="logo-group">
            <div className="logo-icon-box">
              <Shield className="w-6 h-6 text-cyan-400" />
            </div>
            <div>
              <h1 className="logo-title">ThreatTrace AI</h1>
              <p className="logo-subtitle">Cybersecurity Email Investigation Platform</p>
            </div>
          </div>
        </div>

        <div className="header-actions">
          <div className="status-badge">
            <Radio
              className={`w-3.5 h-3.5 ${
                isLoading
                  ? "text-gray-400"
                  : isError || health?.status !== "healthy"
                  ? "text-amber-400"
                  : "text-emerald-400 animate-pulse"
              }`}
            />
            <span>
              {isLoading
                ? "Connecting..."
                : isError
                ? "Offline"
                : health?.status === "healthy"
                ? "SOC Engine Ready"
                : "Engine Degraded"}
            </span>
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
