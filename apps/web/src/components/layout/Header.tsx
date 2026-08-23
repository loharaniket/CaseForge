"use client";

import React from "react";
import Link from "next/link";
import { Shield, Radio, FileCode2, Menu, UserCheck, LogOut, LogIn } from "lucide-react";
import { useHealth } from "@/hooks/useHealth";
import { useAuth } from "@/context/AuthContext";

interface HeaderProps {
  onToggleSidebar?: () => void;
}

export const Header: React.FC<HeaderProps> = ({ onToggleSidebar }) => {
  const { data: health, isLoading, isError } = useHealth();
  const { user, isAuthenticated, logout } = useAuth();

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

          <Link href="/" className="logo-group">
            <div className="logo-icon-box">
              <Shield className="w-6 h-6 text-cyan-400" />
            </div>
            <div>
              <h1 className="logo-title">ThreatTrace AI</h1>
              <p className="logo-subtitle">Cybersecurity Email Investigation Platform</p>
            </div>
          </Link>
        </div>

        <div className="header-actions">
          {/* Engine Health Status */}
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

          {/* API Docs Link */}
          <a
            href="http://localhost:8000/api/v1/docs"
            target="_blank"
            rel="noopener noreferrer"
            className="api-docs-link"
          >
            <FileCode2 className="w-4 h-4" />
            <span>API Docs</span>
          </a>

          {/* Auth State Control */}
          {isAuthenticated && user ? (
            <div className="flex items-center gap-2 pl-2 border-l border-gray-800">
              <div className="user-profile-badge">
                <UserCheck className="w-3.5 h-3.5 text-cyan-400" />
                <span className="text-xs font-semibold text-gray-200">{user.full_name}</span>
                <span className="user-role-tag">{user.role}</span>
              </div>
              <button
                onClick={logout}
                className="logout-btn"
                title="Sign out of SOC Console"
                aria-label="Sign out"
              >
                <LogOut className="w-4 h-4 text-gray-400 hover:text-rose-400" />
              </button>
            </div>
          ) : (
            <Link href="/login" className="login-btn">
              <LogIn className="w-3.5 h-3.5 text-cyan-400" />
              <span>Analyst Login</span>
            </Link>
          )}
        </div>
      </div>
    </header>
  );
};
