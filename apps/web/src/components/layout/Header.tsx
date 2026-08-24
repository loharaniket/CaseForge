"use client";

import React from "react";
import Link from "next/link";
import { Shield, Menu, UserCheck, LogOut, LogIn } from "lucide-react";
import { useAuth } from "@/context/AuthContext";
import { usePathname } from "next/navigation";

interface HeaderProps {
  onToggleSidebar?: () => void;
}

export const Header: React.FC<HeaderProps> = ({ onToggleSidebar }) => {
  const { user, isAuthenticated, logout } = useAuth();
  const pathname = usePathname();

  // Basic logic to determine header title based on route
  const getPageTitle = () => {
    if (pathname?.includes("/investigations/")) return "Investigation Details";
    if (pathname === "/login") return "Authentication";
    return "Cybersecurity Operations";
  };

  return (
    <header className="header">
      <div className="header-container">
        <div className="flex items-center gap-4">
          {onToggleSidebar && (
            <button
              onClick={onToggleSidebar}
              className="text-gray-300 hover:text-white"
              aria-label="Toggle navigation drawer"
            >
              <Menu className="w-5 h-5" />
            </button>
          )}

          <Link href="/" className="logo-group">
            <Shield className="w-6 h-6 text-cyan-500" />
            <div>
              <h1 className="logo-title">ThreatTrace AI</h1>
              <p className="logo-subtitle">Enterprise SOC Platform</p>
            </div>
          </Link>
          
          <div className="hidden md:flex ml-8 pl-8 border-l border-[#334E68] h-8 items-center text-sm font-semibold text-white">
            {getPageTitle()}
          </div>
        </div>

        <div className="header-actions">
          {/* Auth State Control */}
          {isAuthenticated && user ? (
            <div className="flex items-center gap-4">
              <div className="user-profile-badge">
                <UserCheck className="w-4 h-4 text-gray-300" />
                <div className="flex flex-col">
                  <span className="text-xs font-semibold text-white leading-tight">{user.full_name}</span>
                  <span className="text-[10px] text-gray-400">{user.role}</span>
                </div>
              </div>
              <button
                onClick={logout}
                className="text-gray-400 hover:text-white transition-colors"
                title="Sign out"
                aria-label="Sign out"
              >
                <LogOut className="w-4 h-4" />
              </button>
            </div>
          ) : (
            <Link href="/login" className="login-btn">
              <LogIn className="w-4 h-4" />
              <span>Analyst Login</span>
            </Link>
          )}
        </div>
      </div>
    </header>
  );
};
