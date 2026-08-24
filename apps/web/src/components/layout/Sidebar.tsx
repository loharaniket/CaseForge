"use client";

import React from "react";
import {
  FileSearch,
  History,
  Settings,
  ShieldCheck,
} from "lucide-react";

interface SidebarProps {
  isOpen: boolean;
  onClose?: () => void;
}

interface NavItem {
  icon: React.ElementType;
  label: string;
  href: string;
  status: "active" | "planned";
}

export const Sidebar: React.FC<SidebarProps> = ({ isOpen }) => {
  const navItems: NavItem[] = [
    {
      icon: History,
      label: "Investigations",
      href: "/#recent-investigations",
      status: "active",
    },
    {
      icon: FileSearch,
      label: "New Investigation",
      href: "/#new-investigation",
      status: "active",
    },
    {
      icon: Settings,
      label: "Settings",
      href: "#settings",
      status: "active",
    },
  ];

  return (
    <aside className={`sidebar ${isOpen ? "open" : "collapsed"}`} aria-label="Main Navigation">
      <div className="sidebar-inner">
        <div className="sidebar-section-title">
          <span>INVESTIGATIONS</span>
        </div>

        <nav className="sidebar-nav">
          {navItems.map((item, index) => {
            const Icon = item.icon;
            const isActive = item.status === "active";

            return (
              <a
                key={index}
                href={item.href}
                className={`nav-item ${isActive ? "active" : "disabled"}`}
              >
                <Icon className="w-4 h-4 nav-icon" />
                <span className="nav-label">{item.label}</span>
              </a>
            );
          })}
        </nav>

        <div className="sidebar-footer">
          <div className="sidebar-security-badge">
            <ShieldCheck className="w-4 h-4 text-emerald-400" />
            <div className="text-xs">
              <p className="font-semibold text-gray-200">SOC Environment</p>
              <p className="text-gray-500 font-mono">Air-gap Compatible</p>
            </div>
          </div>
        </div>
      </div>
    </aside>
  );
};
