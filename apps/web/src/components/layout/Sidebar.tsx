"use client";

import React from "react";
import {
  LayoutDashboard,
  MailSearch,
  Fingerprint,
  Globe2,
  FileText,
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
      icon: LayoutDashboard,
      label: "SOC Overview",
      href: "/",
      status: "active",
    },
    {
      icon: MailSearch,
      label: "Email Ingestion",
      href: "#ingestion-zone",
      status: "active",
    },
    {
      icon: Fingerprint,
      label: "Header Forensics",
      href: "#forensics-zone",
      status: "active",
    },
    {
      icon: Globe2,
      label: "Threat Intelligence",
      href: "#intel",
      status: "planned",
    },
    {
      icon: FileText,
      label: "Reports & Evidence",
      href: "#reports",
      status: "planned",
    },
    {
      icon: Settings,
      label: "Platform Settings",
      href: "#settings",
      status: "planned",
    },
  ];

  return (
    <aside className={`sidebar ${isOpen ? "open" : "collapsed"}`} aria-label="Main Navigation">
      <div className="sidebar-inner">
        <div className="sidebar-section-title">
          <span>INVESTIGATION MODULES</span>
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
                aria-current={item.href === "/" ? "page" : undefined}
              >
                <Icon className="w-4 h-4 nav-icon" />
                <span className="nav-label">{item.label}</span>
                {item.status === "planned" && (
                  <span className="nav-badge">Planned</span>
                )}
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
