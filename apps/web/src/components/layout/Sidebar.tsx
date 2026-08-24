"use client";

import React from "react";
import Link from "next/link";
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
    <aside className={`flex flex-col bg-nav-bg border-r border-[#334E68] transition-all duration-200 z-40 ${isOpen ? 'w-[240px]' : 'w-0 overflow-hidden border-none'}`} aria-label="Main Navigation">
      <div className="flex flex-col h-full py-5 px-3.5 gap-5">
        <div className="text-[11px] font-[650] tracking-[0.05em] text-[#9FB3C8] uppercase px-2">
          <span>INVESTIGATIONS</span>
        </div>

        <nav className="flex flex-col gap-1 flex-1">
          {navItems.map((item, index) => {
            const Icon = item.icon;
            const isActive = item.status === "active";

            return (
              <Link
                key={index}
                href={item.href}
                className={`flex items-center gap-3 px-3 py-2.5 rounded-[6px] text-sm font-semibold transition-colors no-underline ${isActive ? "text-white bg-[#243B53] hover:bg-[#334E68]" : "text-[#9FB3C8] opacity-50 cursor-not-allowed"}`}
              >
                <Icon className={`w-4 h-4 ${isActive ? "text-info" : ""}`} />
                <span>{item.label}</span>
              </Link>
            );
          })}
        </nav>

        <div className="mt-auto pt-4 border-t border-[#334E68]">
          <div className="flex items-center gap-3 p-3 bg-[#121A22] rounded-[8px] border border-[#243B53]">
            <ShieldCheck className="w-4 h-4 text-success" />
            <div className="flex flex-col">
              <p className="font-semibold text-white text-xs">SOC Environment</p>
              <p className="text-[#9FB3C8] font-mono text-[10px]">Air-gap Compatible</p>
            </div>
          </div>
        </div>
      </div>
    </aside>
  );
};
