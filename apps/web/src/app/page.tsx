"use client";

import React from "react";
import { SystemStatusCard } from "@/components/dashboard/SystemStatusCard";
import {
  Search,
  Cpu,
  Fingerprint,
  Share2,
  FileText,
  Globe2,
} from "lucide-react";

export default function HomePage() {
  const modules = [
    {
      icon: Search,
      title: "Email Ingestion & Forensic Parsing",
      description: "Secure parsing of raw RFC 5322 EML structures, MIME multi-part bodies, and metadata.",
      status: "Pipeline Module",
    },
    {
      icon: Fingerprint,
      title: "Authentication Forensics",
      description: "Automated SPF, DKIM, and DMARC alignment and cryptographic signature verification.",
      status: "Forensic Module",
    },
    {
      icon: Cpu,
      title: "AI Threat Engine & Explainability",
      description: "Multi-class threat categorization with confidence metrics and explainable risk factors.",
      status: "AI Detection",
    },
    {
      icon: Globe2,
      title: "Threat Intel & Geo Infrastructure",
      description: "Reputation correlation and infrastructure origin resolution via decoupled adapters.",
      status: "Intelligence Module",
    },
    {
      icon: Share2,
      title: "Threat Graph & IOC Correlation",
      description: "Visual topology of extracted IOCs, senders, domains, hashes, and relay pathways.",
      status: "SOC Visualizer",
    },
    {
      icon: FileText,
      title: "Evidence Ledger & PDF Reports",
      description: "Tamper-evident SHA-256 evidence hashing and executive PDF report compilation.",
      status: "Reporting Module",
    },
  ];

  return (
    <div className="flex flex-col gap-8">
      <section className="hero-section">
        <span className="hero-tag">SOC Investigation Platform</span>
        <h1 className="hero-title">ThreatTrace AI</h1>
        <p className="hero-description">
          Unified cybersecurity email investigation system designed for Security Operations Centers.
          Automated header forensics, AI threat detection, and tamper-evident case management.
        </p>
      </section>

      {/* Live System Diagnostics */}
      <section>
        <SystemStatusCard />
      </section>

      {/* Investigation Pipeline Capabilities */}
      <section>
        <div className="mb-4">
          <h3 className="text-lg font-semibold text-white mb-1">MVP Investigation Architecture</h3>
          <p className="text-sm text-gray-400">
            Core modular capabilities provisioned for incremental feature rollouts.
          </p>
        </div>

        <div className="features-grid">
          {modules.map((mod, index) => {
            const Icon = mod.icon;
            return (
              <div key={index} className="feature-box">
                <div className="feature-header">
                  <div className="feature-icon-wrap">
                    <Icon className="w-4 h-4 text-cyan-400" />
                  </div>
                  <h4 className="feature-title">{mod.title}</h4>
                </div>
                <p className="feature-desc">{mod.description}</p>
                <span className="feature-tag">{mod.status}</span>
              </div>
            );
          })}
        </div>
      </section>
    </div>
  );
}
