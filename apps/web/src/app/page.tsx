"use client";

import React, { useState } from "react";
import { SystemStatusCard } from "@/components/dashboard/SystemStatusCard";
import { EmailUploadZone } from "@/components/investigation/EmailUploadZone";
import { EmailForensicsInspector } from "@/components/investigation/EmailForensicsInspector";
import { EmailUploadResponse } from "@/types";
import {
  Search,
  Cpu,
  Fingerprint,
  Share2,
  FileText,
  Globe2,
} from "lucide-react";

export default function HomePage() {
  const [selectedCaseId, setSelectedCaseId] = useState<string | null>(null);

  const modules = [
    {
      icon: Search,
      title: "Email Ingestion & Forensic Parsing",
      description: "Secure RFC 822 EML ingestion, SHA-256 evidence hashing, and deterministic forensic parsing.",
      status: "Live & Active",
      highlight: true,
    },
    {
      icon: Fingerprint,
      title: "Authentication Forensics",
      description: "Automated SPF, DKIM, and DMARC alignment and cryptographic signature verification.",
      status: "Planned",
      highlight: false,
    },
    {
      icon: Cpu,
      title: "AI Threat Engine & Explainability",
      description: "Multi-class threat categorization with confidence metrics and explainable risk factors.",
      status: "Planned",
      highlight: false,
    },
    {
      icon: Globe2,
      title: "Threat Intel & Geo Infrastructure",
      description: "Reputation correlation and infrastructure origin resolution via decoupled adapters.",
      status: "Planned",
      highlight: false,
    },
    {
      icon: Share2,
      title: "Threat Graph & IOC Correlation",
      description: "Visual topology of extracted IOCs, senders, domains, hashes, and relay pathways.",
      status: "Planned",
      highlight: false,
    },
    {
      icon: FileText,
      title: "Evidence Ledger & PDF Reports",
      description: "Tamper-evident SHA-256 evidence hashing and executive PDF report compilation.",
      status: "Planned",
      highlight: false,
    },
  ];

  const handleUploadSuccess = (response: EmailUploadResponse) => {
    setSelectedCaseId(response.case_id);
  };

  return (
    <div className="flex flex-col gap-8">
      {/* Hero Header */}
      <section className="hero-section">
        <span className="hero-tag">SOC Investigation Platform</span>
        <h1 className="hero-title">ThreatTrace AI</h1>
        <p className="hero-description">
          Unified cybersecurity email investigation console for Security Operations Centers.
          Deterministic header forensics, safe evidence hashing, and AI threat analysis.
        </p>
      </section>

      {/* Live System Diagnostics */}
      <section>
        <SystemStatusCard />
      </section>

      {/* Evidence Ingestion Dropzone */}
      <section id="ingestion-zone">
        <EmailUploadZone onUploadSuccess={handleUploadSuccess} />
      </section>

      {/* Live Forensic Case Inspector */}
      {selectedCaseId && (
        <section id="forensics-zone">
          <EmailForensicsInspector caseId={selectedCaseId} />
        </section>
      )}

      {/* Investigation Pipeline Capabilities */}
      <section>
        <div className="mb-4">
          <h3 className="text-lg font-semibold text-white mb-1">SOC Investigation Architecture</h3>
          <p className="text-sm text-gray-400">
            Core modular capabilities provisioned for incremental feature rollouts.
          </p>
        </div>

        <div className="features-grid">
          {modules.map((mod, index) => {
            const Icon = mod.icon;
            return (
              <div
                key={index}
                className={`feature-box ${mod.highlight ? "border-cyan-500/40 shadow-lg shadow-cyan-500/5" : ""}`}
              >
                <div className="feature-header">
                  <div className="feature-icon-wrap">
                    <Icon className="w-4 h-4 text-cyan-400" />
                  </div>
                  <h4 className="feature-title">{mod.title}</h4>
                </div>
                <p className="feature-desc">{mod.description}</p>
                <span
                  className={`feature-tag ${
                    mod.highlight
                      ? "bg-emerald-500/10 text-emerald-400 border border-emerald-500/20"
                      : ""
                  }`}
                >
                  {mod.status}
                </span>
              </div>
            );
          })}
        </div>
      </section>
    </div>
  );
}
