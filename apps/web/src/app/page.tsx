"use client";

import React, { useState } from "react";
import { SystemStatusCard } from "@/components/dashboard/SystemStatusCard";
import { EmailUploadZone } from "@/components/investigation/EmailUploadZone";
import { InvestigationDashboard } from "@/components/dashboard/InvestigationDashboard";
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
      description: "Automated SPF, DKIM, and DMARC alignment, selector extraction, and spoofing detection.",
      status: "Live & Active",
      highlight: true,
    },
    {
      icon: Cpu,
      title: "AI Threat Detection & Risk Scoring",
      description: "Multi-class threat categorization, explainable heuristic reasons, and deterministic 0-100 risk scoring.",
      status: "Live & Active",
      highlight: true,
    },
    {
      icon: Globe2,
      title: "Threat Intel & Geo Infrastructure",
      description: "IP and Domain reputation adapters (AbuseIPDB, VirusTotal) and Probable Infrastructure Origin resolution.",
      status: "Live & Active",
      highlight: true,
    },
    {
      icon: Share2,
      title: "IOC Extraction & Telemetry",
      description: "Deterministic normalization and deduplication across 6 IOC types (IPv4, IPv6, Domain, URL, Email, SHA-256).",
      status: "Live & Active",
      highlight: true,
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

      {/* Live Analyst Investigation Dashboard */}
      {selectedCaseId && (
        <section id="investigation-zone">
          <InvestigationDashboard caseId={selectedCaseId} />
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
