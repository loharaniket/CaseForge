"use client";

import React, { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import {
  FileSearch,
  Mail,
  User,
  Calendar,
  Key,
  Globe,
  Paperclip,
  Code,
  Copy,
  Check,
  Shield,
  FileText,
  AlertTriangle,
  RefreshCw,
} from "lucide-react";
import { getParsedEmail } from "@/lib/api/email";
import { ParsedEmail } from "@/types";

interface EmailForensicsInspectorProps {
  caseId: string;
}

type TabKey = "body" | "urls" | "attachments" | "headers";

export const EmailForensicsInspector: React.FC<EmailForensicsInspectorProps> = ({ caseId }) => {
  const [activeTab, setActiveTab] = useState<TabKey>("body");
  const [bodyFormat, setBodyFormat] = useState<"plain" | "html">("plain");
  const [copiedUrl, setCopiedUrl] = useState<string | null>(null);

  const {
    data: parsed,
    isLoading,
    isError,
    error,
    refetch,
    isFetching,
  } = useQuery<ParsedEmail, Error>({
    queryKey: ["parsed_email", caseId],
    queryFn: () => getParsedEmail(caseId),
    enabled: !!caseId,
    retry: 1,
  });

  const handleCopy = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopiedUrl(text);
    setTimeout(() => setCopiedUrl(null), 2000);
  };

  if (isLoading) {
    return (
      <div className="card">
        <div className="p-8 text-center flex flex-col items-center gap-2">
          <RefreshCw className="w-8 h-8 text-cyan-400 animate-spin" />
          <p className="text-sm font-semibold text-white">Performing Deterministic EML Forensic Parsing...</p>
          <p className="text-xs text-gray-400 font-mono">Extracting RFC headers, bodies, attachments, and URLs</p>
        </div>
      </div>
    );
  }

  if (isError || !parsed) {
    return (
      <div className="card">
        <div className="p-6 text-center flex flex-col items-center gap-3">
          <AlertTriangle className="w-8 h-8 text-amber-400" />
          <div>
            <h3 className="text-sm font-semibold text-white">Forensic Parsing Notice</h3>
            <p className="text-xs text-gray-400 mt-1">
              {error?.message || "Failed to retrieve parsed forensic analysis for this case."}
            </p>
          </div>
          <button onClick={() => refetch()} className="action-btn">
            <RefreshCw className="w-3.5 h-3.5" />
            <span>Retry Parsing</span>
          </button>
        </div>
      </div>
    );
  }

  return (
    <div className="card">
      {/* Header Banner */}
      <div className="card-header">
        <div className="flex items-center gap-2">
          <FileSearch className="w-5 h-5 text-cyan-400" />
          <h2 className="card-title">Forensic Case Analysis: {parsed.case_id}</h2>
        </div>
        <div className="flex items-center gap-2">
          <span className="status-pill ready">PARSED</span>
          <button
            onClick={() => refetch()}
            disabled={isFetching}
            className="refresh-button"
            title="Re-parse evidence"
          >
            <RefreshCw className={`w-4 h-4 ${isFetching ? "animate-spin text-cyan-400" : ""}`} />
          </button>
        </div>
      </div>

      {/* Forensic Header Summary Grid */}
      <div className="forensic-summary-grid">
        <div className="forensic-summary-item">
          <div className="flex items-center gap-1.5 text-xs text-gray-400 mb-1">
            <Mail className="w-3.5 h-3.5 text-cyan-400" />
            <span>Subject</span>
          </div>
          <p className="font-semibold text-sm text-white break-words">
            {parsed.subject || "(No Subject Header)"}
          </p>
        </div>

        <div className="forensic-summary-item">
          <div className="flex items-center gap-1.5 text-xs text-gray-400 mb-1">
            <User className="w-3.5 h-3.5 text-cyan-400" />
            <span>Sender (From)</span>
          </div>
          <p className="font-mono text-xs text-cyan-300 break-all">
            {parsed.sender || parsed.from_address || "Unknown"}
          </p>
        </div>

        <div className="forensic-summary-item">
          <div className="flex items-center gap-1.5 text-xs text-gray-400 mb-1">
            <User className="w-3.5 h-3.5 text-emerald-400" />
            <span>Recipients (To)</span>
          </div>
          <p className="font-mono text-xs text-gray-200 break-all">
            {parsed.recipients.length > 0 ? parsed.recipients.join(", ") : "None specified"}
          </p>
        </div>

        <div className="forensic-summary-item">
          <div className="flex items-center gap-1.5 text-xs text-gray-400 mb-1">
            <Calendar className="w-3.5 h-3.5 text-amber-400" />
            <span>Date & Timestamp</span>
          </div>
          <p className="font-mono text-xs text-gray-200">
            {parsed.date_parsed ? new Date(parsed.date_parsed).toUTCString() : parsed.date_raw || "Unknown"}
          </p>
        </div>

        {parsed.message_id && (
          <div className="forensic-summary-item col-span-full">
            <div className="flex items-center gap-1.5 text-xs text-gray-400 mb-1">
              <Key className="w-3.5 h-3.5 text-gray-400" />
              <span>Message-ID</span>
            </div>
            <p className="font-mono text-xs text-gray-400 break-all">{parsed.message_id}</p>
          </div>
        )}
      </div>

      {/* Forensic Tabs Navigation */}
      <div className="forensics-tabs-bar">
        <button
          onClick={() => setActiveTab("body")}
          className={`forensics-tab-btn ${activeTab === "body" ? "active" : ""}`}
        >
          <FileText className="w-4 h-4" />
          <span>Body Content</span>
        </button>

        <button
          onClick={() => setActiveTab("urls")}
          className={`forensics-tab-btn ${activeTab === "urls" ? "active" : ""}`}
        >
          <Globe className="w-4 h-4" />
          <span>Extracted URLs</span>
          <span className="tab-count-badge">{parsed.extracted_urls.length}</span>
        </button>

        <button
          onClick={() => setActiveTab("attachments")}
          className={`forensics-tab-btn ${activeTab === "attachments" ? "active" : ""}`}
        >
          <Paperclip className="w-4 h-4" />
          <span>Attachments</span>
          <span className="tab-count-badge">{parsed.attachments_metadata.length}</span>
        </button>

        <button
          onClick={() => setActiveTab("headers")}
          className={`forensics-tab-btn ${activeTab === "headers" ? "active" : ""}`}
        >
          <Code className="w-4 h-4" />
          <span>Raw RFC Headers</span>
          <span className="tab-count-badge">{Object.keys(parsed.raw_headers || {}).length}</span>
        </button>
      </div>

      {/* Tab 1: Body Content */}
      {activeTab === "body" && (
        <div className="tab-content-box">
          <div className="flex items-center justify-between pb-3 mb-3 border-b border-gray-800">
            <span className="text-xs text-gray-400">Viewing parsed email body payload</span>
            <div className="flex items-center gap-1 bg-gray-900 p-0.5 rounded-lg border border-gray-800">
              <button
                onClick={() => setBodyFormat("plain")}
                className={`format-toggle-btn ${bodyFormat === "plain" ? "active" : ""}`}
              >
                Plain Text
              </button>
              <button
                onClick={() => setBodyFormat("html")}
                className={`format-toggle-btn ${bodyFormat === "html" ? "active" : ""}`}
                disabled={!parsed.body_html}
              >
                Sandboxed HTML
              </button>
            </div>
          </div>

          {bodyFormat === "plain" ? (
            <pre className="body-text-box">
              {parsed.body_plain || "(No plain-text body part present in email)"}
            </pre>
          ) : (
            <div className="sandboxed-html-wrap">
              <div className="sandboxed-html-warning">
                <Shield className="w-3.5 h-3.5 text-amber-400" />
                <span>Isolated sandbox iframe: Scripts, forms, and external network interactions disabled.</span>
              </div>
              <iframe
                title="Sandboxed Email HTML Body"
                sandbox="allow-same-origin"
                srcDoc={parsed.body_html || "<p>No HTML payload</p>"}
                className="sandboxed-html-frame"
              />
            </div>
          )}
        </div>
      )}

      {/* Tab 2: Extracted URLs */}
      {activeTab === "urls" && (
        <div className="tab-content-box">
          {parsed.extracted_urls.length === 0 ? (
            <div className="p-6 text-center text-xs text-gray-400 font-mono">
              No embedded HTTP/HTTPS URLs detected in this email.
            </div>
          ) : (
            <div className="flex flex-col gap-2">
              <div className="flex items-center gap-2 mb-1">
                <span className="text-xs text-gray-400 font-mono">
                  {parsed.extracted_urls.length} distinct URL targets extracted for inspection (no automatic network calls made)
                </span>
              </div>
              {parsed.extracted_urls.map((url, idx) => (
                <div key={idx} className="extracted-url-card">
                  <span className="url-index">#{idx + 1}</span>
                  <span className="url-text font-mono select-all">{url}</span>
                  <button
                    onClick={() => handleCopy(url)}
                    className="copy-btn"
                    title="Copy URL to clipboard"
                  >
                    {copiedUrl === url ? (
                      <Check className="w-3.5 h-3.5 text-emerald-400" />
                    ) : (
                      <Copy className="w-3.5 h-3.5 text-gray-400" />
                    )}
                  </button>
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {/* Tab 3: Attachment Forensics */}
      {activeTab === "attachments" && (
        <div className="tab-content-box">
          {parsed.attachments_metadata.length === 0 ? (
            <div className="p-6 text-center text-xs text-gray-400 font-mono">
              No binary or document attachments identified in this evidence file.
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="attachments-table">
                <thead>
                  <tr>
                    <th>Filename</th>
                    <th>Type</th>
                    <th>Size</th>
                    <th>SHA-256 Fingerprint</th>
                  </tr>
                </thead>
                <tbody>
                  {parsed.attachments_metadata.map((att, idx) => (
                    <tr key={idx}>
                      <td className="font-semibold text-white">{att.filename}</td>
                      <td>
                        <span className="ext-badge font-mono">{att.extension || "bin"}</span>
                      </td>
                      <td className="font-mono text-gray-300">
                        {(att.file_size_bytes / 1024).toFixed(1)} KB
                      </td>
                      <td>
                        <span className="font-mono text-xs text-cyan-300 select-all">{att.sha256}</span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}

      {/* Tab 4: Raw RFC Headers */}
      {activeTab === "headers" && (
        <div className="tab-content-box">
          <div className="raw-headers-box">
            {Object.entries(parsed.raw_headers || {}).map(([key, val], idx) => (
              <div key={idx} className="raw-header-row">
                <span className="raw-header-key font-mono">{key}:</span>
                <span className="raw-header-val font-mono">
                  {Array.isArray(val) ? val.join("\n") : String(val)}
                </span>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
};
