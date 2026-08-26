"use client";

import React, { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import {
  Shield,
  RefreshCw,
  Mail,
  Paperclip,
  FileDown,
  FileCheck2,
  Share2,
} from "lucide-react";
import {
  downloadInvestigationReport,
  getCaseEvidence,
  getCaseGeoInfrastructure,
  getCaseIOCs,
  getCaseRisk,
  getCaseThreatGraph,
  getCaseThreatIntel,
  getCaseTimeline,
  getHeaderForensics,
  getParsedEmail,
  getThreatAnalysis,
  verifyCaseEvidence,
  getAnalysisStatus,
} from "@/lib/api/email";
import {
  CaseEvidenceListResponse,
  CaseEvidenceVerificationResponse,
  CaseGeoInfrastructureResponse,
  CaseIOCListResponse,
  CaseThreatGraphResponse,
  CaseThreatIntelResponse,
  ForensicTimelineResponse,
  HeaderForensicsResponse,
  ParsedEmail,
  RiskAssessmentResponse,
  ThreatAssessmentResponse,
} from "@/types";
import { ThreatScoreWidget } from "./ThreatScoreWidget";
import { AuthenticationForensicsWidget } from "./AuthenticationForensicsWidget";
import { RelayHopsTimelineWidget } from "./RelayHopsTimelineWidget";
import { ThreatIntelGeoWidget } from "./ThreatIntelGeoWidget";
import { IOCTableWidget } from "./IOCTableWidget";
import { ForensicTimelineWidget } from "./ForensicTimelineWidget";
import { EvidenceIntegrityWidget } from "./EvidenceIntegrityWidget";
import { InvestigationConclusionWidget } from "./InvestigationConclusionWidget";
import { IPIntelligenceWidget } from "./IPIntelligenceWidget";
import { DomainIntelligenceWidget } from "./DomainIntelligenceWidget";
import { URLIntelligenceWidget } from "./URLIntelligenceWidget";
import { ThreatGraphWidget } from "./ThreatGraphWidget";
import { CampaignWidget } from "./CampaignWidget";
import { Card, CardContent, Badge, Button } from "@/components/ui";

interface InvestigationDashboardProps {
  caseId: string;
}

export const InvestigationDashboard: React.FC<InvestigationDashboardProps> = ({ caseId }) => {
  const [bodyFormat, setBodyFormat] = useState<"plain" | "html">("plain");
  const [isDownloadingPdf, setIsDownloadingPdf] = useState(false);
  const [isVerifyingEvidence, setIsVerifyingEvidence] = useState(false);
  const [verifyNotice, setVerifyNotice] = useState<string | null>(null);

  // 0. Polling Analysis Status Query
  const {
    data: analysisStatus,
    isLoading: isStatusLoading,
  } = useQuery({
    queryKey: ["analysis_status", caseId],
    queryFn: () => getAnalysisStatus(caseId),
    enabled: !!caseId,
    refetchInterval: (query) => {
      const status = query.state.data?.analysis_status;
      if (status === "QUEUED" || status === "PROCESSING") {
        return 2000; // Poll every 2 seconds
      }
      return false; // Stop polling
    },
  });

  const isAnalysisComplete =
    analysisStatus?.analysis_status === "COMPLETED" ||
    analysisStatus?.analysis_status === "PARTIAL" ||
    analysisStatus?.analysis_status === "FAILED";

  // 1. Parsed Email Query
  const {
    data: parsed,
    isLoading: isParsedLoading,
    isError: isParsedError,
    error: parsedError,
    refetch: refetchParsed,
  } = useQuery<ParsedEmail, Error>({
    queryKey: ["parsed_email", caseId],
    queryFn: () => getParsedEmail(caseId),
    enabled: !!caseId && isAnalysisComplete,
    staleTime: 60000,
  });

  // 2. Risk Assessment Query
  const {
    data: risk,
    isLoading: isRiskLoading,
    refetch: refetchRisk,
  } = useQuery<RiskAssessmentResponse, Error>({
    queryKey: ["case_risk", caseId],
    queryFn: () => getCaseRisk(caseId),
    enabled: !!caseId && isAnalysisComplete,
    staleTime: 60000,
  });

  // 3. AI Threat Assessment Query
  const {
    data: threat,
    isLoading: isThreatLoading,
    refetch: refetchThreat,
  } = useQuery<ThreatAssessmentResponse, Error>({
    queryKey: ["threat_analysis", caseId],
    queryFn: () => getThreatAnalysis(caseId),
    enabled: !!caseId && isAnalysisComplete,
    staleTime: 60000,
  });

  // 4. Header Forensics Query
  const {
    data: forensics,
    isLoading: isForensicsLoading,
    refetch: refetchForensics,
  } = useQuery<HeaderForensicsResponse, Error>({
    queryKey: ["header_forensics", caseId],
    queryFn: () => getHeaderForensics(caseId),
    enabled: !!caseId && isAnalysisComplete,
    staleTime: 60000,
  });

  // 5. Extracted IOCs Query
  const {
    data: iocs,
    isLoading: isIocsLoading,
    refetch: refetchIocs,
  } = useQuery<CaseIOCListResponse, Error>({
    queryKey: ["case_iocs", caseId],
    queryFn: () => getCaseIOCs(caseId),
    enabled: !!caseId && isAnalysisComplete,
    staleTime: 60000,
  });

  // 6. Threat Intel Query
  const {
    data: intel,
    isLoading: isIntelLoading,
    refetch: refetchIntel,
  } = useQuery<CaseThreatIntelResponse, Error>({
    queryKey: ["case_threat_intel", caseId],
    queryFn: () => getCaseThreatIntel(caseId),
    enabled: !!caseId && isAnalysisComplete,
    staleTime: 60000,
  });

  // 7. Geo Infrastructure Query
  const {
    data: geo,
    isLoading: isGeoLoading,
    refetch: refetchGeo,
  } = useQuery<CaseGeoInfrastructureResponse, Error>({
    queryKey: ["case_geo_infrastructure", caseId],
    queryFn: () => getCaseGeoInfrastructure(caseId),
    enabled: !!caseId && isAnalysisComplete,
    staleTime: 60000,
  });

  // 8. Forensic Timeline Query
  const {
    data: timeline,
    isLoading: isTimelineLoading,
    refetch: refetchTimeline,
  } = useQuery<ForensicTimelineResponse, Error>({
    queryKey: ["case_timeline", caseId],
    queryFn: () => getCaseTimeline(caseId),
    enabled: !!caseId && isAnalysisComplete,
    staleTime: 60000,
  });

  // 9. Evidence Records Query
  const {
    data: evidence,
    isLoading: isEvidenceLoading,
    refetch: refetchEvidence,
  } = useQuery<CaseEvidenceListResponse, Error>({
    queryKey: ["case_evidence", caseId],
    queryFn: () => getCaseEvidence(caseId),
    enabled: !!caseId && isAnalysisComplete,
    staleTime: 60000,
  });

  // 10. Threat Relationship Graph Query
  const {
    data: graph,
    isLoading: isGraphLoading,
    refetch: refetchGraph,
  } = useQuery<CaseThreatGraphResponse, Error>({
    queryKey: ["case_threat_graph", caseId],
    queryFn: () => getCaseThreatGraph(caseId),
    enabled: !!caseId && isAnalysisComplete,
    staleTime: 60000,
  });

  const handleRefreshAll = () => {
    refetchParsed();
    refetchRisk();
    refetchThreat();
    refetchForensics();
    refetchIocs();
    refetchIntel();
    refetchGeo();
    refetchTimeline();
    refetchEvidence();
    refetchGraph();
  };

  const handleDownloadPdf = async () => {
    setIsDownloadingPdf(true);
    try {
      await downloadInvestigationReport(caseId);
    } catch (err: unknown) {
      console.error("PDF export failed:", err);
    } finally {
      setIsDownloadingPdf(false);
    }
  };

  const handleVerifyEvidence = async () => {
    setIsVerifyingEvidence(true);
    setVerifyNotice(null);
    try {
      const res: CaseEvidenceVerificationResponse = await verifyCaseEvidence(caseId);
      if (res.all_valid) {
        setVerifyNotice("✓ Evidence integrity verified: All SHA-256 hashes match tamper-evident baselines.");
      } else {
        setVerifyNotice("⚠ Evidence integrity warning: One or more evidence records failed hash verification.");
      }
      refetchEvidence();
    } catch {
      setVerifyNotice("Failed to verify evidence integrity records.");
    } finally {
      setIsVerifyingEvidence(false);
    }
  };

  const isInitialLoading = !isAnalysisComplete || (isParsedLoading && !parsed);

  if (analysisStatus?.analysis_status === "QUEUED" || analysisStatus?.analysis_status === "PROCESSING") {
    return (
      <Card className="p-12 text-center flex flex-col items-center justify-center">
        <RefreshCw className="w-8 h-8 text-primary animate-spin mb-4" />
        <h3 className="text-[18px] font-[700] text-text-primary mb-2">
          {analysisStatus.analysis_step || "Analyzing email..."}
        </h3>
        <p className="text-sm font-mono text-text-secondary">
          ThreatTrace is performing near-real-time automated analysis...
        </p>
      </Card>
    );
  }

  if (analysisStatus?.analysis_status === "FAILED") {
    return (
      <Card className="p-8">
        <h3 className="text-[18px] font-[700] text-danger-dark mb-4">
          Investigation Analysis Failed
        </h3>
        <div className="p-4 bg-danger-bg border border-danger text-danger-dark rounded-[8px] mb-6 text-sm">
          {analysisStatus.error_message || "A critical error occurred during background analysis."}
        </div>
      </Card>
    );
  }

  if (isInitialLoading) {
    return (
      <Card className="p-12 text-center flex flex-col items-center justify-center">
        <RefreshCw className="w-8 h-8 text-primary animate-spin mb-4" />
        <h3 className="text-[18px] font-[700] text-text-primary mb-2">
          Loading Investigation Telemetry...
        </h3>
        <p className="text-sm font-mono text-text-secondary">
          Aggregating case evidence, header forensics, threat intelligence, and risk assessment
        </p>
      </Card>
    );
  }

  if (isParsedError || !parsed) {
    return (
      <Card className="p-8">
        <h3 className="text-[18px] font-[700] text-danger-dark mb-4">
          Investigation Loading Notice
        </h3>
        <div className="p-4 bg-danger-bg border border-danger text-danger-dark rounded-[8px] mb-6 text-sm">
          Email parsing failed: {parsedError?.message || "Failed to load case investigation evidence."}
        </div>
        <div className="text-center">
          <Button variant="secondary" onClick={handleRefreshAll} className="gap-2">
            <RefreshCw className="w-4 h-4" />
            <span>Retry Investigation Analysis</span>
          </Button>
        </div>
      </Card>
    );
  }

  return (
    <div className="flex flex-col gap-6">
      {/* Investigation Top Header Bar */}
      <Card className="shadow-md">
        <CardContent className="p-4 sm:p-6">
          <div className="flex flex-col md:flex-row md:justify-between md:items-start gap-4 mb-4">
            <div className="flex flex-col">
              <div className="flex items-center gap-3 mb-2">
                <Shield className="w-6 h-6 text-primary" />
                <h1 className="text-[20px] font-[800] text-text-primary tracking-tight">
                  Case Investigation Console
                </h1>
                <Badge variant="neutral" className="bg-primary-soft text-primary border-primary font-[700] text-[10px] px-2 py-0.5">
                  ACTIVE CASE
                </Badge>
              </div>
              <span className="text-[12px] text-text-secondary font-mono">
                Case ID: {parsed.case_id} • Ingested: {new Date(parsed.created_at).toLocaleString()}
              </span>
            </div>

            {/* Refresh Header Control */}
            <div className="flex items-center">
              <button
                onClick={handleRefreshAll}
                className="p-2 rounded hover:bg-bg-panel-subtle text-text-secondary hover:text-text-primary transition-colors"
                title="Refresh all investigation telemetry"
                aria-label="Refresh telemetry"
              >
                <RefreshCw className="w-4 h-4" />
              </button>
            </div>
          </div>

          {verifyNotice && (
            <div className={`mt-4 p-3 rounded-[8px] border text-sm ${
              verifyNotice.startsWith("✓") 
                ? "bg-success-bg border-success text-success-dark" 
                : "bg-warning-bg border-warning text-warning-dark"
            }`}>
              <div className="flex items-center justify-between">
                <span>{verifyNotice}</span>
                <button onClick={() => setVerifyNotice(null)} className="opacity-70 hover:opacity-100 text-lg leading-none">&times;</button>
              </div>
            </div>
          )}

        </CardContent>
      </Card>

      {/* SIH WORKFLOW */}
      {/* 1. Verdict & 2. Risk & 3. Why Flagged */}
      <section id="section-verdict-why">
        <InvestigationConclusionWidget caseId={parsed.case_id} />
        <ThreatScoreWidget
          risk={risk}
          threat={threat}
          forensics={forensics}
          caseId={parsed.case_id}
          isLoading={isRiskLoading || isThreatLoading}
        />
      </section>

      {/* 4. Authentication */}
      <section id="section-auth">
        <AuthenticationForensicsWidget forensics={forensics} isLoading={isForensicsLoading} />
      </section>

      {/* 5. Sender Identity */}
      <section id="section-email-summary">
        <Card className="shadow-md overflow-hidden">
          <CardContent className="p-6">
            <div className="flex items-center gap-3 mb-6">
              <Mail className="w-5 h-5 text-primary" />
              <h2 className="text-[16px] font-[700] text-text-primary">
                Email Envelope & Identity Summary
              </h2>
            </div>
            
            <div className="p-5 bg-bg-page border border-border rounded-[8px] mb-6">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-5">
                <div className="flex flex-col gap-1">
                  <span className="text-[11px] font-[600] text-text-secondary uppercase tracking-wider">
                    From (Sender)
                  </span>
                  <span className="text-[13px] font-[600] text-text-primary break-all">
                    {parsed.from_name ? `${parsed.from_name} <${parsed.from_address || parsed.sender}>` : parsed.sender || "N/A"}
                  </span>
                </div>
                <div className="flex flex-col gap-1">
                  <span className="text-[11px] font-[600] text-text-secondary uppercase tracking-wider">
                    To (Recipients)
                  </span>
                  <span className="text-[13px] font-[600] text-text-primary break-all">
                    {parsed.recipients && parsed.recipients.length > 0 ? parsed.recipients.join(", ") : "None declared"}
                  </span>
                </div>
                <div className="flex flex-col gap-1">
                  <span className="text-[11px] font-[600] text-text-secondary uppercase tracking-wider">
                    Subject
                  </span>
                  <span className="text-[14px] font-[700] text-primary">
                    {parsed.subject || "(No Subject Declared)"}
                  </span>
                </div>
                <div className="flex flex-col gap-1">
                  <span className="text-[11px] font-[600] text-text-secondary uppercase tracking-wider">
                    Date Declared
                  </span>
                  <span className="text-[13px] text-text-primary">
                    {parsed.date_parsed ? new Date(parsed.date_parsed).toUTCString() : parsed.date_raw || "Not available"}
                  </span>
                </div>
                <div className="flex flex-col gap-1">
                  <span className="text-[11px] font-[600] text-text-secondary uppercase tracking-wider">
                    Message-ID
                  </span>
                  <span className="text-[11px] font-mono text-text-muted break-all">
                    {parsed.message_id || "None declared"}
                  </span>
                </div>
                <div className="flex flex-col gap-1">
                  <span className="text-[11px] font-[600] text-text-secondary uppercase tracking-wider">
                    Reply-To / CC
                  </span>
                  <span className="text-[13px] text-text-muted">
                    {parsed.reply_to && parsed.reply_to.length > 0 ? `Reply-To: ${parsed.reply_to.join(", ")}` : "No Reply-To mismatch"}
                  </span>
                </div>
              </div>
            </div>

            <div className="mb-0">
              <div className="flex flex-col sm:flex-row sm:justify-between sm:items-center gap-3 mb-4">
                <h3 className="text-[14px] font-[700] text-text-primary">
                  Email Body Content Preview
                </h3>
                <div className="flex items-center bg-bg-panel-subtle p-1 rounded-[6px] border border-border">
                  <button
                    onClick={() => setBodyFormat("plain")}
                    className={`px-3 py-1 text-[11px] font-[600] rounded-[4px] transition-colors ${
                      bodyFormat === "plain" ? "bg-white shadow text-text-primary" : "text-text-secondary hover:text-text-primary"
                    }`}
                  >
                    Plain Text
                  </button>
                  <button
                    onClick={() => setBodyFormat("html")}
                    className={`px-3 py-1 text-[11px] font-[600] rounded-[4px] transition-colors ${
                      bodyFormat === "html" ? "bg-white shadow text-text-primary" : "text-text-secondary hover:text-text-primary"
                    }`}
                  >
                    Safe HTML
                  </button>
                </div>
              </div>

              {bodyFormat === "plain" ? (
                <div className="p-4 bg-slate-900 rounded-[8px] border border-slate-700 max-h-[220px] overflow-y-auto custom-scrollbar font-mono text-[12px] text-slate-300 whitespace-pre-wrap">
                  {parsed.body_plain || "No plain text content available."}
                </div>
              ) : (
                <div 
                  className="p-4 bg-white rounded-[8px] border border-border max-h-[220px] overflow-y-auto custom-scrollbar text-[13px] text-slate-800"
                  dangerouslySetInnerHTML={{
                    __html: parsed.body_html || "<p>No HTML body content available.</p>",
                  }}
                />
              )}
            </div>
          </CardContent>
        </Card>
      </section>

      {/* 6. Relay/origin */}
      <section id="section-relay-origin">
        <RelayHopsTimelineWidget forensics={forensics} isLoading={isForensicsLoading} />
      </section>

      {/* 7. Infrastructure intelligence */}
      <section id="section-threat-intel-geo" className="flex flex-col gap-6">
        <ThreatIntelGeoWidget intel={intel} geo={geo} isLoading={isIntelLoading || isGeoLoading} />
        <IPIntelligenceWidget caseId={caseId} />
        <DomainIntelligenceWidget caseId={caseId} />
        <URLIntelligenceWidget caseId={caseId} />
      </section>

      {/* 8. IOCs */}
      <section id="section-iocs">
        <IOCTableWidget iocData={iocs} isLoading={isIocsLoading} />
      </section>

      {/* 9. Related campaign */}
      <section id="section-campaign">
        <CampaignWidget caseId={parsed.case_id} />
      </section>

      {/* 10. Evidence integrity */}
      <section id="section-evidence">
        <EvidenceIntegrityWidget caseId={caseId} />
        {parsed.attachments_metadata && parsed.attachments_metadata.length > 0 && (
          <Card className="mt-6">
            <CardContent className="p-6">
              <h3 className="text-[14px] font-[700] text-text-primary mb-3 flex items-center gap-2">
                <Paperclip className="w-4 h-4" /> Attached Evidence Files ({parsed.attachments_metadata.length})
              </h3>
              <div className="flex flex-col gap-2">
                {parsed.attachments_metadata.map((att, idx) => (
                  <div
                    key={idx}
                    className="p-3 bg-bg-page border border-border rounded-[8px] flex flex-col sm:flex-row sm:items-center justify-between gap-3"
                  >
                    <div className="flex flex-col gap-1">
                      <span className="text-[13px] font-[600] text-text-primary">
                        {att.filename}
                      </span>
                      <span className="text-[11px] text-text-secondary font-mono">
                        Size: {(att.file_size_bytes / 1024).toFixed(1)} KB • SHA-256: {att.sha256}
                      </span>
                    </div>
                    <Badge variant="neutral" className="bg-border/50 text-text-muted text-[10px] uppercase w-fit">
                      {att.extension}
                    </Badge>
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>
        )}
      </section>

      {/* 11. Graph */}
      <section id="section-graph">
        <ThreatGraphWidget graph={graph} isLoading={isGraphLoading} onRefresh={refetchGraph} />
      </section>

      {/* 12. Timeline */}
      <section id="section-timeline">
        <ForensicTimelineWidget timelineData={timeline} isLoading={isTimelineLoading} />
      </section>

      {/* SECTION L: BOTTOM ACTIONS TOOLBAR */}
      <Card className="p-6">
        <div className="flex flex-col md:flex-row md:justify-between md:items-center gap-4">
          <div className="flex flex-col gap-1">
            <h3 className="text-[14px] font-[700] text-text-primary">
              Investigation Actions & Export
            </h3>
            <span className="text-[12px] text-text-secondary">
              Generate tamper-evident PDF reports, verify cryptographic hash records, or re-run analysis.
            </span>
          </div>

          <div className="flex flex-wrap items-center gap-3">
            <Button
              variant="secondary"
              onClick={handleDownloadPdf}
              disabled={isDownloadingPdf}
              className="gap-2 px-3 py-1.5 h-auto text-xs"
            >
              <FileDown className="w-4 h-4" />
              <span>{isDownloadingPdf ? "Compiling PDF..." : "Export PDF Report"}</span>
            </Button>

            <Button
              variant="secondary"
              onClick={() => {
                const el = document.getElementById("section-graph");
                if (el) el.scrollIntoView({ behavior: "smooth" });
              }}
              className="gap-2 px-3 py-1.5 h-auto text-xs"
            >
              <Share2 className="w-4 h-4" />
              <span>View Relationship Graph</span>
            </Button>

            <Button
              variant="primary"
              onClick={handleVerifyEvidence}
              disabled={isVerifyingEvidence}
              className="gap-2 px-3 py-1.5 h-auto text-xs"
            >
              <FileCheck2 className="w-4 h-4" />
              <span>Verify Evidence Integrity</span>
            </Button>
          </div>
        </div>
      </Card>
    </div>
  );
};
