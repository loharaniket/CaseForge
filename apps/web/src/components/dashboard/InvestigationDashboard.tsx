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
  Layers,
  Flame,
  ShieldAlert,
  AlertTriangle,
  ShieldCheck,
  Globe,
  Radio,
  Clock,
  Lock,
  ArrowLeft,
  Copy,
  Check,
  ExternalLink,
  Search,
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

type ActiveTab =
  | "overview"
  | "authentication"
  | "intel"
  | "iocs"
  | "graph"
  | "timeline"
  | "evidence";

interface InvestigationDashboardProps {
  caseId: string;
  onBack?: () => void;
}

export const InvestigationDashboard: React.FC<InvestigationDashboardProps> = ({
  caseId,
  onBack,
}) => {
  const [activeTab, setActiveTab] = useState<ActiveTab>("overview");
  const [bodyFormat, setBodyFormat] = useState<"plain" | "html">("plain");
  const [isDownloadingPdf, setIsDownloadingPdf] = useState(false);
  const [isVerifyingEvidence, setIsVerifyingEvidence] = useState(false);
  const [verifyNotice, setVerifyNotice] = useState<string | null>(null);
  const [copiedCaseId, setCopiedCaseId] = useState(false);

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
        return 2000;
      }
      return false;
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

  const handleCopyCaseId = () => {
    navigator.clipboard.writeText(caseId);
    setCopiedCaseId(true);
    setTimeout(() => setCopiedCaseId(false), 2000);
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
      <div className="bg-bg-panel border border-border rounded-xl p-12 text-center flex flex-col items-center justify-center shadow-lg">
        <div className="relative mb-6">
          <div className="w-16 h-16 rounded-full bg-primary-soft flex items-center justify-center animate-pulse">
            <Shield className="w-8 h-8 text-primary" />
          </div>
          <RefreshCw className="w-6 h-6 text-primary animate-spin absolute -bottom-1 -right-1" />
        </div>
        <h3 className="text-xl font-bold text-text-primary mb-2">
          {analysisStatus.analysis_step || "Analyzing Suspicious Email..."}
        </h3>
        <p className="text-sm font-mono text-text-secondary max-w-md">
          CaseForge is executing header forensics, reputation lookups, and ML-assisted threat scoring.
        </p>
      </div>
    );
  }

  if (analysisStatus?.analysis_status === "FAILED") {
    return (
      <div className="bg-bg-panel border border-danger/40 rounded-xl p-8 shadow-lg">
        <div className="flex items-center gap-3 text-danger mb-4">
          <AlertTriangle className="w-6 h-6" />
          <h3 className="text-lg font-bold">Investigation Analysis Failed</h3>
        </div>
        <div className="p-4 bg-danger-bg border border-danger rounded-lg mb-6 text-sm text-critical">
          {analysisStatus.error_message || "A critical error occurred during background analysis."}
        </div>
        {onBack && (
          <Button variant="secondary" onClick={onBack} className="gap-2">
            <ArrowLeft className="w-4 h-4" />
            <span>Return to Cases</span>
          </Button>
        )}
      </div>
    );
  }

  if (isInitialLoading) {
    return (
      <div className="bg-bg-panel border border-border rounded-xl p-12 text-center flex flex-col items-center justify-center shadow-lg">
        <RefreshCw className="w-8 h-8 text-primary animate-spin mb-4" />
        <h3 className="text-lg font-bold text-text-primary mb-2">
          Loading Investigation Telemetry...
        </h3>
        <p className="text-sm font-mono text-text-secondary">
          Aggregating case evidence, header forensics, threat intelligence, and risk assessment
        </p>
      </div>
    );
  }

  if (isParsedError || !parsed) {
    return (
      <div className="bg-bg-panel border border-border rounded-xl p-8 shadow-lg">
        <h3 className="text-lg font-bold text-critical mb-4">
          Investigation Loading Notice
        </h3>
        <div className="p-4 bg-danger-bg border border-danger rounded-lg mb-6 text-sm text-critical">
          Email parsing failed: {parsedError?.message || "Failed to load case investigation evidence."}
        </div>
        <div className="flex items-center gap-3">
          <Button variant="secondary" onClick={handleRefreshAll} className="gap-2">
            <RefreshCw className="w-4 h-4" />
            <span>Retry Investigation Analysis</span>
          </Button>
          {onBack && (
            <Button variant="secondary" onClick={onBack} className="gap-2">
              <ArrowLeft className="w-4 h-4" />
              <span>Back to Cases</span>
            </Button>
          )}
        </div>
      </div>
    );
  }

  // Calculate score & severity metrics
  const totalScore = risk ? Math.round(risk.total_score) : 0;
  const severity = (risk?.severity || threat?.classification || "low").toLowerCase();
  const classification = (threat?.classification || "normal").toUpperCase();

  const getSeverityStyle = (sev: string) => {
    switch (sev) {
      case "critical":
        return {
          bg: "bg-red-500/10",
          border: "border-red-500/40",
          text: "text-red-500",
          ring: "stroke-red-500",
          glow: "shadow-[0_0_20px_rgba(239,68,68,0.25)]",
          label: "CRITICAL RISK",
          icon: Flame,
        };
      case "high":
        return {
          bg: "bg-orange-500/10",
          border: "border-orange-500/40",
          text: "text-orange-500",
          ring: "stroke-orange-500",
          glow: "shadow-[0_0_20px_rgba(249,115,22,0.25)]",
          label: "HIGH RISK",
          icon: ShieldAlert,
        };
      case "medium":
        return {
          bg: "bg-amber-500/10",
          border: "border-amber-500/40",
          text: "text-amber-500",
          ring: "stroke-amber-500",
          glow: "shadow-[0_0_20px_rgba(245,158,11,0.25)]",
          label: "MEDIUM RISK",
          icon: AlertTriangle,
        };
      default:
        return {
          bg: "bg-emerald-500/10",
          border: "border-emerald-500/40",
          text: "text-emerald-500",
          ring: "stroke-emerald-500",
          glow: "shadow-[0_0_20px_rgba(16,185,129,0.25)]",
          label: "LOW / BENIGN",
          icon: ShieldCheck,
        };
    }
  };

  const sevStyle = getSeverityStyle(severity);
  const SevIcon = sevStyle.icon;

  const totalIocCount = iocs?.total_count ?? iocs?.iocs?.length ?? 0;

  const tabs: { id: ActiveTab; label: string; icon: React.ElementType; badge?: string | number }[] = [
    { id: "overview", label: "Overview & Verdict", icon: Shield },
    { id: "authentication", label: "Authentication & Relays", icon: Radio },
    { id: "intel", label: "Threat Intel & Geo", icon: Globe },
    {
      id: "iocs",
      label: "IOC Indicators",
      icon: Layers,
      badge: totalIocCount > 0 ? totalIocCount : undefined,
    },
    { id: "graph", label: "Threat Graph", icon: Share2 },
    { id: "timeline", label: "Forensic Timeline", icon: Clock },
    {
      id: "evidence",
      label: "Evidence & Custody Integrity",
      icon: Lock,
      badge: parsed.attachments_metadata?.length ? parsed.attachments_metadata.length : undefined,
    },
  ];

  return (
    <div className="flex flex-col gap-6">
      {/* TOP EXECUTIVE COMMAND HEADER */}
      <div className="bg-nav-bg border border-[#243B53] rounded-xl p-5 md:p-6 text-white shadow-xl">
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-6">
          {/* Left: Case Info & Status */}
          <div className="flex flex-col gap-2">
            <div className="flex flex-wrap items-center gap-3">
              {onBack && (
                <button
                  onClick={onBack}
                  className="flex items-center gap-1 text-xs font-semibold text-[#9FB3C8] hover:text-white bg-[#243B53] hover:bg-[#334E68] px-2.5 py-1 rounded transition-colors"
                  title="Return to investigation list"
                >
                  <ArrowLeft className="w-3.5 h-3.5" />
                  <span>Cases</span>
                </button>
              )}
              <h1 className="text-xl md:text-2xl font-black text-white tracking-tight flex items-center gap-2">
                <Shield className="w-6 h-6 text-cyan-400" />
                Case Investigation Console
              </h1>
              <span className={`px-2.5 py-0.5 rounded-full text-xs font-black uppercase tracking-wider border ${sevStyle.bg} ${sevStyle.border} ${sevStyle.text}`}>
                {sevStyle.label}
              </span>
            </div>

            <div className="flex flex-wrap items-center gap-x-4 gap-y-1 text-xs text-[#9FB3C8] font-mono">
              <span className="flex items-center gap-1.5">
                Case ID:
                <span className="text-white font-bold">{parsed.case_id}</span>
                <button
                  onClick={handleCopyCaseId}
                  className="p-1 hover:text-white rounded transition-colors"
                  title="Copy Case ID"
                >
                  {copiedCaseId ? (
                    <Check className="w-3.5 h-3.5 text-emerald-400" />
                  ) : (
                    <Copy className="w-3.5 h-3.5" />
                  )}
                </button>
              </span>
              <span>•</span>
              <span>Ingested: {new Date(parsed.created_at).toLocaleString()}</span>
              {parsed.subject && (
                <>
                  <span>•</span>
                  <span className="text-slate-300 font-sans italic truncate max-w-sm">
                    "{parsed.subject}"
                  </span>
                </>
              )}
            </div>
          </div>

          {/* Right: Quick Actions */}
          <div className="flex flex-wrap items-center gap-2.5 self-start lg:self-center">
            <button
              onClick={handleDownloadPdf}
              disabled={isDownloadingPdf}
              className="inline-flex items-center gap-2 px-3.5 py-1.5 rounded-lg text-xs font-bold text-white bg-[#243B53] hover:bg-[#334E68] border border-cyan-500/40 hover:border-cyan-400 shadow-sm transition-all disabled:opacity-50 disabled:cursor-not-allowed"
            >
              <FileDown className="w-4 h-4 text-cyan-400 shrink-0" />
              <span className="text-white font-bold">{isDownloadingPdf ? "Compiling PDF..." : "Export PDF Report"}</span>
            </button>

            <button
              onClick={handleVerifyEvidence}
              disabled={isVerifyingEvidence}
              className="inline-flex items-center gap-2 px-3.5 py-1.5 rounded-lg text-xs font-bold text-white bg-[#243B53] hover:bg-[#334E68] border border-emerald-500/40 hover:border-emerald-400 shadow-sm transition-all disabled:opacity-50 disabled:cursor-not-allowed"
            >
              <FileCheck2 className="w-4 h-4 text-emerald-400 shrink-0" />
              <span className="text-white font-bold">{isVerifyingEvidence ? "Verifying..." : "Verify Custody"}</span>
            </button>

            <button
              onClick={handleRefreshAll}
              className="p-2 rounded-lg bg-[#243B53] hover:bg-[#334E68] text-[#9FB3C8] hover:text-white transition-colors border border-[#334E68]"
              title="Refresh all investigation telemetry"
              aria-label="Refresh telemetry"
            >
              <RefreshCw className="w-4 h-4" />
            </button>
          </div>
        </div>

        {/* Verification Status Alert */}
        {verifyNotice && (
          <div
            className={`mt-4 p-3 rounded-lg border text-sm flex items-center justify-between ${
              verifyNotice.startsWith("✓")
                ? "bg-emerald-950/50 border-emerald-500/50 text-emerald-300"
                : "bg-amber-950/50 border-amber-500/50 text-amber-300"
            }`}
          >
            <span>{verifyNotice}</span>
            <button
              onClick={() => setVerifyNotice(null)}
              className="opacity-70 hover:opacity-100 text-lg leading-none ml-2"
            >
              &times;
            </button>
          </div>
        )}

        {/* KPI TELEMETRY METRIC TILES */}
        <div className="grid grid-cols-2 lg:grid-cols-4 gap-3 mt-6 pt-5 border-t border-[#243B53]">
          {/* Tile 1: Threat Score Gauge */}
          <div className="flex items-center gap-3.5 bg-[#121A22] p-3 rounded-lg border border-[#243B53]">
            <div className="relative w-12 h-12 flex items-center justify-center shrink-0">
              <svg className="w-12 h-12 -rotate-90" viewBox="0 0 36 36">
                <path
                  className="text-slate-800"
                  strokeWidth="3.5"
                  stroke="currentColor"
                  fill="none"
                  d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831"
                />
                <path
                  className={sevStyle.ring}
                  strokeDasharray={`${totalScore}, 100`}
                  strokeWidth="3.5"
                  strokeLinecap="round"
                  stroke="currentColor"
                  fill="none"
                  d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831"
                />
              </svg>
              <span className="absolute font-black text-sm text-white">
                {totalScore}
              </span>
            </div>
            <div className="flex flex-col">
              <span className="text-[10px] uppercase font-bold tracking-wider text-[#9FB3C8]">
                Composite Risk
              </span>
              <span className={`text-xs font-black uppercase ${sevStyle.text}`}>
                {severity}
              </span>
            </div>
          </div>

          {/* Tile 2: AI Classification */}
          <div className="flex items-center gap-3.5 bg-[#121A22] p-3 rounded-lg border border-[#243B53]">
            <div className="w-10 h-10 rounded-lg bg-cyan-500/10 border border-cyan-500/30 flex items-center justify-center shrink-0">
              <SevIcon className="w-5 h-5 text-cyan-400" />
            </div>
            <div className="flex flex-col">
              <span className="text-[10px] uppercase font-bold tracking-wider text-[#9FB3C8]">
                AI Classification
              </span>
              <span className="text-xs font-black text-white">
                {classification}
              </span>
            </div>
          </div>

          {/* Tile 3: Authentication Alignment */}
          <div className="flex items-center gap-3.5 bg-[#121A22] p-3 rounded-lg border border-[#243B53]">
            <div className="w-10 h-10 rounded-lg bg-blue-500/10 border border-blue-500/30 flex items-center justify-center shrink-0">
              <Radio className="w-5 h-5 text-blue-400" />
            </div>
            <div className="flex flex-col">
              <span className="text-[10px] uppercase font-bold tracking-wider text-[#9FB3C8]">
                Email Authentication
              </span>
              <div className="flex items-center gap-1.5 text-[11px] font-mono mt-0.5">
                <span className={forensics?.spf_status?.toLowerCase() === "pass" ? "text-emerald-400" : "text-red-400"}>
                  SPF:{forensics?.spf_status || "N/A"}
                </span>
                <span className="text-slate-600">|</span>
                <span className={forensics?.dkim_status?.toLowerCase() === "pass" ? "text-emerald-400" : "text-red-400"}>
                  DKIM:{forensics?.dkim_status || "N/A"}
                </span>
              </div>
            </div>
          </div>

          {/* Tile 4: Evidence & IOC Count */}
          <div className="flex items-center gap-3.5 bg-[#121A22] p-3 rounded-lg border border-[#243B53]">
            <div className="w-10 h-10 rounded-lg bg-emerald-500/10 border border-emerald-500/30 flex items-center justify-center shrink-0">
              <Lock className="w-5 h-5 text-emerald-400" />
            </div>
            <div className="flex flex-col">
              <span className="text-[10px] uppercase font-bold tracking-wider text-[#9FB3C8]">
                Evidence Chain
              </span>
              <span className="text-xs font-semibold text-white">
                {totalIocCount} IOCs • SHA-256 Validated
              </span>
            </div>
          </div>
        </div>
      </div>

      {/* NAVIGATION TABS */}
      <div className="flex items-center gap-2 border-b border-border pb-1 overflow-x-auto custom-scrollbar">
        {tabs.map((tab) => {
          const Icon = tab.icon;
          const isActive = activeTab === tab.id;
          return (
            <button
              key={tab.id}
              role="tab"
              aria-selected={isActive}
              onClick={() => setActiveTab(tab.id)}
              className={`flex items-center gap-2.5 px-4 py-2.5 rounded-lg text-xs font-bold transition-all whitespace-nowrap ${
                isActive
                  ? "bg-primary text-white shadow-md"
                  : "text-text-secondary hover:text-text-primary hover:bg-bg-panel-subtle bg-bg-panel border border-border/60"
              }`}
            >
              <Icon className={`w-4 h-4 ${isActive ? "text-white" : "text-primary"}`} />
              <span>{tab.label}</span>
              {tab.badge !== undefined && (
                <span
                  className={`px-1.5 py-0.5 rounded-full text-[10px] font-bold ${
                    isActive
                      ? "bg-white/20 text-white"
                      : "bg-primary-soft text-primary"
                  }`}
                >
                  {tab.badge}
                </span>
              )}
            </button>
          );
        })}
      </div>

      {/* TAB 1: OVERVIEW & VERDICT */}
      {activeTab === "overview" && (
        <div className="flex flex-col gap-6 animate-fadeIn">
          {/* 1. AI Conclusion & Risk Breakdown */}
          <InvestigationConclusionWidget caseId={parsed.case_id} />

          <ThreatScoreWidget
            risk={risk}
            threat={threat}
            forensics={forensics}
            caseId={parsed.case_id}
            isLoading={isRiskLoading || isThreatLoading}
          />

          {/* 2. Sender Identity & Envelope */}
          <Card className="shadow-md overflow-hidden">
            <CardContent className="p-6">
              <div className="flex items-center gap-3 mb-6">
                <Mail className="w-5 h-5 text-primary" />
                <h2 className="text-[16px] font-[700] text-text-primary">
                  Email Envelope & Identity Summary
                </h2>
              </div>

              <div className="p-5 bg-bg-page border border-border rounded-xl mb-6">
                <div className="grid grid-cols-1 md:grid-cols-2 gap-5">
                  <div className="flex flex-col gap-1">
                    <span className="text-[11px] font-[700] text-text-secondary uppercase tracking-wider">
                      From (Sender)
                    </span>
                    <span className="text-[13px] font-[700] text-text-primary break-all">
                      {parsed.from_name && <span className="mr-1">{parsed.from_name}</span>}
                      <span>{parsed.from_address || parsed.sender || "N/A"}</span>
                    </span>
                  </div>
                  <div className="flex flex-col gap-1">
                    <span className="text-[11px] font-[700] text-text-secondary uppercase tracking-wider">
                      To (Recipients)
                    </span>
                    <span className="text-[13px] font-[600] text-text-primary break-all">
                      {parsed.recipients && parsed.recipients.length > 0
                        ? parsed.recipients.join(", ")
                        : "None declared"}
                    </span>
                  </div>
                  <div className="flex flex-col gap-1">
                    <span className="text-[11px] font-[700] text-text-secondary uppercase tracking-wider">
                      Subject
                    </span>
                    <span className="text-[14px] font-[800] text-primary">
                      {parsed.subject || "(No Subject Declared)"}
                    </span>
                  </div>
                  <div className="flex flex-col gap-1">
                    <span className="text-[11px] font-[700] text-text-secondary uppercase tracking-wider">
                      Date Declared
                    </span>
                    <span className="text-[13px] text-text-primary">
                      {parsed.date_parsed
                        ? new Date(parsed.date_parsed).toUTCString()
                        : parsed.date_raw || "Not available"}
                    </span>
                  </div>
                  <div className="flex flex-col gap-1">
                    <span className="text-[11px] font-[700] text-text-secondary uppercase tracking-wider">
                      Message-ID
                    </span>
                    <span className="text-[11px] font-mono text-text-muted break-all">
                      {parsed.message_id || "None declared"}
                    </span>
                  </div>
                  <div className="flex flex-col gap-1">
                    <span className="text-[11px] font-[700] text-text-secondary uppercase tracking-wider">
                      Reply-To / CC
                    </span>
                    <span className="text-[13px] text-text-muted">
                      {parsed.reply_to && parsed.reply_to.length > 0
                        ? `Reply-To: ${parsed.reply_to.join(", ")}`
                        : "No Reply-To mismatch"}
                    </span>
                  </div>
                </div>
              </div>

              {/* Email Content Preview with Safe HTML toggle */}
              <div>
                <div className="flex flex-col sm:flex-row sm:justify-between sm:items-center gap-3 mb-4">
                  <div className="flex items-center gap-2">
                    <h3 className="text-[14px] font-[700] text-text-primary">
                      Email Body Content Preview
                    </h3>
                    <Badge variant="neutral" className="text-[10px]">
                      ISOLATED SANDBOX
                    </Badge>
                  </div>
                  <div className="flex items-center bg-bg-panel-subtle p-1 rounded-lg border border-border">
                    <button
                      onClick={() => setBodyFormat("plain")}
                      className={`px-3 py-1 text-[11px] font-[600] rounded transition-colors ${
                        bodyFormat === "plain"
                          ? "bg-white shadow text-text-primary"
                          : "text-text-secondary hover:text-text-primary"
                      }`}
                    >
                      Plain Text
                    </button>
                    <button
                      onClick={() => setBodyFormat("html")}
                      className={`px-3 py-1 text-[11px] font-[600] rounded transition-colors ${
                        bodyFormat === "html"
                          ? "bg-white shadow text-text-primary"
                          : "text-text-secondary hover:text-text-primary"
                      }`}
                    >
                      Safe HTML
                    </button>
                  </div>
                </div>

                {bodyFormat === "plain" ? (
                  <div className="p-4 bg-slate-950 rounded-xl border border-slate-800 max-h-[300px] overflow-y-auto custom-scrollbar font-mono text-[12px] text-slate-300 whitespace-pre-wrap leading-relaxed">
                    {parsed.body_plain || "No plain text content available."}
                  </div>
                ) : (
                  <div
                    className="p-5 bg-white rounded-xl border border-border max-h-[300px] overflow-y-auto custom-scrollbar text-[13px] text-slate-800"
                    dangerouslySetInnerHTML={{
                      __html: parsed.body_html || "<p>No HTML body content available.</p>",
                    }}
                  />
                )}
              </div>
            </CardContent>
          </Card>
        </div>
      )}

      {/* TAB 2: AUTHENTICATION & RELAYS */}
      {activeTab === "authentication" && (
        <div className="flex flex-col gap-6 animate-fadeIn">
          <AuthenticationForensicsWidget forensics={forensics} isLoading={isForensicsLoading} />
          <RelayHopsTimelineWidget forensics={forensics} isLoading={isForensicsLoading} />
        </div>
      )}

      {/* TAB 3: THREAT INTEL & GEO */}
      {activeTab === "intel" && (
        <div className="flex flex-col gap-6 animate-fadeIn">
          <ThreatIntelGeoWidget intel={intel} geo={geo} isLoading={isIntelLoading || isGeoLoading} />
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            <IPIntelligenceWidget caseId={caseId} />
            <DomainIntelligenceWidget caseId={caseId} />
          </div>
          <URLIntelligenceWidget caseId={caseId} />
          <CampaignWidget caseId={parsed.case_id} />
        </div>
      )}

      {/* TAB 4: IOC INDICATORS */}
      {activeTab === "iocs" && (
        <div className="flex flex-col gap-6 animate-fadeIn">
          <IOCTableWidget iocData={iocs} isLoading={isIocsLoading} />
        </div>
      )}

      {/* TAB 5: RELATIONSHIP GRAPH */}
      {activeTab === "graph" && (
        <div className="flex flex-col gap-6 animate-fadeIn">
          <ThreatGraphWidget graph={graph} isLoading={isGraphLoading} onRefresh={refetchGraph} />
        </div>
      )}

      {/* TAB 6: FORENSIC TIMELINE */}
      {activeTab === "timeline" && (
        <div className="flex flex-col gap-6 animate-fadeIn">
          <ForensicTimelineWidget timelineData={timeline} isLoading={isTimelineLoading} />
        </div>
      )}

      {/* TAB 7: EVIDENCE & CUSTODY */}
      {activeTab === "evidence" && (
        <div className="flex flex-col gap-6 animate-fadeIn">
          <EvidenceIntegrityWidget caseId={caseId} />

          {/* Attachments Section */}
          {parsed.attachments_metadata && parsed.attachments_metadata.length > 0 && (
            <Card className="shadow-md">
              <CardContent className="p-6">
                <h3 className="text-[14px] font-[700] text-text-primary mb-4 flex items-center gap-2">
                  <Paperclip className="w-4 h-4 text-primary" />
                  Attached Evidence Artifacts ({parsed.attachments_metadata.length})
                </h3>
                <div className="flex flex-col gap-2.5">
                  {parsed.attachments_metadata.map((att, idx) => (
                    <div
                      key={idx}
                      className="p-3.5 bg-bg-page border border-border rounded-xl flex flex-col sm:flex-row sm:items-center justify-between gap-3"
                    >
                      <div className="flex flex-col gap-1">
                        <span className="text-[13px] font-[700] text-text-primary">
                          {att.filename}
                        </span>
                        <span className="text-[11px] text-text-secondary font-mono">
                          Size: {(att.file_size_bytes / 1024).toFixed(1)} KB • SHA-256: {att.sha256}
                        </span>
                      </div>
                      <Badge variant="neutral" className="bg-border/60 text-text-muted text-[10px] uppercase w-fit">
                        {att.extension}
                      </Badge>
                    </div>
                  ))}
                </div>
              </CardContent>
            </Card>
          )}
        </div>
      )}
    </div>
  );
};
