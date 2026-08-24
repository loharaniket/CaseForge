"use client";

import React, { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import {
  Box,
  Card,
  CardContent,
  Chip,
  Grid,
  Stack,
  Tab,
  Tabs,
  Typography,
  Alert,
} from "@mui/material";
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
import { ThreatGraphWidget } from "./ThreatGraphWidget";

interface InvestigationDashboardProps {
  caseId: string;
}

export const InvestigationDashboard: React.FC<InvestigationDashboardProps> = ({ caseId }) => {
  const [activeTab, setActiveTab] = useState<number>(0);
  const [bodyFormat, setBodyFormat] = useState<"plain" | "html">("plain");
  const [isDownloadingPdf, setIsDownloadingPdf] = useState(false);
  const [isVerifyingEvidence, setIsVerifyingEvidence] = useState(false);
  const [verifyNotice, setVerifyNotice] = useState<string | null>(null);

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
    enabled: !!caseId,
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
    enabled: !!caseId,
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
    enabled: !!caseId,
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
    enabled: !!caseId && (activeTab === 0 || activeTab === 1),
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
    enabled: !!caseId && (activeTab === 0 || activeTab === 3),
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
    enabled: !!caseId && (activeTab === 0 || activeTab === 2),
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
    enabled: !!caseId && (activeTab === 0 || activeTab === 2),
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
    enabled: !!caseId && (activeTab === 0 || activeTab === 4),
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
    enabled: !!caseId && (activeTab === 0 || activeTab === 5),
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
    enabled: !!caseId && (activeTab === 0 || activeTab === 6),
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

  const isInitialLoading = isParsedLoading && !parsed;

  if (isInitialLoading) {
    return (
      <Card sx={{ bgcolor: "background.paper", border: "1px solid #D9E0E7", p: 6, textAlign: "center" }}>
        <Stack spacing={2} alignItems="center">
          <RefreshCw className="w-8 h-8 text-[#1F4E79] animate-spin" />
          <Typography variant="h6" color="text.primary">
            Loading Investigation Telemetry...
          </Typography>
          <Typography variant="body2" color="text.secondary" fontFamily="monospace">
            Aggregating case evidence, header forensics, threat intelligence, and risk assessment
          </Typography>
        </Stack>
      </Card>
    );
  }

  if (isParsedError || !parsed) {
    return (
      <Card sx={{ bgcolor: "background.paper", border: "1px solid #D9E0E7", p: 4 }}>
        <Typography variant="h6" color="#C53030" mb={1}>
          Investigation Loading Notice
        </Typography>
        <Alert severity="error" sx={{ bgcolor: "rgba(239, 68, 68, 0.1)", color: "#C53030", border: "1px solid #dc2626" }}>
          Email parsing failed: {parsedError?.message || "Failed to load case investigation evidence."}
        </Alert>
        <Box mt={2} textAlign="center">
          <button onClick={handleRefreshAll} className="action-btn">
            <RefreshCw className="w-4 h-4" />
            <span>Retry Investigation Analysis</span>
          </button>
        </Box>
      </Card>
    );
  }

  return (
    <Box sx={{ display: "flex", flexDirection: "column", gap: 3 }}>
      {/* Investigation Top Header Bar */}
      <Card
        sx={{
          bgcolor: "background.paper",
          border: "1px solid #D9E0E7",
          borderRadius: 2,
          boxShadow: "0 4px 12px rgba(0, 0, 0, 0.4)",
        }}
      >
        <CardContent sx={{ p: { xs: 2, sm: 3 } }}>
          <Stack
            direction={{ xs: "column", md: "row" }}
            justifyContent="space-between"
            alignItems={{ xs: "flex-start", md: "center" }}
            spacing={2}
          >
            <div>
              <Stack direction="row" spacing={1.5} alignItems="center">
                <Shield className="w-6 h-6 text-[#1F4E79]" />
                <Typography variant="h5" fontWeight={800} color="text.primary" letterSpacing="-0.01em">
                  Case Investigation Console
                </Typography>
                <Chip
                  label="ACTIVE CASE"
                  size="small"
                  sx={{
                    bgcolor: "#EAF2F8",
                    color: "#1F4E79",
                    fontWeight: 700,
                    fontSize: "0.7rem",
                    border: "1px solid #1F4E79",
                  }}
                />
              </Stack>
              <Typography variant="caption" sx={{ color: "text.secondary", fontFamily: "monospace", mt: 0.5, display: "block" }}>
                Case ID: {parsed.case_id} • Ingested: {new Date(parsed.created_at).toLocaleString()}
              </Typography>
            </div>

            {/* Refresh Header Control */}
            <Stack direction="row" spacing={1.5} alignItems="center">
              <button
                onClick={handleRefreshAll}
                className="refresh-button"
                title="Refresh all investigation telemetry"
                aria-label="Refresh telemetry"
              >
                <RefreshCw className="w-4 h-4 text-gray-600" />
              </button>
            </Stack>
          </Stack>

          {verifyNotice && (
            <Box mt={2}>
              <Alert
                severity={verifyNotice.startsWith("✓") ? "success" : "warning"}
                onClose={() => setVerifyNotice(null)}
                sx={{
                  bgcolor: verifyNotice.startsWith("✓") ? "#E8F5EF" : "#FFF7E6",
                  color: verifyNotice.startsWith("✓") ? "#237A57" : "#B7791F",
                  border: `1px solid ${verifyNotice.startsWith("✓") ? "#18533B" : "#975A16"}`,
                }}
              >
                {verifyNotice}
              </Alert>
            </Box>
          )}

          {/* Section Jump Tabs */}
          <Box sx={{ mt: 3, borderTop: "1px solid #D9E0E7", pt: 1 }}>
            <Tabs
              value={activeTab}
              onChange={(_, val) => setActiveTab(val)}
              variant="scrollable"
              scrollButtons="auto"
              sx={{
                "& .MuiTab-root": {
                  color: "text.secondary",
                  fontWeight: 600,
                  fontSize: "0.8rem",
                  textTransform: "none",
                  minHeight: 40,
                  py: 1,
                  "&.Mui-selected": {
                    color: "#1F4E79",
                  },
                },
                "& .MuiTabs-indicator": {
                  bgcolor: "#1F4E79",
                  height: 2,
                },
              }}
            >
              <Tab label="Full Investigation (Continuous View)" />
              <Tab label="Authentication & Relays" />
              <Tab label="Threat Intel & Geo" />
              <Tab label="IOC Indicators" />
              <Tab label="Forensic Timeline" />
              <Tab label="Evidence & Custody Integrity" />
              <Tab label="Threat Graph" />
            </Tabs>
          </Box>
        </CardContent>
      </Card>

      {/* ========================================================================= */}
      {/* CONTINUOUS VERTICAL INVESTIGATION WORKFLOW (SECTIONS A THROUGH L)          */}
      {/* ========================================================================= */}

      {/* SECTION A: VERDICT & SECTION B: WHY? */}
      {(activeTab === 0 || activeTab === 1) && (
        <section id="section-verdict-why">
          <ThreatScoreWidget
            risk={risk}
            threat={threat}
            forensics={forensics}
            caseId={parsed.case_id}
            isLoading={isRiskLoading || isThreatLoading}
          />
        </section>
      )}

      {/* SECTION C: EMAIL SUMMARY & ENVELOPE */}
      {(activeTab === 0) && (
        <section id="section-email-summary">
          <Card
            sx={{
              bgcolor: "background.paper",
              border: "1px solid #D9E0E7",
              borderRadius: 2,
              boxShadow: "0 4px 12px rgba(0, 0, 0, 0.4)",
              overflow: "hidden",
            }}
          >
            <CardContent sx={{ p: 3 }}>
              <Stack direction="row" alignItems="center" spacing={1.5} mb={2.5}>
                <Mail className="w-5 h-5 text-[#1F4E79]" />
                <Typography variant="h6" fontWeight={700} color="text.primary">
                  Email Envelope & Identity Summary
                </Typography>
              </Stack>

              {/* 2-Column Info Grid */}
              <Box
                sx={{
                  p: 2.5,
                  borderRadius: 1.5,
                  bgcolor: "#F5F7FA",
                  border: "1px solid #D9E0E7",
                  mb: 3,
                }}
              >
                <Grid container spacing={2}>
                  <Grid item xs={12} md={6}>
                    <Typography variant="caption" sx={{ color: "text.secondary", textTransform: "uppercase", fontWeight: 600 }}>
                      From (Sender)
                    </Typography>
                    <Typography variant="body2" fontWeight={600} color="text.primary" sx={{ mt: 0.5, wordBreak: "break-all" }}>
                      {parsed.from_name ? `${parsed.from_name} <${parsed.from_address || parsed.sender}>` : parsed.sender || "N/A"}
                    </Typography>
                  </Grid>

                  <Grid item xs={12} md={6}>
                    <Typography variant="caption" sx={{ color: "text.secondary", textTransform: "uppercase", fontWeight: 600 }}>
                      To (Recipients)
                    </Typography>
                    <Typography variant="body2" fontWeight={600} color="text.primary" sx={{ mt: 0.5, wordBreak: "break-all" }}>
                      {parsed.recipients && parsed.recipients.length > 0 ? parsed.recipients.join(", ") : "None declared"}
                    </Typography>
                  </Grid>

                  <Grid item xs={12} md={6}>
                    <Typography variant="caption" sx={{ color: "text.secondary", textTransform: "uppercase", fontWeight: 600 }}>
                      Subject
                    </Typography>
                    <Typography variant="body1" fontWeight={700} color="#1F4E79" sx={{ mt: 0.5 }}>
                      {parsed.subject || "(No Subject Declared)"}
                    </Typography>
                  </Grid>

                  <Grid item xs={12} md={6}>
                    <Typography variant="caption" sx={{ color: "text.secondary", textTransform: "uppercase", fontWeight: 600 }}>
                      Date Declared
                    </Typography>
                    <Typography variant="body2" color="text.primary" sx={{ mt: 0.5 }}>
                      {parsed.date_parsed ? new Date(parsed.date_parsed).toUTCString() : parsed.date_raw || "Not available"}
                    </Typography>
                  </Grid>

                  <Grid item xs={12} md={6}>
                    <Typography variant="caption" sx={{ color: "text.secondary", textTransform: "uppercase", fontWeight: 600 }}>
                      Message-ID
                    </Typography>
                    <Typography variant="caption" fontFamily="monospace" color="#cbd5e1" sx={{ mt: 0.5, display: "block", wordBreak: "break-all" }}>
                      {parsed.message_id || "None declared"}
                    </Typography>
                  </Grid>

                  <Grid item xs={12} md={6}>
                    <Typography variant="caption" sx={{ color: "text.secondary", textTransform: "uppercase", fontWeight: 600 }}>
                      Reply-To / CC
                    </Typography>
                    <Typography variant="body2" color="#cbd5e1" sx={{ mt: 0.5 }}>
                      {parsed.reply_to && parsed.reply_to.length > 0 ? `Reply-To: ${parsed.reply_to.join(", ")}` : "No Reply-To mismatch"}
                    </Typography>
                  </Grid>
                </Grid>
              </Box>

              {/* Body Content Preview */}
              <Box>
                <Stack direction="row" justifyContent="space-between" alignItems="center" mb={1.5}>
                  <Typography variant="subtitle2" fontWeight={700} color="text.primary">
                    Email Body Content Preview
                  </Typography>
                  <Stack direction="row" spacing={1}>
                    <button
                      onClick={() => setBodyFormat("plain")}
                      className={`format-toggle-btn ${bodyFormat === "plain" ? "active" : ""}`}
                    >
                      Plain Text
                    </button>
                    <button
                      onClick={() => setBodyFormat("html")}
                      className={`format-toggle-btn ${bodyFormat === "html" ? "active" : ""}`}
                    >
                      Safe HTML
                    </button>
                  </Stack>
                </Stack>

                {bodyFormat === "plain" ? (
                  <Box
                    sx={{
                      p: 2,
                      borderRadius: 1.5,
                      bgcolor: "rgba(15, 23, 42, 0.9)",
                      border: "1px solid #D9E0E7",
                      maxHeight: 220,
                      overflowY: "auto",
                      fontFamily: "monospace",
                      fontSize: "0.82rem",
                      color: "text.primary",
                      whiteSpace: "pre-wrap",
                    }}
                  >
                    {parsed.body_plain || "No plain text content available."}
                  </Box>
                ) : (
                  <Box
                    sx={{
                      p: 2,
                      borderRadius: 1.5,
                      bgcolor: "#ffffff",
                      color: "#F5F7FA",
                      maxHeight: 220,
                      overflowY: "auto",
                      fontSize: "0.85rem",
                    }}
                    dangerouslySetInnerHTML={{
                      __html: parsed.body_html || "<p>No HTML body content available.</p>",
                    }}
                  />
                )}
              </Box>

              {/* Attachments Section */}
              {parsed.attachments_metadata && parsed.attachments_metadata.length > 0 && (
                <Box mt={3}>
                  <Typography variant="subtitle2" fontWeight={700} color="text.primary" mb={1.5} display="flex" alignItems="center" gap={1}>
                    <Paperclip size={16} /> Attached Evidence Files ({parsed.attachments_metadata.length})
                  </Typography>
                  <Stack spacing={1}>
                    {parsed.attachments_metadata.map((att, idx) => (
                      <Box
                        key={idx}
                        sx={{
                          p: 1.5,
                          borderRadius: 1.5,
                          bgcolor: "rgba(30, 41, 59, 0.4)",
                          border: "1px solid #D9E0E7",
                          display: "flex",
                          justifyContent: "space-between",
                          alignItems: "center",
                        }}
                      >
                        <div>
                          <Typography variant="body2" fontWeight={600} color="text.primary">
                            {att.filename}
                          </Typography>
                          <Typography variant="caption" sx={{ color: "text.secondary", fontFamily: "monospace" }}>
                            Size: {(att.file_size_bytes / 1024).toFixed(1)} KB • SHA-256: {att.sha256}
                          </Typography>
                        </div>
                        <Chip label={att.extension.toUpperCase()} size="small" sx={{ bgcolor: "#D9E0E7", color: "#cbd5e1" }} />
                      </Box>
                    ))}
                  </Stack>
                </Box>
              )}
            </CardContent>
          </Card>
        </section>
      )}

      {/* SECTION D: AUTHENTICATION & SECTION E: HEADER FORENSICS */}
      {(activeTab === 0 || activeTab === 1) && (
        <section id="section-auth-relays">
          <Stack spacing={3}>
            <AuthenticationForensicsWidget forensics={forensics} isLoading={isForensicsLoading} />
            <RelayHopsTimelineWidget forensics={forensics} isLoading={isForensicsLoading} />
          </Stack>
        </section>
      )}

      {/* SECTION F: THREAT INTEL & SECTION G: GEO INFRASTRUCTURE */}
      {(activeTab === 0 || activeTab === 2) && (
        <section id="section-threat-intel-geo">
          <ThreatIntelGeoWidget
            intel={intel}
            geo={geo}
            isLoading={isIntelLoading || isGeoLoading}
          />
        </section>
      )}

      {/* SECTION H: INDICATORS OF COMPROMISE (IOCS) */}
      {(activeTab === 0 || activeTab === 3) && (
        <section id="section-iocs">
          <IOCTableWidget iocData={iocs} isLoading={isIocsLoading} />
        </section>
      )}

      {/* SECTION I: FORENSIC TIMELINE */}
      {(activeTab === 0 || activeTab === 4) && (
        <section id="section-timeline">
          <ForensicTimelineWidget timelineData={timeline} isLoading={isTimelineLoading} />
        </section>
      )}

      {/* SECTION J: THREAT RELATIONSHIP GRAPH */}
      {(activeTab === 0 || activeTab === 6) && (
        <section id="section-graph">
          <ThreatGraphWidget graph={graph} isLoading={isGraphLoading} onRefresh={refetchGraph} />
        </section>
      )}

      {/* SECTION K: EVIDENCE INTEGRITY */}
      {(activeTab === 0 || activeTab === 5) && (
        <section id="section-evidence">
          <EvidenceIntegrityWidget caseId={caseId} />
        </section>
      )}

      {/* SECTION L: BOTTOM ACTIONS TOOLBAR */}
      <Card
        sx={{
          bgcolor: "background.paper",
          border: "1px solid #D9E0E7",
          borderRadius: 2,
          p: 3,
        }}
      >
        <Stack
          direction={{ xs: "column", sm: "row" }}
          justifyContent="space-between"
          alignItems="center"
          spacing={2}
        >
          <div>
            <Typography variant="subtitle2" fontWeight={700} color="text.primary">
              Investigation Actions & Export
            </Typography>
            <Typography variant="caption" color="text.secondary">
              Generate tamper-evident PDF reports, verify cryptographic hash records, or re-run analysis.
            </Typography>
          </div>

          <Stack direction="row" spacing={1.5} flexWrap="wrap">
            <button
              onClick={handleDownloadPdf}
              disabled={isDownloadingPdf}
              className="action-btn"
            >
              <FileDown className="w-4 h-4" />
              <span>{isDownloadingPdf ? "Compiling PDF..." : "Export PDF Report"}</span>
            </button>

            <button
              onClick={() => {
                setActiveTab(6);
                const el = document.getElementById("section-graph");
                if (el) el.scrollIntoView({ behavior: "smooth" });
              }}
              className="action-btn"
            >
              <Share2 className="w-4 h-4" />
              <span>View Relationship Graph</span>
            </button>

            <button
              onClick={handleVerifyEvidence}
              disabled={isVerifyingEvidence}
              className="action-btn"
            >
              <FileCheck2 className="w-4 h-4" />
              <span>Verify Evidence Integrity</span>
            </button>
          </Stack>
        </Stack>
      </Card>
    </Box>
  );
};
