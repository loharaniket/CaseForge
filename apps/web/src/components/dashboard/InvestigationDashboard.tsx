"use client";

import React, { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import {
  Box,
  Button,
  Card,
  CardContent,
  Chip,
  Divider,
  Grid,
  IconButton,
  LinearProgress,
  Stack,
  Tab,
  Tabs,
  Typography,
  Alert,
  Tooltip,
} from "@mui/material";
import {
  FileSearch,
  Shield,
  Radio,
  Fingerprint,
  FileText,
  RefreshCw,
  AlertTriangle,
  Mail,
  User,
  Calendar,
  Key,
  Globe,
  Paperclip,
  Copy,
  Check,
  Clock,
  FileDown,
} from "lucide-react";
import {
  downloadInvestigationReport,
  getCaseGeoInfrastructure,
  getCaseIOCs,
  getCaseRisk,
  getCaseThreatIntel,
  getCaseTimeline,
  getHeaderForensics,
  getParsedEmail,
  getThreatAnalysis,
} from "@/lib/api/email";
import { ThreatScoreWidget } from "./ThreatScoreWidget";
import { AuthenticationForensicsWidget } from "./AuthenticationForensicsWidget";
import { RelayHopsTimelineWidget } from "./RelayHopsTimelineWidget";
import { ThreatIntelGeoWidget } from "./ThreatIntelGeoWidget";
import { IOCTableWidget } from "./IOCTableWidget";
import { ForensicTimelineWidget } from "./ForensicTimelineWidget";
import {
  CaseGeoInfrastructureResponse,
  CaseIOCListResponse,
  CaseThreatIntelResponse,
  ForensicTimelineResponse,
  HeaderForensicsResponse,
  ParsedEmail,
  RiskAssessmentResponse,
  ThreatAssessmentResponse,
} from "@/types";

interface InvestigationDashboardProps {
  caseId: string;
}

export const InvestigationDashboard: React.FC<InvestigationDashboardProps> = ({ caseId }) => {
  const [activeTab, setActiveTab] = useState<number>(0);
  const [bodyFormat, setBodyFormat] = useState<"plain" | "html">("plain");
  const [copiedText, setCopiedText] = useState<string | null>(null);
  const [isDownloadingReport, setIsDownloadingReport] = useState<boolean>(false);

  const handleDownloadReport = async () => {
    try {
      setIsDownloadingReport(true);
      await downloadInvestigationReport(caseId);
    } catch (err) {
      console.error("Failed to download investigation PDF report:", err);
    } finally {
      setIsDownloadingReport(false);
    }
  };

  // Orchestrate parallel data fetching for the case
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
  });

  const {
    data: risk,
    isLoading: isRiskLoading,
    refetch: refetchRisk,
  } = useQuery<RiskAssessmentResponse, Error>({
    queryKey: ["case_risk", caseId],
    queryFn: () => getCaseRisk(caseId),
    enabled: !!caseId,
  });

  const {
    data: threat,
    isLoading: isThreatLoading,
    refetch: refetchThreat,
  } = useQuery<ThreatAssessmentResponse, Error>({
    queryKey: ["case_threat", caseId],
    queryFn: () => getThreatAnalysis(caseId),
    enabled: !!caseId,
  });

  const {
    data: forensics,
    isLoading: isForensicsLoading,
    refetch: refetchForensics,
  } = useQuery<HeaderForensicsResponse, Error>({
    queryKey: ["case_forensics", caseId],
    queryFn: () => getHeaderForensics(caseId),
    enabled: !!caseId,
  });

  const {
    data: iocData,
    isLoading: isIocLoading,
    refetch: refetchIocs,
  } = useQuery<CaseIOCListResponse, Error>({
    queryKey: ["case_iocs", caseId],
    queryFn: () => getCaseIOCs(caseId),
    enabled: !!caseId,
  });

  const {
    data: intel,
    isLoading: isIntelLoading,
    refetch: refetchIntel,
  } = useQuery<CaseThreatIntelResponse, Error>({
    queryKey: ["case_threat_intel", caseId],
    queryFn: () => getCaseThreatIntel(caseId),
    enabled: !!caseId,
  });

  const {
    data: geo,
    isLoading: isGeoLoading,
    refetch: refetchGeo,
  } = useQuery<CaseGeoInfrastructureResponse, Error>({
    queryKey: ["case_geo", caseId],
    queryFn: () => getCaseGeoInfrastructure(caseId),
    enabled: !!caseId,
  });

  const {
    data: timeline,
    isLoading: isTimelineLoading,
    refetch: refetchTimeline,
  } = useQuery<ForensicTimelineResponse, Error>({
    queryKey: ["case_timeline", caseId],
    queryFn: () => getCaseTimeline(caseId),
    enabled: !!caseId,
  });

  const handleRefetchAll = () => {
    refetchParsed();
    refetchRisk();
    refetchThreat();
    refetchForensics();
    refetchIocs();
    refetchIntel();
    refetchGeo();
    refetchTimeline();
  };

  const handleCopy = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopiedText(text);
    setTimeout(() => setCopiedText(null), 2000);
  };

  const isAnyLoading =
    isParsedLoading ||
    isRiskLoading ||
    isThreatLoading ||
    isForensicsLoading ||
    isIocLoading ||
    isIntelLoading ||
    isGeoLoading ||
    isTimelineLoading;

  if (isParsedLoading && !parsed) {
    return (
      <Card sx={{ bgcolor: "background.paper", border: "1px solid", borderColor: "divider", p: 4 }}>
        <Stack spacing={2} alignItems="center" textAlign="center">
          <RefreshCw className="w-8 h-8 text-cyan-400 animate-spin" />
          <Typography variant="h6" fontWeight={600} color="text.primary">
            Loading Investigation Telemetry...
          </Typography>
          <Typography variant="caption" color="text.secondary">
            Synchronizing risk assessment, forensic relay graphs, threat intelligence, and IOC extractions.
          </Typography>
          <LinearProgress sx={{ width: "100%", maxWidth: 400, borderRadius: 2 }} />
        </Stack>
      </Card>
    );
  }

  if (isParsedError && !parsed) {
    return (
      <Card sx={{ bgcolor: "background.paper", border: "1px solid", borderColor: "error.main", p: 3 }}>
        <Stack spacing={2} alignItems="center" textAlign="center">
          <AlertTriangle className="w-8 h-8 text-amber-400" />
          <Typography variant="h6" fontWeight={600} color="text.primary">
            Investigation Loading Notice
          </Typography>
          <Typography variant="body2" color="text.secondary">
            {parsedError?.message || "Failed to load investigation telemetry for case ID: " + caseId}
          </Typography>
          <IconButton onClick={handleRefetchAll} color="primary" sx={{ border: "1px solid", borderColor: "divider" }}>
            <RefreshCw size={18} />
          </IconButton>
        </Stack>
      </Card>
    );
  }

  return (
    <Stack spacing={3}>
      {/* 1. Master Case Header Card */}
      <Card
        sx={{
          bgcolor: "background.paper",
          border: "1px solid",
          borderColor: "divider",
          borderRadius: 2,
          boxShadow: 2,
        }}
      >
        <CardContent sx={{ p: 3 }}>
          <Stack direction={{ xs: "column", md: "row" }} justifyContent="space-between" alignItems={{ xs: "flex-start", md: "center" }} spacing={2} mb={2}>
            <Stack direction="row" alignItems="center" spacing={1.5}>
              <FileSearch className="w-6 h-6 text-cyan-400" />
              <Box>
                <Typography variant="h5" fontWeight={700} color="text.primary">
                  Case Investigation Console
                </Typography>
                <Typography variant="caption" color="text.secondary" sx={{ fontFamily: "monospace" }}>
                  Case ID: {caseId}
                </Typography>
              </Box>
            </Stack>

            <Stack direction="row" spacing={1} alignItems="center">
              <Chip label="ACTIVE INVESTIGATION" size="small" color="primary" sx={{ fontWeight: 700, fontSize: "0.75rem" }} />
              <Button
                variant="outlined"
                size="small"
                onClick={handleDownloadReport}
                disabled={isDownloadingReport}
                startIcon={<FileDown size={14} className={isDownloadingReport ? "animate-bounce" : ""} />}
                sx={{
                  textTransform: "none",
                  fontWeight: 600,
                  fontSize: "0.75rem",
                  borderColor: "rgba(6, 182, 212, 0.4)",
                  color: "#06b6d4",
                  "&:hover": { borderColor: "#06b6d4", bgcolor: "rgba(6, 182, 212, 0.1)" },
                }}
              >
                {isDownloadingReport ? "Exporting PDF..." : "Export PDF Report"}
              </Button>
              <Tooltip title="Refresh investigation telemetry">
                <IconButton onClick={handleRefetchAll} size="small" sx={{ border: "1px solid", borderColor: "divider" }}>
                  <RefreshCw size={16} className={isAnyLoading ? "animate-spin text-cyan-400" : ""} />
                </IconButton>
              </Tooltip>
            </Stack>
          </Stack>

          <Divider sx={{ my: 1.5 }} />

          {/* Quick Case Metadata Row */}
          <Grid container spacing={2}>
            <Grid item xs={12} sm={6} md={3}>
              <Typography variant="caption" color="text.secondary" display="flex" alignItems="center" gap={0.5}>
                <Mail size={12} /> Subject
              </Typography>
              <Typography variant="body2" fontWeight={600} color="text.primary" noWrap>
                {parsed?.subject || "(No Subject)"}
              </Typography>
            </Grid>

            <Grid item xs={12} sm={6} md={3}>
              <Typography variant="caption" color="text.secondary" display="flex" alignItems="center" gap={0.5}>
                <User size={12} /> Sender (From)
              </Typography>
              <Typography variant="body2" fontWeight={600} color="cyan.300" noWrap sx={{ fontFamily: "monospace" }}>
                {parsed?.from_address || parsed?.sender || "Unknown"}
              </Typography>
            </Grid>

            <Grid item xs={12} sm={6} md={3}>
              <Typography variant="caption" color="text.secondary" display="flex" alignItems="center" gap={0.5}>
                <Calendar size={12} /> Date Received
              </Typography>
              <Typography variant="body2" color="text.primary" noWrap>
                {parsed?.date_parsed ? new Date(parsed.date_parsed).toUTCString() : parsed?.date_raw || "Unknown"}
              </Typography>
            </Grid>

            <Grid item xs={12} sm={6} md={3}>
              <Typography variant="caption" color="text.secondary" display="flex" alignItems="center" gap={0.5}>
                <Key size={12} /> Evidence SHA-256
              </Typography>
              <Stack direction="row" alignItems="center" spacing={0.5}>
                <Typography variant="caption" color="text.secondary" noWrap sx={{ fontFamily: "monospace", maxWidth: 160 }}>
                  {parsed?.id || caseId}
                </Typography>
                <IconButton size="small" onClick={() => handleCopy(caseId)} sx={{ p: 0.2 }}>
                  {copiedText === caseId ? <Check size={12} color="#10b981" /> : <Copy size={12} color="#9ca3af" />}
                </IconButton>
              </Stack>
            </Grid>
          </Grid>
        </CardContent>
      </Card>

      {/* 2. Top-Level Risk & Threat Widget */}
      <ThreatScoreWidget risk={risk} threat={threat} isLoading={isRiskLoading || isThreatLoading} />

      {/* 3. Section Navigation Tabs */}
      <Box sx={{ borderBottom: 1, borderColor: "divider" }}>
        <Tabs
          value={activeTab}
          onChange={(_, newVal) => setActiveTab(newVal)}
          variant="scrollable"
          scrollButtons="auto"
          sx={{
            "& .MuiTab-root": { textTransform: "none", fontWeight: 600, fontSize: "0.85rem", minHeight: 44 },
          }}
        >
          <Tab value={0} icon={<Shield size={16} />} iconPosition="start" label="Overview & Envelope" />
          <Tab value={1} icon={<Radio size={16} />} iconPosition="start" label="Authentication & Relays" />
          <Tab value={2} icon={<Globe size={16} />} iconPosition="start" label="Threat Intel & Geo" />
          <Tab
            value={3}
            icon={<Fingerprint size={16} />}
            iconPosition="start"
            label={`IOC Indicators (${iocData?.total_count || 0})`}
          />
          <Tab
            value={4}
            icon={<Clock size={16} />}
            iconPosition="start"
            label={`Forensic Timeline (${timeline?.total_events || 0})`}
          />
          <Tab value={5} icon={<FileText size={16} />} iconPosition="start" label="Evidence & Body Preview" />
        </Tabs>
      </Box>

      {/* Tab 0: Overview & Envelope */}
      {activeTab === 0 && (
        <Stack spacing={3}>
          <Grid container spacing={3}>
            {/* Sender & Recipient Details */}
            <Grid item xs={12} md={6}>
              <Card sx={{ bgcolor: "background.paper", border: "1px solid", borderColor: "divider", borderRadius: 2, height: "100%" }}>
                <CardContent sx={{ p: 3 }}>
                  <Typography variant="subtitle1" fontWeight={700} color="text.primary" mb={2}>
                    Envelope & Address Entities
                  </Typography>
                  <Stack spacing={1.5}>
                    <Box>
                      <Typography variant="caption" color="text.secondary">From Display Name</Typography>
                      <Typography variant="body2" fontWeight={600} color="text.primary">{parsed?.from_name || "(None)"}</Typography>
                    </Box>
                    <Box>
                      <Typography variant="caption" color="text.secondary">From Address</Typography>
                      <Typography variant="body2" color="cyan.300" sx={{ fontFamily: "monospace" }}>{parsed?.from_address || parsed?.sender || "None"}</Typography>
                    </Box>
                    <Box>
                      <Typography variant="caption" color="text.secondary">To Recipients ({parsed?.recipients?.length || 0})</Typography>
                      <Typography variant="body2" color="text.primary" sx={{ fontFamily: "monospace" }}>
                        {parsed?.recipients && parsed.recipients.length > 0 ? parsed.recipients.join(", ") : "None specified"}
                      </Typography>
                    </Box>
                    {parsed?.cc && parsed.cc.length > 0 && (
                      <Box>
                        <Typography variant="caption" color="text.secondary">CC Recipients</Typography>
                        <Typography variant="body2" color="text.primary" sx={{ fontFamily: "monospace" }}>{parsed.cc.join(", ")}</Typography>
                      </Box>
                    )}
                    {parsed?.reply_to && parsed.reply_to.length > 0 && (
                      <Box>
                        <Typography variant="caption" color="text.secondary">Reply-To Address</Typography>
                        <Typography variant="body2" color="amber.300" sx={{ fontFamily: "monospace" }}>{parsed.reply_to.join(", ")}</Typography>
                      </Box>
                    )}
                  </Stack>
                </CardContent>
              </Card>
            </Grid>

            {/* Quick Forensics & Geo Summary */}
            <Grid item xs={12} md={6}>
              <Card sx={{ bgcolor: "background.paper", border: "1px solid", borderColor: "divider", borderRadius: 2, height: "100%" }}>
                <CardContent sx={{ p: 3 }}>
                  <Typography variant="subtitle1" fontWeight={700} color="text.primary" mb={2}>
                    Forensic Highlights
                  </Typography>
                  <Stack spacing={1.5}>
                    <Box>
                      <Typography variant="caption" color="text.secondary">Probable Infrastructure Origin</Typography>
                      <Typography variant="body2" fontWeight={600} color="text.primary">
                        {geo?.probable_infrastructure_origin || "Pending / Local Network"}
                      </Typography>
                    </Box>
                    <Box>
                      <Typography variant="caption" color="text.secondary">Candidate Origin IP</Typography>
                      <Typography variant="body2" color="cyan.300" sx={{ fontFamily: "monospace" }}>
                        {forensics?.probable_origin_ip || geo?.candidate_origin_ip || "None identified"}
                      </Typography>
                    </Box>
                    <Box>
                      <Typography variant="caption" color="text.secondary">Authentication Posture</Typography>
                      <Stack direction="row" spacing={1} mt={0.5}>
                        <Chip label={`SPF: ${forensics?.spf_status || "NONE"}`} size="small" variant="outlined" />
                        <Chip label={`DKIM: ${forensics?.dkim_status || "NONE"}`} size="small" variant="outlined" />
                        <Chip label={`DMARC: ${forensics?.dmarc_status || "NONE"}`} size="small" variant="outlined" />
                      </Stack>
                    </Box>
                    <Box>
                      <Typography variant="caption" color="text.secondary">Extracted Indicators</Typography>
                      <Typography variant="body2" fontWeight={600} color="text.primary">
                        {iocData?.total_count || 0} Indicators of Compromise (IOCs) Cataloged
                      </Typography>
                    </Box>
                  </Stack>
                </CardContent>
              </Card>
            </Grid>
          </Grid>
        </Stack>
      )}

      {/* Tab 1: Authentication & Relay Hops */}
      {activeTab === 1 && (
        <Stack spacing={3}>
          <AuthenticationForensicsWidget forensics={forensics} isLoading={isForensicsLoading} />
          <RelayHopsTimelineWidget forensics={forensics} isLoading={isForensicsLoading} />
        </Stack>
      )}

      {/* Tab 2: Threat Intel & Geo */}
      {activeTab === 2 && (
        <ThreatIntelGeoWidget intel={intel} geo={geo} isLoading={isIntelLoading || isGeoLoading} />
      )}

      {/* Tab 3: IOC Indicators */}
      {activeTab === 3 && (
        <IOCTableWidget iocData={iocData} isLoading={isIocLoading} />
      )}

      {/* Tab 4: Forensic Timeline */}
      {activeTab === 4 && (
        <ForensicTimelineWidget timeline={timeline} isLoading={isTimelineLoading} />
      )}

      {/* Tab 5: Evidence & Body Preview */}
      {activeTab === 5 && (
        <Card sx={{ bgcolor: "background.paper", border: "1px solid", borderColor: "divider", borderRadius: 2 }}>
          <CardContent sx={{ p: 3 }}>
            <Stack direction="row" justifyContent="space-between" alignItems="center" mb={2}>
              <Typography variant="h6" fontWeight={700} color="text.primary">
                Untrusted Body & Evidence Payload
              </Typography>
              <Stack direction="row" spacing={1}>
                <Chip
                  label="Plain Text"
                  onClick={() => setBodyFormat("plain")}
                  color={bodyFormat === "plain" ? "primary" : "default"}
                  size="small"
                  sx={{ cursor: "pointer" }}
                />
                <Chip
                  label="Sandboxed HTML"
                  onClick={() => setBodyFormat("html")}
                  color={bodyFormat === "html" ? "primary" : "default"}
                  size="small"
                  disabled={!parsed?.body_html}
                  sx={{ cursor: "pointer" }}
                />
              </Stack>
            </Stack>

            {bodyFormat === "plain" ? (
              <Box
                component="pre"
                sx={{
                  p: 2,
                  bgcolor: "rgba(0, 0, 0, 0.4)",
                  borderRadius: 1.5,
                  border: "1px solid rgba(255, 255, 255, 0.05)",
                  fontFamily: "monospace",
                  fontSize: "0.8rem",
                  color: "text.primary",
                  overflowX: "auto",
                  whiteSpace: "pre-wrap",
                  wordBreak: "break-word",
                  maxHeight: 400,
                }}
              >
                {parsed?.body_plain || "(No plain text body content found in email)"}
              </Box>
            ) : (
              <Box sx={{ border: "1px solid rgba(255, 255, 255, 0.1)", borderRadius: 1.5, overflow: "hidden" }}>
                <Alert severity="warning" icon={<Shield size={16} />} sx={{ py: 0.5, fontSize: "0.75rem" }}>
                  Isolated sandbox iframe: Scripts, forms, and network executions are strictly disabled.
                </Alert>
                <Box
                  component="iframe"
                  title="Sandboxed Email HTML Body"
                  sandbox="allow-same-origin"
                  srcDoc={parsed?.body_html || "<p>No HTML body</p>"}
                  sx={{ width: "100%", height: 400, border: 0, bgcolor: "#ffffff" }}
                />
              </Box>
            )}

            {/* Attachments Section */}
            {parsed?.attachments_metadata && parsed.attachments_metadata.length > 0 && (
              <Box mt={3}>
                <Typography variant="subtitle2" fontWeight={600} color="text.primary" mb={1} display="flex" alignItems="center" gap={0.5}>
                  <Paperclip size={14} /> Attachments ({parsed.attachments_metadata.length})
                </Typography>
                <Stack spacing={1}>
                  {parsed.attachments_metadata.map((att, idx) => (
                    <Box
                      key={idx}
                      sx={{
                        p: 1.5,
                        borderRadius: 1,
                        bgcolor: "rgba(255, 255, 255, 0.02)",
                        border: "1px solid rgba(255, 255, 255, 0.05)",
                        display: "flex",
                        justifyContent: "space-between",
                        alignItems: "center",
                      }}
                    >
                      <Box>
                        <Typography variant="body2" fontWeight={600} color="text.primary">{att.filename}</Typography>
                        <Typography variant="caption" color="text.secondary" sx={{ fontFamily: "monospace" }}>
                          SHA-256: {att.sha256}
                        </Typography>
                      </Box>
                      <Chip label={`${(att.file_size_bytes / 1024).toFixed(1)} KB`} size="small" />
                    </Box>
                  ))}
                </Stack>
              </Box>
            )}
          </CardContent>
        </Card>
      )}
    </Stack>
  );
};
