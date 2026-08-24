"use client";

import React from "react";
import {
  Box,
  Card,
  CardContent,
  Chip,
  LinearProgress,
  Stack,
  Typography,
} from "@mui/material";
import {
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  Flame,
  Check,
  Info,
} from "lucide-react";
import { HeaderForensicsResponse, RiskAssessmentResponse, ThreatAssessmentResponse } from "@/types";

interface ThreatScoreWidgetProps {
  risk: RiskAssessmentResponse | undefined;
  threat: ThreatAssessmentResponse | undefined;
  forensics?: HeaderForensicsResponse | undefined;
  caseId?: string;
  isLoading?: boolean;
}

export const ThreatScoreWidget: React.FC<ThreatScoreWidgetProps> = ({
  risk,
  threat,
  forensics,
  caseId,
  isLoading = false,
}) => {
  if (isLoading) {
    return (
      <Card sx={{ bgcolor: "background.paper", border: "1px solid", borderColor: "divider", p: 3 }}>
        <Typography variant="body2" color="text.secondary">
          Analyzing investigation...
        </Typography>
        <LinearProgress sx={{ mt: 2 }} />
      </Card>
    );
  }

  const totalScore = risk ? Math.round(risk.total_score) : 0;
  const severity = risk?.severity || "low";
  const classification = threat?.classification || "normal";
  const confidencePercent = threat ? Math.round(threat.confidence * 100) : 0;

  // Severity color definitions
  const getSeverityConfig = (sev: string) => {
    switch (sev.toLowerCase()) {
      case "critical":
        return { color: "error", icon: Flame, label: "CRITICAL", bgcolor: "#FDECEC", text: "#C53030", border: "#C53030" };
      case "high":
        return { color: "error", icon: ShieldAlert, label: "HIGH", bgcolor: "rgba(249, 115, 22, 0.15)", text: "#B7791F", border: "#B7791F" };
      case "medium":
        return { color: "warning", icon: AlertTriangle, label: "MEDIUM", bgcolor: "#FFF7E6", text: "#B7791F", border: "#B7791F" };
      default:
        return { color: "success", icon: ShieldCheck, label: "LOW", bgcolor: "#E8F5EF", text: "#237A57", border: "#237A57" };
    }
  };

  const sevConfig = getSeverityConfig(severity);
  const SevIcon = sevConfig.icon;

  // Synthesize concise executive explanation verdict
  const getExecutiveVerdict = () => {
    const isPhishOrBec = classification === "phishing" || classification === "bec";
    if (isPhishOrBec && totalScore >= 75) {
      return "High-risk phishing email with failed authentication, suspicious sender-domain relationship, and malicious infrastructure indicators.";
    }
    if (isPhishOrBec) {
      return "Suspicious email with anomalous routing and social engineering indicators requiring containment.";
    }
    if (classification === "spam") {
      return "Unsolicited bulk email with low confidence indicators and non-standard relay origins.";
    }
    return "Normal email communication with valid authentication alignment and benign infrastructure indicators.";
  };

  // Compile top 5 strongest reasons prioritizing explainability signals
  const getTopReasons = (): string[] => {
    const reasons: string[] = [];

    // 1. AI Threat heuristic reasons first to ensure explainability
    if (threat?.reasons && threat.reasons.length > 0) {
      threat.reasons.forEach((r) => {
        if (!reasons.includes(r)) reasons.push(r);
      });
    }

    // 2. Authentication signals
    if (forensics?.spf_status?.toLowerCase() === "fail") {
      reasons.push("SPF authentication failed (Unauthorized sending host)");
    }
    if (forensics?.dkim_status?.toLowerCase() === "fail") {
      reasons.push("DKIM cryptographic signature verification failed");
    }
    if (forensics?.dmarc_status?.toLowerCase() === "fail") {
      reasons.push("DMARC alignment policy failed");
    }

    // 3. Spoofing & Header anomalies
    if (forensics?.spoofing_indicators && forensics.spoofing_indicators.length > 0) {
      forensics.spoofing_indicators.forEach((ind) => {
        if (!reasons.includes(ind)) reasons.push(ind);
      });
    }

    // 4. Fallback if clean
    if (reasons.length === 0) {
      if (classification === "normal") {
        reasons.push("Authentication checks passed (SPF/DKIM/DMARC valid)");
        reasons.push("No known malicious IOCs or blacklisted relay hops identified");
        reasons.push("Sender identity aligns with declared Return-Path domain");
      } else {
        reasons.push(`Classified as ${classification.toUpperCase()} based on composite risk scoring`);
      }
    }

    return reasons.slice(0, 5);
  };

  const topReasons = getTopReasons();

  return (
    <Card
      sx={{
        bgcolor: "background.paper",
        border: "1px solid #D9E0E7",
        borderRadius: 2,
        boxShadow: "0 4px 12px rgba(0, 0, 0, 0.4)",
        overflow: "hidden",
      }}
    >
      {/* SECTION A: VERDICT */}
      <Box
        sx={{
          p: 3,
          borderBottom: "1px solid #F8FAFC",
          bgcolor: "#F5F7FA",
        }}
      >
        <Stack
          direction={{ xs: "column", md: "row" }}
          justifyContent="space-between"
          alignItems={{ xs: "flex-start", md: "center" }}
          spacing={2}
          mb={2}
        >
          <Stack direction="row" alignItems="center" spacing={1.5}>
            <Box
              sx={{
                p: 1.25,
                borderRadius: 1.5,
                bgcolor: sevConfig.bgcolor,
                color: sevConfig.text,
                display: "flex",
                alignItems: "center",
                border: `1px solid ${sevConfig.border}`,
              }}
            >
              <SevIcon size={24} />
            </Box>
            <Box>
              <Stack direction="row" spacing={1} alignItems="center" flexWrap="wrap">
                <Typography variant="h5" fontWeight={800} color="text.primary" sx={{ letterSpacing: "-0.02em" }}>
                  Threat Risk Score: {totalScore} / 100
                </Typography>
                <Chip
                  label={sevConfig.label}
                  size="small"
                  sx={{
                    bgcolor: sevConfig.bgcolor,
                    color: sevConfig.text,
                    fontWeight: 700,
                    fontSize: "0.75rem",
                    border: `1px solid ${sevConfig.border}`,
                  }}
                />
                <Chip
                  label={`Class: ${classification.toUpperCase()}`}
                  size="small"
                  sx={{
                    bgcolor: classification === "normal" ? "#E8F5EF" : "rgba(239, 68, 68, 0.1)",
                    color: classification === "normal" ? "#237A57" : "#C53030",
                    fontWeight: 700,
                    fontSize: "0.75rem",
                    border: `1px solid ${classification === "normal" ? "#18533B" : "#dc2626"}`,
                  }}
                />
              </Stack>
              <Typography variant="caption" sx={{ color: "text.secondary", fontFamily: "monospace", mt: 0.5, display: "block" }}>
                Case ID: {caseId || risk?.case_id || "N/A"} • Confidence: {confidencePercent}%
              </Typography>
            </Box>
          </Stack>
        </Stack>

        {/* Progress Bar */}
        <Box mb={2}>
          <LinearProgress
            variant="determinate"
            value={Math.min(100, Math.max(0, totalScore))}
            sx={{
              height: 8,
              borderRadius: 4,
              bgcolor: "#F8FAFC",
              "& .MuiLinearProgress-bar": {
                bgcolor: sevConfig.text,
                borderRadius: 4,
              },
            }}
          />
        </Box>

        {/* Short Executive Verdict Explanation */}
        <Box
          sx={{
            p: 1.75,
            borderRadius: 1.5,
            bgcolor: "#FFFFFF",
            border: "1px solid #D9E0E7",
          }}
        >
          <Typography variant="body2" sx={{ color: "text.primary", fontWeight: 500, lineHeight: 1.5 }}>
            {getExecutiveVerdict()}
          </Typography>
        </Box>
      </Box>

      {/* SECTION B: WHY? (Top 5 Strongest Reasons) */}
      <CardContent sx={{ p: 3 }}>
        <Stack direction="row" alignItems="center" spacing={1} mb={2}>
          <Typography
            variant="subtitle1"
            sx={{
              fontWeight: 800,
              color: "text.primary",
              textTransform: "uppercase",
              letterSpacing: "0.05em",
              fontSize: "0.85rem",
            }}
          >
            Why Was It Classified This Way? (Top Reasons)
          </Typography>
        </Stack>

        <Stack spacing={1.25}>
          {topReasons.map((reason, idx) => (
            <Box
              key={idx}
              sx={{
                display: "flex",
                alignItems: "flex-start",
                gap: 1.5,
                p: 1.25,
                borderRadius: 1,
                bgcolor: "rgba(30, 41, 59, 0.4)",
                border: "1px solid rgba(51, 65, 85, 0.5)",
              }}
            >
              <Box
                sx={{
                  display: "flex",
                  alignItems: "center",
                  justifyContent: "center",
                  width: 20,
                  height: 20,
                  borderRadius: "50%",
                  bgcolor: classification === "normal" ? "#E8F5EF" : "rgba(249, 115, 22, 0.15)",
                  color: classification === "normal" ? "#237A57" : "#fb923c",
                  flexShrink: 0,
                  mt: "1px",
                }}
              >
                <Check size={13} strokeWidth={3} />
              </Box>
              <Typography variant="body2" sx={{ color: "#17212B", fontWeight: 500, fontSize: "0.85rem" }}>
                {reason}
              </Typography>
            </Box>
          ))}
        </Stack>

        {threat?.model_version && (
          <Box mt={2} display="flex" alignItems="center" gap={0.75}>
            <Info size={13} color="#7B8794" />
            <Typography variant="caption" sx={{ color: "#7B8794", fontStyle: "italic" }}>
              Assessment Model: {threat.model_version}
            </Typography>
          </Box>
        )}
      </CardContent>
    </Card>
  );
};
