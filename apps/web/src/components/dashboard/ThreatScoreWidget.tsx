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
  Divider,
} from "@mui/material";
import {
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  Flame,
  CheckCircle2,
  Info,
} from "lucide-react";
import { RiskAssessmentResponse, ThreatAssessmentResponse } from "@/types";

interface ThreatScoreWidgetProps {
  risk: RiskAssessmentResponse | undefined;
  threat: ThreatAssessmentResponse | undefined;
  isLoading?: boolean;
}

export const ThreatScoreWidget: React.FC<ThreatScoreWidgetProps> = ({
  risk,
  threat,
  isLoading = false,
}) => {
  if (isLoading) {
    return (
      <Card sx={{ bgcolor: "background.paper", border: "1px solid", borderColor: "divider", p: 3 }}>
        <Typography variant="body2" color="text.secondary">
          Calculating deterministic risk and threat posture...
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
        return { color: "error", icon: Flame, label: "CRITICAL", bgcolor: "rgba(239, 68, 68, 0.15)", text: "#ef4444" };
      case "high":
        return { color: "error", icon: ShieldAlert, label: "HIGH", bgcolor: "rgba(249, 115, 22, 0.15)", text: "#f97316" };
      case "medium":
        return { color: "warning", icon: AlertTriangle, label: "MEDIUM", bgcolor: "rgba(234, 179, 8, 0.15)", text: "#eab308" };
      default:
        return { color: "success", icon: ShieldCheck, label: "LOW", bgcolor: "rgba(16, 185, 129, 0.15)", text: "#10b981" };
    }
  };

  const sevConfig = getSeverityConfig(severity);
  const SevIcon = sevConfig.icon;

  const breakdownItems = [
    { label: "AI Threat Heuristics", weight: "40%", score: risk?.breakdown?.ai_score ?? 0 },
    { label: "Header Forensics", weight: "25%", score: risk?.breakdown?.header_score ?? 0 },
    { label: "Domain Reputation", weight: "15%", score: risk?.breakdown?.domain_score ?? 0 },
    { label: "IP Infrastructure", weight: "10%", score: risk?.breakdown?.ip_score ?? 0 },
    { label: "URL Target Analysis", weight: "10%", score: risk?.breakdown?.url_score ?? 0 },
  ];

  return (
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
        {/* Header Row */}
        <Stack direction={{ xs: "column", sm: "row" }} justifyContent="space-between" alignItems={{ xs: "flex-start", sm: "center" }} spacing={2} mb={3}>
          <Stack direction="row" alignItems="center" spacing={1.5}>
            <Box
              sx={{
                p: 1,
                borderRadius: 1.5,
                bgcolor: sevConfig.bgcolor,
                color: sevConfig.text,
                display: "flex",
                alignItems: "center",
              }}
            >
              <SevIcon size={24} />
            </Box>
            <Box>
              <Typography variant="h6" fontWeight={700} color="text.primary">
                Threat Risk Score: {totalScore} / 100
              </Typography>
              <Typography variant="caption" color="text.secondary">
                Deterministic SOC composite risk evaluation (Formula MVP)
              </Typography>
            </Box>
          </Stack>

          <Stack direction="row" spacing={1} alignItems="center">
            <Chip
              label={sevConfig.label}
              size="small"
              sx={{
                bgcolor: sevConfig.bgcolor,
                color: sevConfig.text,
                fontWeight: 700,
                fontSize: "0.75rem",
                border: `1px solid ${sevConfig.text}`,
              }}
            />
            <Chip
              label={`Class: ${classification.toUpperCase()}`}
              size="small"
              variant="outlined"
              color={classification === "normal" ? "success" : "error"}
              sx={{ fontWeight: 600, fontSize: "0.75rem" }}
            />
            <Chip
              label={`Confidence: ${confidencePercent}%`}
              size="small"
              variant="outlined"
              sx={{ fontWeight: 500, fontSize: "0.75rem", color: "text.secondary" }}
            />
          </Stack>
        </Stack>

        {/* Overall Score Bar */}
        <Box mb={3}>
          <LinearProgress
            variant="determinate"
            value={Math.min(100, Math.max(0, totalScore))}
            sx={{
              height: 10,
              borderRadius: 5,
              bgcolor: "rgba(255, 255, 255, 0.08)",
              "& .MuiLinearProgress-bar": {
                bgcolor: sevConfig.text,
                borderRadius: 5,
              },
            }}
          />
        </Box>

        <Divider sx={{ my: 2 }} />

        {/* Two-Column Grid: Breakdown & Explainability */}
        <Stack direction={{ xs: "column", md: "row" }} spacing={3}>
          {/* Left: Component Breakdown */}
          <Box flex={1}>
            <Typography variant="subtitle2" fontWeight={600} color="text.primary" mb={1.5}>
              Deterministic Score Breakdown
            </Typography>
            <Stack spacing={1.5}>
              {breakdownItems.map((item, idx) => (
                <Box key={idx}>
                  <Stack direction="row" justifyContent="space-between" mb={0.5}>
                    <Typography variant="caption" color="text.secondary">
                      {item.label} ({item.weight})
                    </Typography>
                    <Typography variant="caption" fontWeight={600} color="text.primary">
                      {Math.round(item.score)} / 100
                    </Typography>
                  </Stack>
                  <LinearProgress
                    variant="determinate"
                    value={Math.min(100, item.score)}
                    sx={{
                      height: 5,
                      borderRadius: 2.5,
                      bgcolor: "rgba(255, 255, 255, 0.05)",
                    }}
                  />
                </Box>
              ))}
            </Stack>
          </Box>

          {/* Right: Heuristic Signals & Explainability */}
          <Box flex={1}>
            <Typography variant="subtitle2" fontWeight={600} color="text.primary" mb={1.5}>
              Explainability & Forensic Signals
            </Typography>

            {threat?.reasons && threat.reasons.length > 0 ? (
              <Stack spacing={1}>
                {threat.reasons.map((reason, idx) => (
                  <Stack key={idx} direction="row" spacing={1} alignItems="flex-start">
                    <Box sx={{ color: "warning.main", mt: "2px" }}>
                      <AlertTriangle size={14} />
                    </Box>
                    <Typography variant="body2" color="text.secondary" sx={{ fontSize: "0.82rem" }}>
                      {reason}
                    </Typography>
                  </Stack>
                ))}
              </Stack>
            ) : (
              <Stack direction="row" spacing={1} alignItems="center" sx={{ color: "text.secondary" }}>
                <CheckCircle2 size={16} color="#10b981" />
                <Typography variant="body2" sx={{ fontSize: "0.82rem" }}>
                  No suspicious heuristic signals identified. Classification indicates normal message.
                </Typography>
              </Stack>
            )}

            {threat?.model_version && (
              <Box mt={2} display="flex" alignItems="center" gap={0.5}>
                <Info size={12} color="#9ca3af" />
                <Typography variant="caption" color="text.secondary" sx={{ fontStyle: "italic" }}>
                  Engine: {threat.model_version}
                </Typography>
              </Box>
            )}
          </Box>
        </Stack>
      </CardContent>
    </Card>
  );
};
