"use client";

import React from "react";
import {
  Box,
  Card,
  CardContent,
  Chip,
  Divider,
  Grid,
  Stack,
  Typography,
  Alert,
} from "@mui/material";
import {
  ShieldCheck,
  ShieldAlert,
  ShieldX,
  AlertOctagon,
  KeyRound,
  FileCheck,
} from "lucide-react";
import { HeaderForensicsResponse } from "@/types";

interface AuthenticationForensicsWidgetProps {
  forensics: HeaderForensicsResponse | undefined;
  isLoading?: boolean;
}

export const AuthenticationForensicsWidget: React.FC<AuthenticationForensicsWidgetProps> = ({
  forensics,
  isLoading = false,
}) => {
  if (isLoading || !forensics) {
    return null;
  }

  const getStatusChip = (protocol: string, statusVal: string) => {
    const s = (statusVal || "none").toLowerCase();
    let bg = "rgba(107, 114, 128, 0.15)";
    let border = "#6b7280";
    let text = "#9ca3af";
    let Icon = ShieldAlert;

    if (s === "pass") {
      bg = "rgba(16, 185, 129, 0.15)";
      border = "#10b981";
      text = "#10b981";
      Icon = ShieldCheck;
    } else if (s.includes("fail") || s === "permerror") {
      bg = "rgba(239, 68, 68, 0.15)";
      border = "#ef4444";
      text = "#ef4444";
      Icon = ShieldX;
    } else if (s === "softfail" || s === "neutral" || s === "temperror") {
      bg = "rgba(234, 179, 8, 0.15)";
      border = "#eab308";
      text = "#eab308";
      Icon = ShieldAlert;
    }

    return (
      <Chip
        icon={<Icon size={14} color={text} />}
        label={`${protocol}: ${statusVal.toUpperCase()}`}
        size="small"
        sx={{
          bgcolor: bg,
          color: text,
          borderColor: border,
          borderWidth: 1,
          borderStyle: "solid",
          fontWeight: 700,
          fontSize: "0.75rem",
          "& .MuiChip-icon": { color: text },
        }}
      />
    );
  };

  const authDetails = forensics.authentication_details || {};
  const spfDetail = authDetails.spf;
  const dkimDetail = authDetails.dkim;
  const dmarcDetail = authDetails.dmarc;

  return (
    <Card
      sx={{
        bgcolor: "background.paper",
        border: "1px solid",
        borderColor: "divider",
        borderRadius: 2,
      }}
    >
      <CardContent sx={{ p: 3 }}>
        {/* Header */}
        <Stack direction={{ xs: "column", sm: "row" }} justifyContent="space-between" alignItems={{ xs: "flex-start", sm: "center" }} spacing={1} mb={2}>
          <Stack direction="row" alignItems="center" spacing={1.5}>
            <FileCheck className="w-5 h-5 text-cyan-400" />
            <Typography variant="h6" fontWeight={700} color="text.primary">
              Email Authentication Forensics
            </Typography>
          </Stack>

          <Stack direction="row" spacing={1}>
            {getStatusChip("SPF", forensics.spf_status)}
            {getStatusChip("DKIM", forensics.dkim_status)}
            {getStatusChip("DMARC", forensics.dmarc_status)}
          </Stack>
        </Stack>

        {/* Spoofing Alerts if any */}
        {forensics.spoofing_indicators && forensics.spoofing_indicators.length > 0 && (
          <Box mb={2}>
            {forensics.spoofing_indicators.map((ind, idx) => (
              <Alert
                key={idx}
                severity="error"
                icon={<AlertOctagon size={16} />}
                sx={{ mb: 1, py: 0.5, fontSize: "0.82rem" }}
              >
                <strong>Spoofing Warning:</strong> {ind}
              </Alert>
            ))}
          </Box>
        )}

        <Divider sx={{ my: 2 }} />

        {/* Protocol Details Grid */}
        <Grid container spacing={2}>
          {/* SPF */}
          <Grid item xs={12} md={4}>
            <Box sx={{ p: 2, bgcolor: "rgba(255, 255, 255, 0.02)", borderRadius: 1.5, border: "1px solid rgba(255, 255, 255, 0.05)" }}>
              <Stack direction="row" justifyContent="space-between" alignItems="center" mb={1}>
                <Typography variant="subtitle2" fontWeight={600} color="text.primary">
                  SPF Analysis
                </Typography>
                {getStatusChip("SPF", forensics.spf_status)}
              </Stack>
              <Typography variant="body2" color="text.secondary" sx={{ fontSize: "0.8rem", mb: 1 }}>
                {spfDetail?.explanation || "No SPF record evidence found in email headers."}
              </Typography>
              {spfDetail?.domain && (
                <Typography variant="caption" color="text.secondary" display="block">
                  <strong>Domain:</strong> {spfDetail.domain}
                </Typography>
              )}
              {spfDetail?.sender_ip && (
                <Typography variant="caption" color="text.secondary" display="block">
                  <strong>Sender IP:</strong> {spfDetail.sender_ip}
                </Typography>
              )}
            </Box>
          </Grid>

          {/* DKIM */}
          <Grid item xs={12} md={4}>
            <Box sx={{ p: 2, bgcolor: "rgba(255, 255, 255, 0.02)", borderRadius: 1.5, border: "1px solid rgba(255, 255, 255, 0.05)" }}>
              <Stack direction="row" justifyContent="space-between" alignItems="center" mb={1}>
                <Typography variant="subtitle2" fontWeight={600} color="text.primary">
                  DKIM Signature
                </Typography>
                {getStatusChip("DKIM", forensics.dkim_status)}
              </Stack>
              <Typography variant="body2" color="text.secondary" sx={{ fontSize: "0.8rem", mb: 1 }}>
                {dkimDetail?.explanation || "No DKIM signature found or evaluated."}
              </Typography>
              {dkimDetail?.domain && (
                <Typography variant="caption" color="text.secondary" display="block">
                  <strong>Signing Domain:</strong> {dkimDetail.domain}
                </Typography>
              )}
              {dkimDetail?.selector && (
                <Typography variant="caption" color="text.secondary" display="block">
                  <KeyRound size={10} style={{ display: "inline", marginRight: 4 }} />
                  <strong>Selector:</strong> {dkimDetail.selector}
                </Typography>
              )}
            </Box>
          </Grid>

          {/* DMARC */}
          <Grid item xs={12} md={4}>
            <Box sx={{ p: 2, bgcolor: "rgba(255, 255, 255, 0.02)", borderRadius: 1.5, border: "1px solid rgba(255, 255, 255, 0.05)" }}>
              <Stack direction="row" justifyContent="space-between" alignItems="center" mb={1}>
                <Typography variant="subtitle2" fontWeight={600} color="text.primary">
                  DMARC Policy
                </Typography>
                {getStatusChip("DMARC", forensics.dmarc_status)}
              </Stack>
              <Typography variant="body2" color="text.secondary" sx={{ fontSize: "0.8rem", mb: 1 }}>
                {dmarcDetail?.explanation || "No DMARC evaluation clause in headers."}
              </Typography>
              {dmarcDetail?.domain && (
                <Typography variant="caption" color="text.secondary" display="block">
                  <strong>Policy Domain:</strong> {dmarcDetail.domain}
                </Typography>
              )}
              {dmarcDetail?.matching_clause && (
                <Typography variant="caption" color="text.secondary" display="block">
                  <strong>Clause:</strong> {dmarcDetail.matching_clause}
                </Typography>
              )}
            </Box>
          </Grid>
        </Grid>
      </CardContent>
    </Card>
  );
};
