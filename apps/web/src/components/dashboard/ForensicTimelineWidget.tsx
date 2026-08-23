"use client";

import React from "react";
import {
  Box,
  Card,
  CardContent,
  Chip,
  Divider,
  Stack,
  Typography,
  Alert,
} from "@mui/material";
import {
  Clock,
  Mail,
  Network,
  ShieldCheck,
  UploadCloud,
  FileText,
  AlertTriangle,
  Globe2,
  MapPin,
  ArrowDown,
  Info,
  Calendar,
} from "lucide-react";
import { ForensicTimelineResponse, TimelineEvent } from "@/types";

interface ForensicTimelineWidgetProps {
  timeline: ForensicTimelineResponse | undefined;
  isLoading?: boolean;
}

export const ForensicTimelineWidget: React.FC<ForensicTimelineWidgetProps> = ({
  timeline,
  isLoading = false,
}) => {
  if (isLoading || !timeline) {
    return null;
  }

  const events = timeline.events || [];

  const getEventIcon = (type: string) => {
    switch (type) {
      case "EMAIL_DATE":
        return <Mail size={16} color="#06b6d4" />;
      case "MTA_RELAY":
        return <Network size={16} color="#3b82f6" />;
      case "AUTHENTICATION":
        return <ShieldCheck size={16} color="#10b981" />;
      case "INGESTION_STARTED":
        return <UploadCloud size={16} color="#8b5cf6" />;
      case "PARSING_COMPLETED":
        return <FileText size={16} color="#06b6d4" />;
      case "THREAT_ASSESSMENT":
        return <AlertTriangle size={16} color="#f97316" />;
      case "INTEL_ENRICHMENT":
        return <Globe2 size={16} color="#ec4899" />;
      case "GEO_ENRICHMENT":
        return <MapPin size={16} color="#14b8a6" />;
      default:
        return <Clock size={16} color="#9ca3af" />;
    }
  };

  const getQualityBadge = (quality: string) => {
    switch (quality) {
      case "EXACT":
      case "SERVER_INGESTION":
        return (
          <Chip
            label={quality}
            size="small"
            sx={{ bgcolor: "rgba(16, 185, 129, 0.15)", color: "#10b981", fontSize: "0.65rem", height: 18 }}
          />
        );
      case "HEADER_DECLARED":
        return (
          <Chip
            label="HEADER DECLARED"
            size="small"
            sx={{ bgcolor: "rgba(6, 182, 212, 0.15)", color: "#06b6d4", fontSize: "0.65rem", height: 18 }}
          />
        );
      case "DERIVED":
        return (
          <Chip
            label="DERIVED"
            size="small"
            sx={{ bgcolor: "rgba(234, 179, 8, 0.15)", color: "#eab308", fontSize: "0.65rem", height: 18 }}
          />
        );
      case "MISSING":
        return (
          <Chip
            label="TIMESTAMP MISSING"
            size="small"
            sx={{ bgcolor: "rgba(239, 68, 68, 0.15)", color: "#ef4444", fontSize: "0.65rem", height: 18 }}
          />
        );
      default:
        return (
          <Chip
            label={quality}
            size="small"
            sx={{ bgcolor: "rgba(156, 163, 175, 0.15)", color: "#9ca3af", fontSize: "0.65rem", height: 18 }}
          />
        );
    }
  };

  const formatDelay = (seconds: number | null | undefined) => {
    if (seconds === null || seconds === undefined || seconds <= 0) {
      return null;
    }
    if (seconds < 60) {
      return `+${seconds.toFixed(0)}s`;
    }
    const mins = Math.floor(seconds / 60);
    const remSec = Math.round(seconds % 60);
    return `+${mins}m ${remSec}s`;
  };

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
            <Clock className="w-5 h-5 text-cyan-400" />
            <Box>
              <Typography variant="h6" fontWeight={700} color="text.primary">
                Chronological Forensic Timeline
              </Typography>
              <Typography variant="caption" color="text.secondary">
                Transmission sequence and analysis milestones reconstructed from available evidence headers.
              </Typography>
            </Box>
          </Stack>

          <Stack direction="row" spacing={1} alignItems="center">
            <Chip
              label={`${timeline.total_events} Milestones`}
              size="small"
              sx={{ bgcolor: "rgba(6, 182, 212, 0.15)", color: "#06b6d4", fontWeight: 700 }}
            />
          </Stack>
        </Stack>

        {/* Missing Timestamps Alert if applicable */}
        {timeline.has_missing_timestamps && (
          <Alert severity="info" icon={<Info size={16} />} sx={{ mb: 2, py: 0.5, fontSize: "0.75rem" }}>
            Some transmission hops or headers lacked parseable timestamps. No synthetic timestamps were fabricated; original unparsed values are preserved.
          </Alert>
        )}

        <Divider sx={{ my: 2 }} />

        {/* Events Vertical Sequence */}
        {events.length === 0 ? (
          <Box p={4} textAlign="center">
            <Typography variant="body2" color="text.secondary">
              No timeline events recorded for this case.
            </Typography>
          </Box>
        ) : (
          <Stack spacing={2}>
            {events.map((event: TimelineEvent, idx: number) => {
              const delayStr = formatDelay(event.delay_from_previous_seconds);

              return (
                <Box key={event.event_id || idx}>
                  <Box
                    sx={{
                      p: 2,
                      borderRadius: 1.5,
                      bgcolor: "rgba(255, 255, 255, 0.02)",
                      border: "1px solid rgba(255, 255, 255, 0.06)",
                    }}
                  >
                    <Stack direction={{ xs: "column", sm: "row" }} justifyContent="space-between" alignItems={{ xs: "flex-start", sm: "center" }} spacing={1} mb={1}>
                      <Stack direction="row" spacing={1} alignItems="center">
                        <Box sx={{ display: "flex", alignItems: "center" }}>
                          {getEventIcon(event.event_type)}
                        </Box>
                        <Typography variant="subtitle2" fontWeight={700} color="text.primary">
                          {event.title}
                        </Typography>
                        {getQualityBadge(event.timestamp_quality)}
                      </Stack>

                      {delayStr && (
                        <Chip
                          icon={<Clock size={10} />}
                          label={`Transit Delay: ${delayStr}`}
                          size="small"
                          sx={{
                            bgcolor: "rgba(234, 179, 8, 0.1)",
                            color: "#eab308",
                            fontSize: "0.68rem",
                            height: 20,
                            fontFamily: "monospace",
                          }}
                        />
                      )}
                    </Stack>

                    <Typography variant="body2" color="text.secondary" sx={{ fontSize: "0.82rem", mb: 1 }}>
                      {event.description}
                    </Typography>

                    <Stack direction={{ xs: "column", sm: "row" }} justifyContent="space-between" alignItems={{ xs: "flex-start", sm: "center" }} spacing={1}>
                      <Typography variant="caption" color="text.secondary" sx={{ fontFamily: "monospace", display: "flex", alignItems: "center", gap: 0.5 }}>
                        <Calendar size={12} />
                        {event.timestamp_iso
                          ? new Date(event.timestamp_iso).toUTCString()
                          : event.timestamp_raw || "Timestamp unrecorded"}
                      </Typography>

                      <Typography variant="caption" color="text.secondary" sx={{ fontFamily: "monospace", fontSize: "0.7rem" }}>
                        Source: {event.source}
                      </Typography>
                    </Stack>
                  </Box>

                  {idx < events.length - 1 && (
                    <Box display="flex" justifyContent="center" my={0.5}>
                      <ArrowDown size={14} color="#6b7280" />
                    </Box>
                  )}
                </Box>
              );
            })}
          </Stack>
        )}
      </CardContent>
    </Card>
  );
};
