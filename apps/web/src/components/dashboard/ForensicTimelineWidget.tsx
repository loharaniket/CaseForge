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
  timeline?: ForensicTimelineResponse;
  timelineData?: ForensicTimelineResponse;
  isLoading?: boolean;
}

export const ForensicTimelineWidget: React.FC<ForensicTimelineWidgetProps> = ({
  timeline,
  timelineData,
  isLoading = false,
}) => {
  const activeTimeline = timeline || timelineData;

  if (isLoading || !activeTimeline) {
    return null;
  }

  const events = activeTimeline.events || [];

  const getEventIcon = (type: string) => {
    switch (type) {
      case "EMAIL_DATE":
        return <Mail size={16} color="#1F4E79" />;
      case "MTA_RELAY":
        return <Network size={16} color="#3b82f6" />;
      case "AUTHENTICATION":
        return <ShieldCheck size={16} color="#237A57" />;
      case "INGESTION_STARTED":
        return <UploadCloud size={16} color="#1F4E79" />;
      case "PARSING_COMPLETED":
        return <FileText size={16} color="#1F4E79" />;
      case "THREAT_ASSESSMENT":
        return <AlertTriangle size={16} color="#B7791F" />;
      case "INTEL_ENRICHMENT":
        return <Globe2 size={16} color="#2B6CB0" />;
      case "GEO_ENRICHMENT":
        return <MapPin size={16} color="#237A57" />;
      default:
        return <Clock size={16} color="#52606D" />;
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
            sx={{ bgcolor: "#E8F5EF", color: "#237A57", fontSize: "0.65rem", height: 18 }}
          />
        );
      case "HEADER_DECLARED":
        return (
          <Chip
            label="HEADER DECLARED"
            size="small"
            sx={{ bgcolor: "#EAF2F8", color: "#1F4E79", fontSize: "0.65rem", height: 18 }}
          />
        );
      case "DERIVED":
        return (
          <Chip
            label="DERIVED"
            size="small"
            sx={{ bgcolor: "#FFF7E6", color: "#B7791F", fontSize: "0.65rem", height: 18 }}
          />
        );
      case "MISSING":
        return (
          <Chip
            label="TIMESTAMP MISSING"
            size="small"
            sx={{ bgcolor: "#FDECEC", color: "#C53030", fontSize: "0.65rem", height: 18 }}
          />
        );
      default:
        return (
          <Chip
            label={quality}
            size="small"
            sx={{ bgcolor: "#F5F7FA", color: "#52606D", fontSize: "0.65rem", height: 18 }}
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
            <Clock className="w-5 h-5 text-[#1F4E79]" />
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
              label={`${activeTimeline.total_events} Milestones`}
              size="small"
              sx={{ bgcolor: "#EAF2F8", color: "#1F4E79", fontWeight: 700 }}
            />
          </Stack>
        </Stack>

        {/* Missing Timestamps Alert if applicable */}
        {activeTimeline.has_missing_timestamps && (
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
                            bgcolor: "#FFF7E6",
                            color: "#B7791F",
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
                      <ArrowDown size={14} color="#7B8794" />
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
