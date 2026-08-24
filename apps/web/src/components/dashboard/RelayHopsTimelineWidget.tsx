"use client";

import React from "react";
import {
  Box,
  Card,
  CardContent,
  Chip,
  Stack,
  Typography,
} from "@mui/material";
import {
  Network,
  Clock,
  ArrowDown,
  Globe,
  Lock,
} from "lucide-react";
import { HeaderForensicsResponse } from "@/types";

interface RelayHopsTimelineWidgetProps {
  forensics: HeaderForensicsResponse | undefined;
  isLoading?: boolean;
}

export const RelayHopsTimelineWidget: React.FC<RelayHopsTimelineWidgetProps> = ({
  forensics,
  isLoading = false,
}) => {
  if (isLoading || !forensics) {
    return null;
  }

  const hops = forensics.relay_hops || [];
  const probableOrigin = forensics.probable_origin_ip;

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
        <Stack direction={{ xs: "column", sm: "row" }} justifyContent="space-between" alignItems={{ xs: "flex-start", sm: "center" }} spacing={1} mb={2}>
          <Stack direction="row" alignItems="center" spacing={1.5}>
            <Network className="w-5 h-5 text-[#1F4E79]" />
            <Typography variant="h6" fontWeight={700} color="text.primary">
              MTA Relay Pathway Timeline
            </Typography>
          </Stack>

          <Stack direction="row" spacing={1} alignItems="center">
            <Chip
              label={`${hops.length} Relay Hops`}
              size="small"
              sx={{ bgcolor: "#EAF2F8", color: "#1F4E79", fontWeight: 600 }}
            />
            {probableOrigin && (
              <Chip
                label={`Origin IP: ${probableOrigin}`}
                size="small"
                variant="outlined"
                color="primary"
                sx={{ fontWeight: 600, fontFamily: "monospace" }}
              />
            )}
          </Stack>
        </Stack>

        <Typography variant="caption" color="text.secondary" display="block" mb={3}>
          Chronological hop sequence from source origin to receiving Mail Transfer Agent (MTA).
        </Typography>

        {hops.length === 0 ? (
          <Box p={3} textAlign="center">
            <Typography variant="body2" color="text.secondary">
              No Received header hops available in this message.
            </Typography>
          </Box>
        ) : (
          <Stack spacing={2}>
            {hops.map((hop, idx) => (
              <Box key={idx}>
                <Box
                  sx={{
                    p: 2,
                    bgcolor: "rgba(255, 255, 255, 0.02)",
                    borderRadius: 1.5,
                    border: "1px solid",
                    borderColor: hop.ip_addresses?.includes(probableOrigin || "")
                      ? "primary.main"
                      : "rgba(255, 255, 255, 0.06)",
                  }}
                >
                  <Stack direction={{ xs: "column", sm: "row" }} justifyContent="space-between" alignItems={{ xs: "flex-start", sm: "center" }} spacing={1} mb={1}>
                    <Stack direction="row" spacing={1} alignItems="center">
                      <Chip
                        label={`Hop #${hop.hop_number}`}
                        size="small"
                        sx={{ bgcolor: "rgba(255, 255, 255, 0.1)", fontWeight: 700, fontSize: "0.75rem" }}
                      />
                      {hop.is_private_relay ? (
                        <Chip
                          icon={<Lock size={12} />}
                          label="Private Subnet (RFC1918)"
                          size="small"
                          sx={{ bgcolor: "#F5F7FA", color: "#52606D", fontSize: "0.7rem" }}
                        />
                      ) : (
                        <Chip
                          icon={<Globe size={12} />}
                          label="Public Gateway"
                          size="small"
                          sx={{ bgcolor: "#E8F5EF", color: "#237A57", fontSize: "0.7rem" }}
                        />
                      )}
                    </Stack>

                    {hop.delay_seconds !== null && hop.delay_seconds > 0 && (
                      <Stack direction="row" spacing={0.5} alignItems="center" sx={{ color: "text.secondary" }}>
                        <Clock size={12} />
                        <Typography variant="caption" sx={{ fontStyle: "italic" }}>
                          Transit Delay: +{hop.delay_seconds}s
                        </Typography>
                      </Stack>
                    )}
                  </Stack>

                  <GridContainer fromHost={hop.from_host} byHost={hop.by_host} withProto={hop.with_protocol} ips={hop.ip_addresses} />

                  {hop.timestamp_raw && (
                    <Typography variant="caption" color="text.secondary" sx={{ display: "block", mt: 1, fontSize: "0.7rem" }}>
                      Timestamp: {hop.timestamp_iso ? new Date(hop.timestamp_iso).toUTCString() : hop.timestamp_raw}
                    </Typography>
                  )}
                </Box>

                {idx < hops.length - 1 && (
                  <Box display="flex" justifyContent="center" my={0.5}>
                    <ArrowDown size={14} color="#7B8794" />
                  </Box>
                )}
              </Box>
            ))}
          </Stack>
        )}
      </CardContent>
    </Card>
  );
};

const GridContainer: React.FC<{
  fromHost: string | null;
  byHost: string | null;
  withProto: string | null;
  ips: string[];
}> = ({ fromHost, byHost, withProto, ips }) => (
  <Box sx={{ display: "grid", gridTemplateColumns: { xs: "1fr", sm: "1fr 1fr" }, gap: 1, mt: 1 }}>
    <Typography variant="caption" color="text.secondary" sx={{ fontFamily: "monospace" }}>
      <strong>From:</strong> {fromHost || "Unknown"}
    </Typography>
    <Typography variant="caption" color="text.secondary" sx={{ fontFamily: "monospace" }}>
      <strong>By:</strong> {byHost || "Unknown"}
    </Typography>
    {withProto && (
      <Typography variant="caption" color="text.secondary" sx={{ fontFamily: "monospace" }}>
        <strong>Protocol:</strong> {withProto}
      </Typography>
    )}
    {ips && ips.length > 0 && (
      <Typography variant="caption" color="text.secondary" sx={{ fontFamily: "monospace" }}>
        <strong>IPs:</strong> {ips.join(", ")}
      </Typography>
    )}
  </Box>
);
