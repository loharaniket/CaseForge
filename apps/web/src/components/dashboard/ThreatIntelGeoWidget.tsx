"use client";

import React from "react";
import {
  Box,
  Card,
  CardContent,
  Chip,
  Grid,
  Stack,
  Typography,
} from "@mui/material";
import {
  Globe2,
  Building2,
  Radio,
  MapPin,
} from "lucide-react";
import { CaseGeoInfrastructureResponse, CaseThreatIntelResponse } from "@/types";

interface ThreatIntelGeoWidgetProps {
  intel: CaseThreatIntelResponse | undefined;
  geo: CaseGeoInfrastructureResponse | undefined;
  isLoading?: boolean;
}

export const ThreatIntelGeoWidget: React.FC<ThreatIntelGeoWidgetProps> = ({
  intel,
  geo,
  isLoading = false,
}) => {
  if (isLoading || (!intel && !geo)) {
    return null;
  }

  const ipResults = intel?.ip_results || [];
  const domainResults = intel?.domain_results || [];

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
            <Globe2 className="w-5 h-5 text-cyan-400" />
            <Typography variant="h6" fontWeight={700} color="text.primary">
              Threat Intelligence & Geo Infrastructure
            </Typography>
          </Stack>

          <Stack direction="row" spacing={1}>
            {intel?.ip_provider && (
              <Chip
                label={`IP: ${intel.ip_provider}`}
                size="small"
                variant="outlined"
                sx={{ fontSize: "0.75rem", color: "text.secondary" }}
              />
            )}
            {intel?.domain_provider && (
              <Chip
                label={`Domain: ${intel.domain_provider}`}
                size="small"
                variant="outlined"
                sx={{ fontSize: "0.75rem", color: "text.secondary" }}
              />
            )}
          </Stack>
        </Stack>

        {/* Probable Infrastructure Origin Banner (Rule 14 Compliant) */}
        {geo?.probable_infrastructure_origin && (
          <Box
            sx={{
              p: 2,
              mb: 3,
              borderRadius: 1.5,
              bgcolor: "rgba(6, 182, 212, 0.05)",
              border: "1px solid rgba(6, 182, 212, 0.2)",
            }}
          >
            <Stack direction="row" alignItems="center" spacing={1} mb={0.5}>
              <MapPin className="w-4 h-4 text-cyan-400" />
              <Typography variant="subtitle2" fontWeight={700} color="cyan.main">
                Probable Infrastructure Origin
              </Typography>
            </Stack>
            <Typography variant="body1" fontWeight={600} color="text.primary">
              {geo.probable_infrastructure_origin}
            </Typography>
            {geo.origin_isp && (
              <Typography variant="caption" color="text.secondary" display="block">
                Network Carrier / ISP: {geo.origin_isp} {geo.origin_asn ? `(AS${geo.origin_asn})` : ""}
              </Typography>
            )}
            <Typography variant="caption" color="text.secondary" sx={{ fontStyle: "italic", display: "block", mt: 1 }}>
              Disclaimer: {geo.disclaimer}
            </Typography>
          </Box>
        )}

        <Grid container spacing={3}>
          {/* IP Reputation List */}
          <Grid item xs={12} md={6}>
            <Typography variant="subtitle2" fontWeight={600} color="text.primary" mb={1.5} display="flex" alignItems="center" gap={1}>
              <Radio size={16} /> IP Threat Intelligence ({ipResults.length})
            </Typography>

            {ipResults.length === 0 ? (
              <Typography variant="caption" color="text.secondary">
                No external IP indicators queried.
              </Typography>
            ) : (
              <Stack spacing={1.5}>
                {ipResults.map((r, idx) => (
                  <Box
                    key={idx}
                    sx={{
                      p: 1.5,
                      borderRadius: 1.5,
                      bgcolor: "rgba(255, 255, 255, 0.02)",
                      border: "1px solid rgba(255, 255, 255, 0.05)",
                    }}
                  >
                    <Stack direction="row" justifyContent="space-between" alignItems="center" mb={0.5}>
                      <Typography variant="body2" fontWeight={600} sx={{ fontFamily: "monospace", color: "cyan.300" }}>
                        {r.indicator}
                      </Typography>
                      <Chip
                        label={r.reputation_score !== null ? `Score: ${r.reputation_score}` : r.status}
                        size="small"
                        color={r.is_malicious ? "error" : "success"}
                        sx={{ fontWeight: 700, fontSize: "0.7rem" }}
                      />
                    </Stack>
                    <Typography variant="caption" color="text.secondary" display="block">
                      Provider: {r.provider_name} | {r.cached ? "Cached Query" : "Live Adapter"}
                    </Typography>
                    {r.threat_tags && r.threat_tags.length > 0 && (
                      <Stack direction="row" spacing={0.5} mt={0.5} flexWrap="wrap">
                        {r.threat_tags.map((tag, tIdx) => (
                          <Chip key={tIdx} label={tag} size="small" sx={{ fontSize: "0.65rem", height: 18 }} />
                        ))}
                      </Stack>
                    )}
                  </Box>
                ))}
              </Stack>
            )}
          </Grid>

          {/* Domain Reputation List */}
          <Grid item xs={12} md={6}>
            <Typography variant="subtitle2" fontWeight={600} color="text.primary" mb={1.5} display="flex" alignItems="center" gap={1}>
              <Building2 size={16} /> Domain Threat Intelligence ({domainResults.length})
            </Typography>

            {domainResults.length === 0 ? (
              <Typography variant="caption" color="text.secondary">
                No domain indicators queried.
              </Typography>
            ) : (
              <Stack spacing={1.5}>
                {domainResults.map((r, idx) => (
                  <Box
                    key={idx}
                    sx={{
                      p: 1.5,
                      borderRadius: 1.5,
                      bgcolor: "rgba(255, 255, 255, 0.02)",
                      border: "1px solid rgba(255, 255, 255, 0.05)",
                    }}
                  >
                    <Stack direction="row" justifyContent="space-between" alignItems="center" mb={0.5}>
                      <Typography variant="body2" fontWeight={600} sx={{ fontFamily: "monospace", color: "cyan.300" }}>
                        {r.indicator}
                      </Typography>
                      <Chip
                        label={r.reputation_score !== null ? `Score: ${r.reputation_score}` : r.status}
                        size="small"
                        color={r.is_malicious ? "error" : "success"}
                        sx={{ fontWeight: 700, fontSize: "0.7rem" }}
                      />
                    </Stack>
                    <Typography variant="caption" color="text.secondary" display="block">
                      Provider: {r.provider_name} | {r.cached ? "Cached Query" : "Live Adapter"}
                    </Typography>
                    {r.threat_tags && r.threat_tags.length > 0 && (
                      <Stack direction="row" spacing={0.5} mt={0.5} flexWrap="wrap">
                        {r.threat_tags.map((tag, tIdx) => (
                          <Chip key={tIdx} label={tag} size="small" sx={{ fontSize: "0.65rem", height: 18 }} />
                        ))}
                      </Stack>
                    )}
                  </Box>
                ))}
              </Stack>
            )}
          </Grid>
        </Grid>
      </CardContent>
    </Card>
  );
};
