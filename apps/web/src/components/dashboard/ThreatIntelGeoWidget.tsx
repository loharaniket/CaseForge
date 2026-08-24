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
  ShieldAlert,
  ShieldCheck,
  Info,
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

  const isMockProvider = (name: string) => {
    return name.toLowerCase().includes("mock");
  };

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
      <CardContent sx={{ p: 3 }}>
        {/* SECTION G: GEO INFRASTRUCTURE */}
        <Box mb={4}>
          <Stack direction="row" alignItems="center" spacing={1.5} mb={2}>
            <MapPin className="w-5 h-5 text-[#1F4E79]" />
            <Typography variant="h6" fontWeight={700} color="text.primary">
              Geo Infrastructure Information
            </Typography>
          </Stack>

          {geo ? (
            <Box
              sx={{
                p: 2.5,
                borderRadius: 1.5,
                bgcolor: "rgba(15, 23, 42, 0.9)",
                border: "1px solid #D9E0E7",
              }}
            >
              <Grid container spacing={2}>
                <Grid item xs={12} sm={6}>
                  <Typography variant="caption" sx={{ color: "text.secondary", textTransform: "uppercase", fontWeight: 600 }}>
                    Probable Infrastructure Origin
                  </Typography>
                  <Typography variant="body1" fontWeight={700} color="text.primary" sx={{ mt: 0.5 }}>
                    {geo.probable_infrastructure_origin || "Unknown Origin"}
                  </Typography>
                </Grid>

                <Grid item xs={12} sm={6}>
                  <Typography variant="caption" sx={{ color: "text.secondary", textTransform: "uppercase", fontWeight: 600 }}>
                    Origin Country
                  </Typography>
                  <Typography variant="body1" fontWeight={700} color="text.primary" sx={{ mt: 0.5 }}>
                    {geo.origin_country || "Not available"} {geo.origin_country_code ? `(${geo.origin_country_code})` : ""}
                  </Typography>
                </Grid>

                <Grid item xs={12} sm={6}>
                  <Typography variant="caption" sx={{ color: "text.secondary", textTransform: "uppercase", fontWeight: 600 }}>
                    Autonomous System Number (ASN)
                  </Typography>
                  <Typography variant="body2" fontFamily="monospace" color="#1F4E79" sx={{ mt: 0.5 }}>
                    {geo.origin_asn ? `AS${geo.origin_asn}` : "N/A"}
                  </Typography>
                </Grid>

                <Grid item xs={12} sm={6}>
                  <Typography variant="caption" sx={{ color: "text.secondary", textTransform: "uppercase", fontWeight: 600 }}>
                    Network Provider / ISP & Org
                  </Typography>
                  <Typography variant="body2" color="text.primary" sx={{ mt: 0.5 }}>
                    {geo.origin_isp || "N/A"}
                  </Typography>
                </Grid>
              </Grid>

              {/* Mandatory Rule 14 Disclaimer */}
              <Box
                sx={{
                  mt: 2,
                  pt: 1.5,
                  borderTop: "1px solid #D9E0E7",
                  display: "flex",
                  alignItems: "flex-start",
                  gap: 1,
                }}
              >
                <Info size={14} className="text-gray-400 mt-0.5 flex-shrink-0" />
                <Typography variant="caption" sx={{ color: "text.secondary", fontStyle: "italic", lineHeight: 1.4 }}>
                  {geo.disclaimer || "Geolocation describes network infrastructure and does not establish the physical location or identity of an attacker."}
                </Typography>
              </Box>
            </Box>
          ) : (
            <Typography variant="body2" color="text.secondary">
              No GeoIP infrastructure data resolved for this case.
            </Typography>
          )}
        </Box>

        {/* SECTION F: THREAT INTELLIGENCE */}
        <Box>
          <Stack direction="row" alignItems="center" spacing={1.5} mb={2}>
            <Globe2 className="w-5 h-5 text-[#1F4E79]" />
            <Typography variant="h6" fontWeight={700} color="text.primary">
              Threat Intelligence
            </Typography>
          </Stack>

          <Grid container spacing={3}>
            {/* IP Reputation Table */}
            <Grid item xs={12} md={6}>
              <Typography variant="subtitle2" fontWeight={700} color="text.primary" mb={1.5} display="flex" alignItems="center" gap={1}>
                <Radio size={15} /> IP Reputation ({ipResults.length})
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
                        bgcolor: "rgba(30, 41, 59, 0.4)",
                        border: "1px solid #D9E0E7",
                      }}
                    >
                      <Stack direction="row" justifyContent="space-between" alignItems="center" mb={1}>
                        <Typography variant="body2" fontWeight={700} sx={{ fontFamily: "monospace", color: "#1F4E79" }}>
                          {r.indicator}
                        </Typography>
                        <Stack direction="row" spacing={0.5} alignItems="center">
                          {isMockProvider(r.provider_name) ? (
                            <Chip
                              label="DEVELOPMENT MOCK"
                              size="small"
                              sx={{
                                bgcolor: "#FFF7E6",
                                color: "#B7791F",
                                border: "1px solid #975A16",
                                fontSize: "0.65rem",
                                fontWeight: 700,
                                height: 20,
                              }}
                            />
                          ) : (
                            <Chip
                              label="LIVE"
                              size="small"
                              sx={{
                                bgcolor: "#E8F5EF",
                                color: "#237A57",
                                border: "1px solid #18533B",
                                fontSize: "0.65rem",
                                fontWeight: 700,
                                height: 20,
                              }}
                            />
                          )}
                          <Chip
                            icon={r.is_malicious ? <ShieldAlert size={12} /> : <ShieldCheck size={12} />}
                            label={r.is_malicious ? "Malicious" : "Clean"}
                            size="small"
                            color={r.is_malicious ? "error" : "success"}
                            sx={{ fontWeight: 700, fontSize: "0.7rem", height: 20 }}
                          />
                        </Stack>
                      </Stack>
                      <Typography variant="caption" sx={{ color: "text.secondary", display: "block" }}>
                        Provider: {r.provider_name} • Score: {r.reputation_score !== null ? r.reputation_score : "N/A"}
                      </Typography>
                      {r.threat_tags && r.threat_tags.length > 0 && (
                        <Stack direction="row" spacing={0.5} mt={0.75} flexWrap="wrap">
                          {r.threat_tags.map((tag, tIdx) => (
                            <Chip key={tIdx} label={tag} size="small" sx={{ fontSize: "0.65rem", height: 18, bgcolor: "#D9E0E7", color: "#cbd5e1" }} />
                          ))}
                        </Stack>
                      )}
                    </Box>
                  ))}
                </Stack>
              )}
            </Grid>

            {/* Domain Reputation Table */}
            <Grid item xs={12} md={6}>
              <Typography variant="subtitle2" fontWeight={700} color="text.primary" mb={1.5} display="flex" alignItems="center" gap={1}>
                <Building2 size={15} /> Domain Reputation ({domainResults.length})
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
                        bgcolor: "rgba(30, 41, 59, 0.4)",
                        border: "1px solid #D9E0E7",
                      }}
                    >
                      <Stack direction="row" justifyContent="space-between" alignItems="center" mb={1}>
                        <Typography variant="body2" fontWeight={700} sx={{ fontFamily: "monospace", color: "#1F4E79" }}>
                          {r.indicator}
                        </Typography>
                        <Stack direction="row" spacing={0.5} alignItems="center">
                          {isMockProvider(r.provider_name) ? (
                            <Chip
                              label="DEVELOPMENT MOCK"
                              size="small"
                              sx={{
                                bgcolor: "#FFF7E6",
                                color: "#B7791F",
                                border: "1px solid #975A16",
                                fontSize: "0.65rem",
                                fontWeight: 700,
                                height: 20,
                              }}
                            />
                          ) : (
                            <Chip
                              label="LIVE"
                              size="small"
                              sx={{
                                bgcolor: "#E8F5EF",
                                color: "#237A57",
                                border: "1px solid #18533B",
                                fontSize: "0.65rem",
                                fontWeight: 700,
                                height: 20,
                              }}
                            />
                          )}
                          <Chip
                            icon={r.is_malicious ? <ShieldAlert size={12} /> : <ShieldCheck size={12} />}
                            label={r.is_malicious ? "Malicious" : "Clean"}
                            size="small"
                            color={r.is_malicious ? "error" : "success"}
                            sx={{ fontWeight: 700, fontSize: "0.7rem", height: 20 }}
                          />
                        </Stack>
                      </Stack>
                      <Typography variant="caption" sx={{ color: "text.secondary", display: "block" }}>
                        Provider: {r.provider_name} • Score: {r.reputation_score !== null ? r.reputation_score : "N/A"}
                      </Typography>
                      {r.threat_tags && r.threat_tags.length > 0 && (
                        <Stack direction="row" spacing={0.5} mt={0.75} flexWrap="wrap">
                          {r.threat_tags.map((tag, tIdx) => (
                            <Chip key={tIdx} label={tag} size="small" sx={{ fontSize: "0.65rem", height: 18, bgcolor: "#D9E0E7", color: "#cbd5e1" }} />
                          ))}
                        </Stack>
                      )}
                    </Box>
                  ))}
                </Stack>
              )}
            </Grid>
          </Grid>
        </Box>
      </CardContent>
    </Card>
  );
};
