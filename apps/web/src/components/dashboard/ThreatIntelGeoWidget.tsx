"use client";

import React from "react";
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
import { Card, CardContent, Badge, Table, Thead, Tbody, Tr, Th, Td } from "@/components/ui";

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
    <Card>
      <CardContent className="p-6">
        {/* SECTION G: GEO INFRASTRUCTURE */}
        <div className="mb-8">
          <div className="flex items-center gap-3 mb-4">
            <MapPin className="w-5 h-5 text-primary" />
            <h3 className="text-[16px] font-[700] text-text-primary">
              Geo Infrastructure Information
            </h3>
          </div>

          {geo ? (
            <div className="p-5 rounded-[8px] bg-bg-page border border-border">
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                <div className="flex flex-col">
                  <span className="text-[11px] font-[600] text-text-muted uppercase tracking-wider">
                    Probable Infrastructure Origin
                  </span>
                  <span className="text-[14px] font-[700] text-text-primary mt-1">
                    {geo.probable_infrastructure_origin || "Unknown Origin"}
                  </span>
                </div>

                <div className="flex flex-col">
                  <span className="text-[11px] font-[600] text-text-muted uppercase tracking-wider">
                    Candidate Origin IP
                  </span>
                  <span className="text-[13px] font-mono text-primary mt-1 bg-primary-soft px-1.5 py-0.5 rounded w-fit">
                    {geo.candidate_origin_ip || "Not available (No hop IP)"}
                  </span>
                </div>

                <div className="flex flex-col">
                  <span className="text-[11px] font-[600] text-text-muted uppercase tracking-wider">
                    Origin Country
                  </span>
                  <span className="text-[14px] font-[700] text-text-primary mt-1">
                    {geo.origin_country || "Not available"} {geo.origin_country_code && geo.origin_country_code !== "LOCAL" ? `(${geo.origin_country_code})` : ""}
                  </span>
                </div>

                <div className="flex flex-col">
                  <span className="text-[11px] font-[600] text-text-muted uppercase tracking-wider">
                    Autonomous System Number (ASN)
                  </span>
                  <span className="text-[13px] font-mono text-primary mt-1 bg-primary-soft px-1.5 py-0.5 rounded w-fit">
                    {geo.origin_asn ? `AS${geo.origin_asn}` : "N/A"}
                  </span>
                </div>

                <div className="flex flex-col sm:col-span-2">
                  <span className="text-[11px] font-[600] text-text-muted uppercase tracking-wider">
                    Network Provider / ISP & Org
                  </span>
                  <span className="text-[13px] text-text-primary mt-1">
                    {geo.origin_isp || "N/A"}
                  </span>
                </div>
              </div>

              {geo.total_ips_analyzed === 0 && (
                <div className="mt-3 p-2.5 rounded bg-warning-soft text-warning text-xs flex items-center gap-2 border border-warning/20">
                  <Info className="w-4 h-4 shrink-0" />
                  <span>No MTA transmission hops or sender IPs were recorded in the headers of this email. Estimated location requires at least one relay hop, SPF sender IP, or resolvable domain.</span>
                </div>
              )}

              {/* Mandatory Rule 14 Disclaimer */}
              <div className="mt-4 pt-3 border-t border-border flex items-start gap-2">
                <Info className="w-3.5 h-3.5 text-text-muted mt-0.5 shrink-0" />
                <span className="text-[11px] text-text-muted italic leading-relaxed">
                  {geo.disclaimer || "Geolocation describes network infrastructure and does not establish the physical location or identity of an attacker."}
                </span>
              </div>
            </div>
          ) : (
            <p className="text-sm text-text-secondary">
              No GeoIP infrastructure data resolved for this case.
            </p>
          )}
        </div>

        {/* SECTION F: THREAT INTELLIGENCE */}
        <div>
          <div className="flex items-center gap-3 mb-4">
            <Globe2 className="w-5 h-5 text-primary" />
            <h3 className="text-[16px] font-[700] text-text-primary">
              Threat Intelligence
            </h3>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            {/* IP Reputation Table */}
            <div className="flex flex-col">
              <h4 className="text-[13px] font-[700] text-text-primary mb-3 flex items-center gap-2">
                <Radio className="w-4 h-4" /> IP Reputation ({ipResults.length})
              </h4>
              {ipResults.length === 0 ? (
                <p className="text-sm text-text-muted">No external IP reputation results.</p>
              ) : (
                <div className="border border-border rounded-[6px] overflow-hidden">
                  <Table className="border-none rounded-none">
                    <Thead>
                      <Tr className="bg-bg-panel-subtle border-b border-border">
                        <Th className="text-[10px]">IP / PROVIDER</Th>
                        <Th className="text-[10px] text-right">VERDICT</Th>
                      </Tr>
                    </Thead>
                    <Tbody>
                      {ipResults.map((r, i) => (
                        <Tr key={i}>
                          <Td>
                            <div className="flex flex-col gap-1">
                              <span className="font-mono text-[12px] font-[600] text-primary break-all">
                                {r.indicator}
                              </span>
                              <div className="flex items-center gap-1.5">
                                <span className="text-[10px] text-text-secondary">
                                  {r.provider_name}
                                </span>
                                {isMockProvider(r.provider_name) && (
                                  <Badge variant="warning" className="text-[9px] px-1 py-0 uppercase">MOCK</Badge>
                                )}
                              </div>
                            </div>
                          </Td>
                          <Td className="text-right">
                            {r.is_malicious ? (
                              <Badge variant="danger" className="gap-1 text-[10px] px-1.5 py-0.5 justify-end">
                                <ShieldAlert className="w-3 h-3" />
                                MALICIOUS
                              </Badge>
                            ) : (
                              <Badge variant="success" className="gap-1 text-[10px] px-1.5 py-0.5 justify-end">
                                <ShieldCheck className="w-3 h-3" />
                                CLEAN
                              </Badge>
                            )}
                          </Td>
                        </Tr>
                      ))}
                    </Tbody>
                  </Table>
                </div>
              )}
            </div>

            {/* Domain Reputation Table */}
            <div className="flex flex-col">
              <h4 className="text-[13px] font-[700] text-text-primary mb-3 flex items-center gap-2">
                <Building2 className="w-4 h-4" /> Domain Reputation ({domainResults.length})
              </h4>
              {domainResults.length === 0 ? (
                <p className="text-sm text-text-muted">No external Domain reputation results.</p>
              ) : (
                <div className="border border-border rounded-[6px] overflow-hidden">
                  <Table className="border-none rounded-none">
                    <Thead>
                      <Tr className="bg-bg-panel-subtle border-b border-border">
                        <Th className="text-[10px]">DOMAIN / PROVIDER</Th>
                        <Th className="text-[10px] text-right">VERDICT</Th>
                      </Tr>
                    </Thead>
                    <Tbody>
                      {domainResults.map((r, i) => (
                        <Tr key={i}>
                          <Td>
                            <div className="flex flex-col gap-1">
                              <span className="font-mono text-[12px] font-[600] text-primary break-all">
                                {r.indicator}
                              </span>
                              <div className="flex items-center gap-1.5">
                                <span className="text-[10px] text-text-secondary">
                                  {r.provider_name}
                                </span>
                                {isMockProvider(r.provider_name) && (
                                  <Badge variant="warning" className="text-[9px] px-1 py-0 uppercase">MOCK</Badge>
                                )}
                              </div>
                            </div>
                          </Td>
                          <Td className="text-right">
                            {r.is_malicious ? (
                              <Badge variant="danger" className="gap-1 text-[10px] px-1.5 py-0.5 justify-end">
                                <ShieldAlert className="w-3 h-3" />
                                MALICIOUS
                              </Badge>
                            ) : (
                              <Badge variant="success" className="gap-1 text-[10px] px-1.5 py-0.5 justify-end">
                                <ShieldCheck className="w-3 h-3" />
                                CLEAN
                              </Badge>
                            )}
                          </Td>
                        </Tr>
                      ))}
                    </Tbody>
                  </Table>
                </div>
              )}
            </div>
          </div>
        </div>
      </CardContent>
    </Card>
  );
};
