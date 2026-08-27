"use client";

import React, { useEffect, useState } from "react";
import { Server, MapPin, Building, ShieldAlert, ShieldCheck } from "lucide-react";
import { Card, CardContent, Badge, Table, Thead, Tbody, Tr, Th, Td } from "@/components/ui";
import { getCaseIPIntelligence, enrichCaseIPIntelligence } from "@/lib/api/email";

interface IPIntelligenceRecord {
  ip_address: string;
  country: string | null;
  region: string | null;
  city: string | null;
  asn: number | null;
  isp: string | null;
  organization: string | null;
  hosting_provider: boolean | null;
  proxy_vpn_indicator: boolean | null;
  tor_indicator: boolean | null;
  reputation: string | null;
  abuse_threat_score: number | null;
}

interface CaseIPIntelligenceResponse {
  case_id: string;
  ip_intelligence: IPIntelligenceRecord[];
}

interface IPIntelligenceWidgetProps {
  caseId: string;
}

export function IPIntelligenceWidget({ caseId }: IPIntelligenceWidgetProps) {
  const [data, setData] = useState<CaseIPIntelligenceResponse | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let isMounted = true;
    async function fetchData() {
      try {
        setIsLoading(true);
        let response: unknown = null;
        try {
            response = await getCaseIPIntelligence(caseId);
        } catch (e: unknown) {
            if ((e as { status?: number }).status === 404) {
                // Try post if not found
                response = await enrichCaseIPIntelligence(caseId);
            } else {
                throw e;
            }
        }
        
        if (!response || !(response as CaseIPIntelligenceResponse).ip_intelligence || (response as CaseIPIntelligenceResponse).ip_intelligence.length === 0) {
             // Fallback
             try {
                response = await enrichCaseIPIntelligence(caseId);
             } catch (postErr: unknown) {}
        }
        
        if (isMounted && response) {
          setData(response as CaseIPIntelligenceResponse);
        }
      } catch (err: unknown) {
        if (isMounted) {
          setError((err as Error).message || "Failed to load IP Intelligence");
        }
      } finally {
        if (isMounted) setIsLoading(false);
      }
    }
    fetchData();
    return () => { isMounted = false; };
  }, [caseId]);

  if (isLoading) {
    return (
      <Card>
        <CardContent className="p-6 text-center text-slate-500">
          Loading Infrastructure Intelligence...
        </CardContent>
      </Card>
    );
  }

  if (error || !data || data.ip_intelligence.length === 0) {
    return null;
  }

  return (
    <Card className="border-slate-200 shadow-sm mt-6">
      <div className="bg-slate-50 px-4 py-3 border-b border-slate-200 flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Server className="h-5 w-5 text-slate-600" />
          <h3 className="font-semibold text-slate-800">Infrastructure Intelligence (Provider Derived)</h3>
        </div>
        <div className="flex items-center gap-2">
          <Badge variant="neutral" className="text-xs bg-slate-200 text-slate-700 font-mono">
            ⚡ ThreatFox & MaxMind GeoLite2
          </Badge>
        </div>
      </div>
      <CardContent className="p-0">
        <div className="overflow-x-auto">
          <Table>
            <Thead>
              <Tr>
                <Th>IP Address</Th>
                <Th>Location</Th>
                <Th>Network / ASN</Th>
                <Th>Reputation</Th>
                <Th>Flags</Th>
              </Tr>
            </Thead>
            <Tbody>
              {data.ip_intelligence.map((ipData, idx) => (
                <Tr key={idx} className="hover:bg-slate-50">
                  <Td className="font-mono text-sm font-medium">{ipData.ip_address}</Td>
                  <Td>
                    <div className="flex items-center gap-2">
                      <MapPin className="h-4 w-4 text-slate-400" />
                      <span className="text-sm">
                        {ipData.city ? ipData.city + ", " : ""}
                        {ipData.country || "Unknown"}
                      </span>
                    </div>
                  </Td>
                  <Td>
                    <div className="flex items-center gap-2">
                      <Building className="h-4 w-4 text-slate-400" />
                      <div className="flex flex-col">
                        <span className="text-sm font-medium">{ipData.organization || "Unknown"}</span>
                        <span className="text-xs text-slate-500">ASN: {ipData.asn || "Unknown"}</span>
                      </div>
                    </div>
                  </Td>
                  <Td>
                    {ipData.reputation === "Malicious" || (ipData.abuse_threat_score && ipData.abuse_threat_score > 0) ? (
                      <div className="flex items-center gap-1 text-red-600">
                        <ShieldAlert className="h-4 w-4" />
                        <span className="text-sm font-medium">Poor ({ipData.abuse_threat_score?.toFixed(1) || 0})</span>
                      </div>
                    ) : (
                      <div className="flex items-center gap-1 text-green-600">
                        <ShieldCheck className="h-4 w-4" />
                        <span className="text-sm font-medium">Clean</span>
                      </div>
                    )}
                  </Td>
                  <Td>
                    <div className="flex flex-wrap gap-1">
                      {ipData.hosting_provider && <Badge variant="info" className="text-xs">Hosting</Badge>}
                      {ipData.proxy_vpn_indicator && <Badge variant="warning" className="text-xs">Proxy/VPN</Badge>}
                      {ipData.tor_indicator && <Badge variant="danger" className="text-xs">TOR</Badge>}
                      {!ipData.hosting_provider && !ipData.proxy_vpn_indicator && !ipData.tor_indicator && (
                        <span className="text-xs text-slate-400">-</span>
                      )}
                    </div>
                  </Td>
                </Tr>
              ))}
            </Tbody>
          </Table>
        </div>
      </CardContent>
    </Card>
  );
}
