"use client";

import React, { useEffect, useState } from "react";
import { Globe, ShieldAlert, ShieldCheck, Clock, CheckCircle } from "lucide-react";
import { Card, CardContent, Badge, Table, Thead, Tbody, Tr, Th, Td } from "@/components/ui";
import { getCaseDomainIntelligence, enrichCaseDomainIntelligence } from "@/lib/api/email";

interface DomainIntelligenceRecord {
  domain: string;
  registrar: string | null;
  creation_date: string | null;
  expiration_date: string | null;
  nameservers: string[];
  a_records: string[];
  aaaa_records: string[];
  mx_records: string[];
  txt_records: string[];
  spf_record: string | null;
  dmarc_record: string | null;
  reputation: string | null;
  risk_score: number | null;
}

interface CaseDomainIntelligenceResponse {
  case_id: string;
  domain_intelligence: DomainIntelligenceRecord[];
}

interface DomainIntelligenceWidgetProps {
  caseId: string;
}

export function DomainIntelligenceWidget({ caseId }: DomainIntelligenceWidgetProps) {
  const [data, setData] = useState<CaseDomainIntelligenceResponse | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let isMounted = true;
    async function fetchData() {
      try {
        setIsLoading(true);
        let response: unknown = null;
        try {
            response = await getCaseDomainIntelligence(caseId);
        } catch (e: unknown) {
            if ((e as { status?: number }).status === 404) {
                response = await enrichCaseDomainIntelligence(caseId);
            } else {
                throw e;
            }
        }
        
        if (!response || !(response as CaseDomainIntelligenceResponse).domain_intelligence || (response as CaseDomainIntelligenceResponse).domain_intelligence.length === 0) {
             try {
                response = await enrichCaseDomainIntelligence(caseId);
             } catch (postErr: unknown) {}
        }
        
        if (isMounted && response) {
          setData(response as CaseDomainIntelligenceResponse);
        }
      } catch (err: unknown) {
        if (isMounted) {
          setError((err as Error).message || "Failed to load Domain Intelligence");
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
          Loading Domain Intelligence...
        </CardContent>
      </Card>
    );
  }

  if (error || !data || data.domain_intelligence.length === 0) {
    return null;
  }

  return (
    <Card className="border-slate-200 shadow-sm mt-6">
      <div className="bg-slate-50 px-4 py-3 border-b border-slate-200 flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Globe className="h-5 w-5 text-slate-600" />
          <h3 className="font-semibold text-slate-800">Domain Intelligence</h3>
        </div>
        <div className="flex items-center gap-2">
          <Badge variant="neutral" className="text-xs bg-slate-200 text-slate-700 font-mono">
            ⚡ ThreatFox & Cloudflare DNS (1.1.1.1)
          </Badge>
        </div>
      </div>
      <CardContent className="p-0">
        <div className="overflow-x-auto">
          <Table>
            <Thead>
              <Tr>
                <Th>Domain</Th>
                <Th>Registrar / Age</Th>
                <Th>DNS / MX</Th>
                <Th>Security Signals</Th>
                <Th>Reputation</Th>
              </Tr>
            </Thead>
            <Tbody>
              {data.domain_intelligence.map((domainData, idx) => (
                <Tr key={idx} className="hover:bg-slate-50">
                  <Td className="font-mono text-sm font-medium">{domainData.domain}</Td>
                  <Td>
                    <div className="flex flex-col gap-1">
                      <span className="text-sm">{domainData.registrar || "Unknown Registrar"}</span>
                      {domainData.creation_date && (
                        <div className="flex items-center gap-1 text-slate-500 text-xs">
                          <Clock className="h-3 w-3" />
                          <span>{new Date(domainData.creation_date).toLocaleDateString()}</span>
                        </div>
                      )}
                    </div>
                  </Td>
                  <Td>
                    <div className="flex flex-col gap-1 text-xs">
                      {domainData.a_records.length > 0 && (
                        <div><span className="font-semibold text-slate-500">A:</span> {domainData.a_records.slice(0, 2).join(', ')}{domainData.a_records.length > 2 ? ' ...' : ''}</div>
                      )}
                      {domainData.mx_records.length > 0 && (
                        <div><span className="font-semibold text-slate-500">MX:</span> {domainData.mx_records.slice(0, 2).join(', ')}{domainData.mx_records.length > 2 ? ' ...' : ''}</div>
                      )}
                    </div>
                  </Td>
                  <Td>
                    <div className="flex flex-wrap gap-1">
                      {domainData.spf_record ? <Badge variant="success" className="text-xs">SPF</Badge> : <Badge variant="neutral" className="text-xs">No SPF</Badge>}
                      {domainData.dmarc_record ? <Badge variant="success" className="text-xs">DMARC</Badge> : <Badge variant="neutral" className="text-xs">No DMARC</Badge>}
                    </div>
                  </Td>
                  <Td>
                    {domainData.reputation === "Malicious" || (domainData.risk_score && domainData.risk_score > 0) ? (
                      <div className="flex items-center gap-1 text-red-600">
                        <ShieldAlert className="h-4 w-4" />
                        <span className="text-sm font-medium">Poor ({domainData.risk_score?.toFixed(1) || 0})</span>
                      </div>
                    ) : (
                      <div className="flex items-center gap-1 text-green-600">
                        <ShieldCheck className="h-4 w-4" />
                        <span className="text-sm font-medium">Clean</span>
                      </div>
                    )}
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
