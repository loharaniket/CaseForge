"use client";

import React, { useEffect, useState } from "react";
import { Link2, ShieldAlert, ShieldCheck, AlertTriangle } from "lucide-react";
import { Card, CardContent, Badge, Table, Thead, Tbody, Tr, Th, Td } from "@/components/ui";
import { getCaseURLIntelligence, enrichCaseURLIntelligence } from "@/lib/api/email";

interface RedirectNode {
  original_url: string;
  status: number | string;
  error?: string;
  hostname?: string;
  resolved_ip?: string;
  order?: number;
  timestamp?: string;
  redirect_url?: string;
  final_url?: string;
}

interface URLIntelligenceRecord {
  raw_url: string;
  scheme: string | null;
  hostname: string | null;
  registrable_domain: string | null;
  path: string | null;
  
  is_raw_ip: boolean;
  is_shortener: boolean;
  has_excessive_subdomains: boolean;
  has_suspicious_path: boolean;
  has_credential_path: boolean;
  is_punycode: boolean;
  has_homoglyphs: boolean;
  is_lookalike: boolean;
  has_suspicious_query: boolean;
  has_mismatch_text: boolean;

  lookalike_target: string | null;
  explanation: string | null;
  reputation: string | null;
  risk_score: number | null;
  redirect_chain?: RedirectNode[] | null;
}

interface CaseURLIntelligenceResponse {
  case_id: string;
  url_intelligence: URLIntelligenceRecord[];
}

interface URLIntelligenceWidgetProps {
  caseId: string;
}

export function URLIntelligenceWidget({ caseId }: URLIntelligenceWidgetProps) {
  const [data, setData] = useState<CaseURLIntelligenceResponse | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let isMounted = true;
    async function fetchData() {
      try {
        setIsLoading(true);
        let response: unknown = null;
        try {
            response = await getCaseURLIntelligence(caseId);
        } catch (e: unknown) {
            if ((e as { status?: number }).status === 404) {
                response = await enrichCaseURLIntelligence(caseId);
            } else {
                throw e;
            }
        }
        
        if (!response || !(response as CaseURLIntelligenceResponse).url_intelligence || (response as CaseURLIntelligenceResponse).url_intelligence.length === 0) {
             try {
                response = await enrichCaseURLIntelligence(caseId);
             } catch (postErr: unknown) {}
        }
        
        if (isMounted && response) {
          setData(response as CaseURLIntelligenceResponse);
        }
      } catch (err: unknown) {
        if (isMounted) {
          setError((err as Error).message || "Failed to load URL Intelligence");
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
          Loading URL Intelligence...
        </CardContent>
      </Card>
    );
  }

  if (error || !data || data.url_intelligence.length === 0) {
    return null;
  }

  return (
    <Card className="border-slate-200 shadow-sm mt-6">
      <div className="bg-slate-50 px-4 py-3 border-b border-slate-200 flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Link2 className="h-5 w-5 text-slate-600" />
          <h3 className="font-semibold text-slate-800">URL Intelligence</h3>
        </div>
        <div className="flex items-center gap-2">
          <Badge variant="neutral" className="text-xs bg-slate-200 text-slate-700 font-mono">
            ⚡ URLhaus & Direct HTTP/HTTPS
          </Badge>
        </div>
      </div>
      <CardContent className="p-0">
        <div className="overflow-x-auto">
          <Table>
            <Thead>
              <Tr>
                <Th>Raw URL</Th>
                <Th>Normalized Domain</Th>
                <Th>Risk Indicators</Th>
                <Th>Lookalike Assessment</Th>
                <Th>Reputation</Th>
                <Th>Redirect Chain</Th>
              </Tr>
            </Thead>
            <Tbody>
              {data.url_intelligence.map((urlData, idx) => (
                <Tr key={idx} className="hover:bg-slate-50">
                  <Td className="font-mono text-xs font-medium max-w-xs truncate" title={urlData.raw_url}>
                    {urlData.raw_url}
                  </Td>
                  <Td>
                    <div className="text-sm">
                      {urlData.hostname || "N/A"}
                    </div>
                  </Td>
                  <Td>
                    <div className="flex flex-wrap gap-1">
                      {urlData.is_shortener && <Badge variant="warning" className="text-xs">Shortener</Badge>}
                      {urlData.is_raw_ip && <Badge variant="warning" className="text-xs">Raw IP</Badge>}
                      {urlData.is_punycode && <Badge variant="danger" className="text-xs">Punycode</Badge>}
                      {urlData.has_excessive_subdomains && <Badge variant="warning" className="text-xs">Subdomains</Badge>}
                      {urlData.has_credential_path && <Badge variant="danger" className="text-xs">Credential Path</Badge>}
                      {urlData.has_suspicious_query && <Badge variant="warning" className="text-xs">Sus Query</Badge>}
                      {!urlData.is_shortener && !urlData.is_raw_ip && !urlData.is_punycode && !urlData.has_credential_path && !urlData.has_suspicious_query && (
                        <span className="text-xs text-slate-400">None detected</span>
                      )}
                    </div>
                  </Td>
                  <Td>
                    {urlData.is_lookalike ? (
                      <div className="flex flex-col gap-1 text-red-600">
                        <div className="flex items-center gap-1 text-xs font-semibold">
                          <AlertTriangle className="h-3 w-3" />
                          <span>Spoofs: {urlData.lookalike_target}</span>
                        </div>
                        <span className="text-[10px] text-slate-500">{urlData.explanation}</span>
                      </div>
                    ) : (
                      <span className="text-xs text-slate-400">Clean</span>
                    )}
                  </Td>
                  <Td>
                    {urlData.reputation === "Malicious" || (urlData.risk_score && urlData.risk_score > 0) ? (
                      <div className="flex items-center gap-1 text-red-600">
                        <ShieldAlert className="h-4 w-4" />
                        <span className="text-sm font-medium">Poor ({urlData.risk_score?.toFixed(1) || 0})</span>
                      </div>
                    ) : (
                      <div className="flex items-center gap-1 text-green-600">
                        <ShieldCheck className="h-4 w-4" />
                        <span className="text-sm font-medium">Clean</span>
                      </div>
                    )}
                  </Td>
                                  <Td>
                    {urlData.redirect_chain && urlData.redirect_chain.length > 0 ? (
                      <div className="flex flex-col gap-1 text-xs">
                        {urlData.redirect_chain.map((node, i) => (
                          <div key={i} className="flex items-center gap-1">
                            <span className="text-slate-400">?</span>
                            <span className="truncate max-w-[200px]" title={(node.redirect_url || node.final_url || node.status) as string}>
                              {node.status === "BLOCKED_SECURITY_POLICY" ? (
                                <span className="text-red-500 font-semibold flex items-center gap-1">
                                  <ShieldAlert className="h-3 w-3"/>
                                  BLOCKED ({node.error})
                                </span>
                              ) : node.redirect_url ? (
                                node.redirect_url
                              ) : node.final_url ? (
                                <span className="text-green-600">Final: {node.final_url}</span>
                              ) : (
                                <span className="text-orange-500">{node.status}</span>
                              )}
                            </span>
                          </div>
                        ))}
                      </div>
                    ) : (
                      <span className="text-xs text-slate-400">No redirects</span>
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
