"use client";

import React, { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  Shield,
  ShieldCheck,
  ShieldAlert,
  Copy,
  Check,
  RefreshCw,
  FileCheck2,
  Lock,
} from "lucide-react";
import { getCaseEvidence, verifyCaseEvidence } from "@/lib/api/email";
import {
  CaseEvidenceListResponse,
  CaseEvidenceVerificationResponse,
  EvidenceVerificationResult,
} from "@/types";
import { Card, CardContent, CardHeader, Button, Badge, Table, Thead, Tbody, Tr, Th, Td, LoadingState } from "@/components/ui";

interface EvidenceIntegrityWidgetProps {
  caseId: string;
}

export const EvidenceIntegrityWidget: React.FC<EvidenceIntegrityWidgetProps> = ({ caseId }) => {
  const queryClient = useQueryClient();
  const [copiedHash, setCopiedHash] = useState<string | null>(null);
  const [verificationData, setVerificationData] = useState<CaseEvidenceVerificationResponse | null>(null);

  const {
    data: evidenceData,
    isLoading,
    isError,
    error,
    refetch,
  } = useQuery<CaseEvidenceListResponse, Error>({
    queryKey: ["case_evidence", caseId],
    queryFn: () => getCaseEvidence(caseId),
    enabled: !!caseId,
  });

  const verifyMutation = useMutation<CaseEvidenceVerificationResponse, Error, void>({
    mutationFn: () => verifyCaseEvidence(caseId),
    onSuccess: (data) => {
      setVerificationData(data);
      queryClient.invalidateQueries({ queryKey: ["case_evidence", caseId] });
    },
  });

  const handleCopy = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopiedHash(text);
    setTimeout(() => setCopiedHash(null), 2000);
  };

  const getVerificationStatusForResult = (evType: string): EvidenceVerificationResult | undefined => {
    return verificationData?.results.find((r) => r.evidence_type === evType);
  };

  const renderStatusBadge = (verResult?: EvidenceVerificationResult) => {
    if (!verResult) {
      return <Badge variant="neutral" className="text-[10px]">UNVERIFIED (STORED)</Badge>;
    }

    if (verResult.status === "VERIFIED") {
      return (
        <Badge variant="success" className="gap-1 px-2 py-0.5 text-[10px]">
          <ShieldCheck className="w-3 h-3" />
          AUTHENTIC &bull; SHA-256 MATCH
        </Badge>
      );
    }

    if (verResult.status === "CORRUPTED") {
      return (
        <Badge variant="danger" className="gap-1 px-2 py-0.5 text-[10px]">
          <ShieldAlert className="w-3 h-3" />
          CORRUPTED / TAMPERED
        </Badge>
      );
    }

    return (
      <Badge variant="warning" className="gap-1 px-2 py-0.5 text-[10px]">
        <ShieldAlert className="w-3 h-3" />
        MISSING PAYLOAD
      </Badge>
    );
  };

  if (isLoading) {
    return <LoadingState message="Loading cryptographic evidence chain of custody..." />;
  }

  if (isError) {
    return (
      <div className="p-4 bg-warning-bg border border-warning rounded-[8px] text-warning-dark text-sm">
        Unable to load evidence integrity records: {error?.message || "Storage service unreachable"}
      </div>
    );
  }

  const records = evidenceData?.records || [];

  return (
    <Card>
      <CardContent className="p-6">
        {/* Header Bar */}
        <div className="flex flex-col sm:flex-row justify-between sm:items-center gap-4 mb-6 pb-4 border-b border-border">
          <div className="flex items-center gap-3">
            <Shield className="w-6 h-6 text-primary" />
            <div className="flex flex-col">
              <h3 className="text-[16px] font-[700] text-text-primary">
                Cryptographic Evidence & Chain of Custody
              </h3>
              <span className="text-[12px] text-text-secondary">
                Deterministic SHA-256 integrity verification across original files and forensic reports
              </span>
            </div>
          </div>

          <div className="flex items-center gap-2">
            <Button
              variant="primary"
              onClick={() => verifyMutation.mutate()}
              disabled={verifyMutation.isPending}
              className="gap-2 px-3 py-1.5 h-auto text-xs"
            >
              <FileCheck2 className={`w-3.5 h-3.5 ${verifyMutation.isPending ? "animate-spin" : ""}`} />
              <span>{verifyMutation.isPending ? "Verifying Hashes..." : "Verify Chain of Custody"}</span>
            </Button>

            <Button variant="secondary" onClick={() => refetch()} className="px-2 h-auto py-1.5" title="Refresh evidence list">
              <RefreshCw className={`w-3.5 h-3.5 ${isLoading ? "animate-spin text-primary" : "text-text-secondary"}`} />
            </Button>
          </div>
        </div>

        {/* Verification Summary Banner if performed */}
        {verificationData && (
          <div className="mb-6">
            {verificationData.all_valid ? (
              <div className="flex items-start gap-3 p-4 bg-success-bg border border-success rounded-[8px]">
                <ShieldCheck className="w-5 h-5 text-success mt-0.5 shrink-0" />
                <div className="flex flex-col">
                  <span className="text-[14px] font-[700] text-success-dark">
                    Chain of Custody Intact & Verified Authentic
                  </span>
                  <span className="text-[12px] text-success-dark opacity-90 mt-1">
                    All {verificationData.total_verified} evidence artifact(s) matched their recorded SHA-256 cryptographic digests byte-for-byte.
                  </span>
                </div>
              </div>
            ) : (
              <div className="flex items-start gap-3 p-4 bg-danger-bg border border-danger rounded-[8px]">
                <ShieldAlert className="w-5 h-5 text-danger mt-0.5 shrink-0" />
                <div className="flex flex-col">
                  <span className="text-[14px] font-[700] text-critical">
                    Integrity Verification Failure Detected
                  </span>
                  <span className="text-[12px] text-critical opacity-90 mt-1">
                    One or more evidence artifacts failed SHA-256 cryptographic verification. Potential data corruption or unauthorized tampering.
                  </span>
                </div>
              </div>
            )}
          </div>
        )}

        {/* Evidence Records Table */}
        {records.length === 0 ? (
          <p className="text-sm text-text-muted text-center py-6">
            No cryptographic evidence records registered for this investigation case yet.
          </p>
        ) : (
          <div className="border border-border rounded-[8px] overflow-hidden">
            <Table className="border-none rounded-none">
              <Thead>
                <Tr className="bg-bg-panel-subtle border-b border-border">
                  <Th className="text-[10px]">EVIDENCE ARTIFACT</Th>
                  <Th className="text-[10px]">ALGORITHM</Th>
                  <Th className="text-[10px]">SHA-256 CRYPTOGRAPHIC DIGEST</Th>
                  <Th className="text-[10px]">SIZE / TIMESTAMP</Th>
                  <Th className="text-[10px] text-right">CUSTODY STATUS</Th>
                </Tr>
              </Thead>
              <Tbody>
                {records.map((rec) => {
                  const verResult = getVerificationStatusForResult(rec.evidence_type);
                  return (
                    <Tr key={rec.id}>
                      {/* Evidence Artifact Name & Type */}
                      <Td className="align-top">
                        <div className="flex flex-col gap-1">
                          <span className="text-[13px] font-[600] text-text-primary">
                            {rec.file_name || rec.evidence_type}
                          </span>
                          <span className="text-[10px] font-[700] text-primary bg-primary-soft px-1.5 py-0.5 rounded w-fit">
                            {rec.evidence_type}
                          </span>
                        </div>
                      </Td>

                      {/* Algorithm */}
                      <Td className="align-top">
                        <div className="flex items-center gap-1.5 mt-0.5">
                          <Lock className="w-3 h-3 text-primary" />
                          <span className="text-[11px] font-[650] text-text-secondary">SHA-256</span>
                        </div>
                      </Td>

                      {/* SHA-256 Hash with Copy */}
                      <Td className="align-top">
                        <div className="flex items-start gap-2">
                          <span className="text-[11px] font-mono bg-bg-panel-subtle px-2 py-1 rounded border border-border text-info break-all max-w-[320px]">
                            {rec.sha256_hash}
                          </span>
                          <button 
                            onClick={() => handleCopy(rec.sha256_hash)}
                            className="p-1 hover:bg-bg-panel-subtle rounded text-text-secondary hover:text-text-primary transition-colors"
                            title={copiedHash === rec.sha256_hash ? "Copied!" : "Copy SHA-256"}
                          >
                            {copiedHash === rec.sha256_hash ? (
                              <Check className="w-3.5 h-3.5 text-success" />
                            ) : (
                              <Copy className="w-3.5 h-3.5" />
                            )}
                          </button>
                        </div>
                      </Td>

                      {/* Size & Timestamp */}
                      <Td className="align-top">
                        <div className="flex flex-col gap-0.5">
                          <span className="text-[11px] text-text-primary font-mono">
                            {(rec.file_size_bytes / 1024).toFixed(1)} KB <span className="text-text-muted">({rec.file_size_bytes} B)</span>
                          </span>
                          <span className="text-[10px] text-text-secondary mt-1">
                            {new Date(rec.calculated_at_iso).toUTCString()}
                          </span>
                        </div>
                      </Td>

                      {/* Custody Status */}
                      <Td className="align-top text-right">
                        <div className="flex justify-end mt-0.5">
                          {renderStatusBadge(verResult)}
                        </div>
                      </Td>
                    </Tr>
                  );
                })}
              </Tbody>
            </Table>
          </div>
        )}
      </CardContent>
    </Card>
  );
};
