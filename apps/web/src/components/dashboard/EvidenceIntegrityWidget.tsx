"use client";

import React, { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  Box,
  Button,
  Card,
  CardContent,
  Chip,
  Divider,
  IconButton,
  LinearProgress,
  Stack,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Tooltip,
  Typography,
  Alert,
} from "@mui/material";
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
      return (
        <Chip
          label="UNVERIFIED (STORED)"
          size="small"
          sx={{
            bgcolor: "rgba(148, 163, 184, 0.1)",
            color: "text.secondary",
            fontWeight: 600,
            fontSize: "0.7rem",
          }}
        />
      );
    }

    if (verResult.status === "VERIFIED") {
      return (
        <Chip
          icon={<ShieldCheck size={14} className="text-[#237A57]" />}
          label="AUTHENTIC &bull; SHA-256 MATCH"
          size="small"
          sx={{
            bgcolor: "rgba(16, 185, 129, 0.12)",
            color: "#237A57",
            border: "1px solid rgba(16, 185, 129, 0.3)",
            fontWeight: 700,
            fontSize: "0.7rem",
          }}
        />
      );
    }

    if (verResult.status === "CORRUPTED") {
      return (
        <Chip
          icon={<ShieldAlert size={14} className="text-[#C53030]" />}
          label="CORRUPTED / TAMPERED"
          size="small"
          sx={{
            bgcolor: "rgba(244, 63, 94, 0.15)",
            color: "#C53030",
            border: "1px solid rgba(244, 63, 94, 0.4)",
            fontWeight: 700,
            fontSize: "0.7rem",
          }}
        />
      );
    }

    return (
      <Chip
        label="MISSING PAYLOAD"
        size="small"
        sx={{
          bgcolor: "rgba(245, 158, 11, 0.12)",
          color: "#fbbf24",
          border: "1px solid rgba(245, 158, 11, 0.3)",
          fontWeight: 700,
          fontSize: "0.7rem",
        }}
      />
    );
  };

  if (isLoading) {
    return (
      <Card sx={{ bgcolor: "background.paper", border: "1px solid", borderColor: "divider", borderRadius: 2 }}>
        <CardContent sx={{ p: 3 }}>
          <Typography variant="body2" color="text.secondary" mb={1}>
            Loading cryptographic evidence chain of custody...
          </Typography>
          <LinearProgress />
        </CardContent>
      </Card>
    );
  }

  if (isError) {
    return (
      <Alert severity="warning" sx={{ borderRadius: 2 }}>
        Unable to load evidence integrity records: {error?.message || "Storage service unreachable"}
      </Alert>
    );
  }

  const records = evidenceData?.records || [];

  return (
    <Card
      sx={{
        bgcolor: "background.paper",
        border: "1px solid",
        borderColor: "divider",
        borderRadius: 2,
        boxShadow: 2,
      }}
    >
      <CardContent sx={{ p: 3 }}>
        {/* Header Bar */}
        <Stack
          direction={{ xs: "column", sm: "row" }}
          justifyContent="space-between"
          alignItems={{ xs: "flex-start", sm: "center" }}
          spacing={2}
          mb={2.5}
        >
          <Box display="flex" alignItems="center" gap={1.5}>
            <Shield className="w-5 h-5 text-[#1F4E79]" />
            <Box>
              <Typography variant="h6" fontWeight={700} color="text.primary">
                Cryptographic Evidence & Chain of Custody
              </Typography>
              <Typography variant="caption" color="text.secondary">
                Deterministic SHA-256 integrity verification across original files and forensic reports
              </Typography>
            </Box>
          </Box>

          <Stack direction="row" spacing={1} alignItems="center">
            <Button
              variant="contained"
              color="primary"
              size="small"
              onClick={() => verifyMutation.mutate()}
              disabled={verifyMutation.isPending}
              startIcon={<FileCheck2 size={14} className={verifyMutation.isPending ? "animate-spin" : ""} />}
              sx={{ textTransform: "none", fontWeight: 700, fontSize: "0.75rem" }}
            >
              {verifyMutation.isPending ? "Verifying Hashes..." : "Verify Chain of Custody"}
            </Button>

            <Tooltip title="Refresh evidence list">
              <IconButton onClick={() => refetch()} size="small" sx={{ border: "1px solid", borderColor: "divider" }}>
                <RefreshCw size={14} className={isLoading ? "animate-spin text-[#1F4E79]" : ""} />
              </IconButton>
            </Tooltip>
          </Stack>
        </Stack>

        {/* Verification Summary Banner if performed */}
        {verificationData && (
          <Box mb={2.5}>
            {verificationData.all_valid ? (
              <Alert
                severity="success"
                icon={<ShieldCheck size={18} />}
                sx={{
                  bgcolor: "rgba(16, 185, 129, 0.08)",
                  border: "1px solid rgba(16, 185, 129, 0.25)",
                  color: "#237A57",
                  "& .MuiAlert-icon": { color: "#237A57" },
                }}
              >
                <Typography variant="subtitle2" fontWeight={700}>
                  Chain of Custody Intact & Verified Authentic
                </Typography>
                <Typography variant="caption" display="block">
                  All {verificationData.total_verified} evidence artifact(s) matched their recorded SHA-256 cryptographic digests byte-for-byte.
                </Typography>
              </Alert>
            ) : (
              <Alert
                severity="error"
                icon={<ShieldAlert size={18} />}
                sx={{
                  bgcolor: "rgba(244, 63, 94, 0.1)",
                  border: "1px solid rgba(244, 63, 94, 0.3)",
                  color: "#C53030",
                  "& .MuiAlert-icon": { color: "#C53030" },
                }}
              >
                <Typography variant="subtitle2" fontWeight={700}>
                  Integrity Verification Failure Detected
                </Typography>
                <Typography variant="caption" display="block">
                  One or more evidence artifacts failed SHA-256 cryptographic verification. Potential data corruption or unauthorized tampering.
                </Typography>
              </Alert>
            )}
          </Box>
        )}

        <Divider sx={{ mb: 2 }} />

        {/* Evidence Records Table */}
        {records.length === 0 ? (
          <Typography variant="body2" color="text.secondary" textAlign="center" py={3}>
            No cryptographic evidence records registered for this investigation case yet.
          </Typography>
        ) : (
          <TableContainer>
            <Table size="small">
              <TableHead>
                <TableRow sx={{ bgcolor: "rgba(255, 255, 255, 0.02)" }}>
                  <TableCell sx={{ color: "text.secondary", fontWeight: 700, fontSize: "0.75rem" }}>
                    EVIDENCE ARTIFACT
                  </TableCell>
                  <TableCell sx={{ color: "text.secondary", fontWeight: 700, fontSize: "0.75rem" }}>
                    ALGORITHM
                  </TableCell>
                  <TableCell sx={{ color: "text.secondary", fontWeight: 700, fontSize: "0.75rem" }}>
                    SHA-256 CRYPTOGRAPHIC DIGEST
                  </TableCell>
                  <TableCell sx={{ color: "text.secondary", fontWeight: 700, fontSize: "0.75rem" }}>
                    SIZE / TIMESTAMP
                  </TableCell>
                  <TableCell align="right" sx={{ color: "text.secondary", fontWeight: 700, fontSize: "0.75rem" }}>
                    CUSTODY STATUS
                  </TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {records.map((rec) => {
                  const verResult = getVerificationStatusForResult(rec.evidence_type);
                  return (
                    <TableRow
                      key={rec.id}
                      hover
                      sx={{
                        "&:hover": { bgcolor: "rgba(255, 255, 255, 0.02)" },
                        transition: "background-color 0.15s ease",
                      }}
                    >
                      {/* Evidence Artifact Name & Type */}
                      <TableCell>
                        <Typography variant="body2" fontWeight={600} color="text.primary">
                          {rec.file_name || rec.evidence_type}
                        </Typography>
                        <Chip
                          label={rec.evidence_type}
                          size="small"
                          sx={{
                            height: 18,
                            fontSize: "0.65rem",
                            fontWeight: 700,
                            bgcolor: "rgba(6, 182, 212, 0.1)",
                            color: "#1F4E79",
                            mt: 0.5,
                          }}
                        />
                      </TableCell>

                      {/* Algorithm */}
                      <TableCell>
                        <Stack direction="row" alignItems="center" spacing={0.5}>
                          <Lock size={12} className="text-[#1F4E79]" />
                          <Typography variant="caption" fontWeight={600} color="text.secondary">
                            SHA-256
                          </Typography>
                        </Stack>
                      </TableCell>

                      {/* SHA-256 Hash with Copy */}
                      <TableCell>
                        <Box display="flex" alignItems="center" gap={1}>
                          <Typography
                            variant="caption"
                            sx={{
                              fontFamily: "monospace",
                              bgcolor: "rgba(0, 0, 0, 0.3)",
                              p: 0.5,
                              borderRadius: 1,
                              border: "1px solid rgba(255, 255, 255, 0.05)",
                              color: "cyan.300",
                              wordBreak: "break-all",
                              maxWidth: 320,
                            }}
                          >
                            {rec.sha256_hash}
                          </Typography>
                          <Tooltip title={copiedHash === rec.sha256_hash ? "Copied!" : "Copy SHA-256"}>
                            <IconButton size="small" onClick={() => handleCopy(rec.sha256_hash)}>
                              {copiedHash === rec.sha256_hash ? (
                                <Check size={14} className="text-[#237A57]" />
                              ) : (
                                <Copy size={14} className="text-slate-400 hover:text-white" />
                              )}
                            </IconButton>
                          </Tooltip>
                        </Box>
                      </TableCell>

                      {/* Size & Timestamp */}
                      <TableCell>
                        <Typography variant="caption" color="text.primary" display="block">
                          {(rec.file_size_bytes / 1024).toFixed(1)} KB ({rec.file_size_bytes} B)
                        </Typography>
                        <Typography variant="caption" color="text.secondary" display="block">
                          {new Date(rec.calculated_at_iso).toUTCString()}
                        </Typography>
                      </TableCell>

                      {/* Custody Status */}
                      <TableCell align="right">{renderStatusBadge(verResult)}</TableCell>
                    </TableRow>
                  );
                })}
              </TableBody>
            </Table>
          </TableContainer>
        )}
      </CardContent>
    </Card>
  );
};
