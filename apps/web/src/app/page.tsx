"use client";

import React, { useState, useEffect } from "react";
import { EmailUploadZone } from "@/components/investigation/EmailUploadZone";
import { InvestigationDashboard } from "@/components/dashboard/InvestigationDashboard";
import { EmailUploadResponse } from "@/types";
import {
  Shield,
  FileSearch,
  History,
  Eye,
} from "lucide-react";
import { 
  Box, 
  Button, 
  Typography, 
  Paper, 
  Table, 
  TableBody, 
  TableCell, 
  TableContainer, 
  TableHead, 
  TableRow,
  Chip
} from "@mui/material";

interface RecentCaseItem {
  case_id: string;
  file_name: string;
  subject?: string;
  classification?: string;
  risk_score?: number;
  severity?: string;
  created_at: string;
  sha256?: string;
}

export default function HomePage() {
  const [selectedCaseId, setSelectedCaseId] = useState<string | null>(null);
  const [recentCases, setRecentCases] = useState<RecentCaseItem[]>([]);
  const [isCreatingNew, setIsCreatingNew] = useState(false);

  useEffect(() => {
    try {
      const stored = localStorage.getItem("threattrace_recent_cases");
      if (stored) {
        setRecentCases(JSON.parse(stored));
      } else {
        const demoCases: RecentCaseItem[] = [
          {
            case_id: "demo-phish-case-001",
            file_name: "urgent_invoice_request.eml",
            subject: "URGENT: Executive Wire Transfer Authorization Required",
            classification: "PHISHING",
            risk_score: 88,
            severity: "CRITICAL",
            created_at: new Date().toISOString(),
            sha256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
          },
        ];
        setRecentCases(demoCases);
      }
    } catch {
      // Ignore
    }
  }, []);

  const handleUploadSuccess = (response: EmailUploadResponse) => {
    setSelectedCaseId(response.case_id);
    setIsCreatingNew(false);

    const newCase: RecentCaseItem = {
      case_id: response.case_id,
      file_name: response.file_name,
      subject: `Investigation: ${response.file_name}`,
      classification: "ANALYZING",
      risk_score: undefined,
      severity: undefined,
      created_at: response.created_at || new Date().toISOString(),
      sha256: response.sha256,
    };

    setRecentCases((prev) => {
      const filtered = prev.filter((c) => c.case_id !== response.case_id);
      const updated = [newCase, ...filtered].slice(0, 10);
      try {
        localStorage.setItem("threattrace_recent_cases", JSON.stringify(updated));
      } catch {
        // Ignore
      }
      return updated;
    });
  };

  const renderSeverityBadge = (sev?: string) => {
    let bg = "#F5F7FA";
    let color = "#52606D";
    let label = "ANALYZED";
    switch (sev?.toLowerCase()) {
      case "critical":
      case "high":
        bg = "#FDECEC";
        color = "#C53030";
        label = sev.toUpperCase();
        break;
      case "medium":
        bg = "#FFF7E6";
        color = "#975A16";
        label = "MEDIUM";
        break;
      case "low":
        bg = "#E8F5EF";
        color = "#18533B";
        label = "LOW";
        break;
    }
    return <Chip label={label} size="small" style={{ backgroundColor: bg, color: color, fontWeight: 650 }} />;
  };

  return (
    <Box sx={{ p: 3, maxWidth: 1440, mx: "auto", display: "flex", flexDirection: "column", gap: 4 }}>
      
      {/* 1. Header Area */}
      <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "center", mb: 3 }}>
        <Box>
          <Typography variant="h1" sx={{ display: "flex", alignItems: "center", gap: 1 }}>
            Investigations
          </Typography>
          <Typography variant="body2" color="text.secondary">
            Recent Threat Analysis Cases
          </Typography>
        </Box>
        <Box sx={{ display: "flex", gap: 2 }}>
          <Button 
            variant="contained" 
            color="primary" 
            startIcon={<FileSearch size={16} />}
            onClick={() => setIsCreatingNew(true)}
          >
            New Case
          </Button>
        </Box>
      </Box>

      {/* 2. New Investigation Dropzone */}
      {isCreatingNew && !selectedCaseId && (
        <Box sx={{ mb: 4 }}>
          <Paper elevation={0} sx={{ p: 4 }}>
            <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "center", mb: 3 }}>
              <Typography variant="h2" sx={{ fontSize: "18px" }}>Upload Evidence</Typography>
              <Button size="small" onClick={() => setIsCreatingNew(false)}>Cancel</Button>
            </Box>
            <EmailUploadZone onUploadSuccess={handleUploadSuccess} />
          </Paper>
        </Box>
      )}

      {/* 3. Live Investigation console */}
      {selectedCaseId && (
        <Box sx={{ mb: 4 }}>
          <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "center", mb: 2 }}>
            <Typography variant="h2" sx={{ fontSize: "18px", display: "flex", alignItems: "center", gap: 1 }}>
              <Shield size={18} color="#1F4E79" /> Live Investigation: {selectedCaseId.slice(0,8)}...
            </Typography>
            <Button size="small" onClick={() => setSelectedCaseId(null)}>Close View</Button>
          </Box>
          <InvestigationDashboard caseId={selectedCaseId} />
        </Box>
      )}

      {/* 4. Recent Investigations table */}
      {!selectedCaseId && !isCreatingNew && (
        <Paper elevation={0}>
          <Box sx={{ p: 2, display: "flex", alignItems: "center", gap: 1, borderBottom: "1px solid #D9E0E7" }}>
            <History size={18} color="#52606D" />
            <Typography variant="subtitle1">Investigation History</Typography>
          </Box>
          <TableContainer>
            <Table>
              <TableHead>
                <TableRow>
                  <TableCell>Case ID</TableCell>
                  <TableCell>Subject / File</TableCell>
                  <TableCell>Risk Score</TableCell>
                  <TableCell>Severity</TableCell>
                  <TableCell>Upload Time</TableCell>
                  <TableCell align="right">Actions</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {recentCases.length === 0 ? (
                  <TableRow>
                    <TableCell colSpan={6} align="center" sx={{ py: 4, color: "text.secondary" }}>
                      No investigation cases recorded.
                    </TableCell>
                  </TableRow>
                ) : (
                  recentCases.map((item) => (
                    <TableRow key={item.case_id}>
                      <TableCell sx={{ fontFamily: "monospace", color: "#1F4E79", fontWeight: 600 }}>
                        {item.case_id.slice(0, 12)}...
                      </TableCell>
                      <TableCell sx={{ maxWidth: 300, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                        {item.subject || item.file_name}
                      </TableCell>
                      <TableCell>
                        <Typography variant="body2" sx={{ fontFamily: "monospace" }}>
                          {item.risk_score !== undefined ? `${item.risk_score} / 100` : "—"}
                        </Typography>
                      </TableCell>
                      <TableCell>{renderSeverityBadge(item.severity)}</TableCell>
                      <TableCell>
                        <Typography variant="body2" sx={{ color: "text.secondary" }}>
                          {new Date(item.created_at).toLocaleDateString()} {new Date(item.created_at).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })}
                        </Typography>
                      </TableCell>
                      <TableCell align="right">
                        <Button 
                          variant="outlined" 
                          size="small"
                          onClick={() => setSelectedCaseId(item.case_id)}
                          startIcon={<Eye size={14} />}
                        >
                          Inspect
                        </Button>
                      </TableCell>
                    </TableRow>
                  ))
                )}
              </TableBody>
            </Table>
          </TableContainer>
        </Paper>
      )}
    </Box>
  );
}
