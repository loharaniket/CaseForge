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
  Button,
  Badge,
  Card,
  Table,
  Thead,
  Tbody,
  Tr,
  Th,
  Td,
  SectionHeader,
  CardHeader,
  CardContent,
} from "@/components/ui";

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
    switch (sev?.toLowerCase()) {
      case "critical":
        return <Badge variant="critical">CRITICAL</Badge>;
      case "high":
        return <Badge variant="danger">HIGH</Badge>;
      case "medium":
        return <Badge variant="warning">MEDIUM</Badge>;
      case "low":
        return <Badge variant="success">LOW</Badge>;
      default:
        return <Badge variant="neutral">ANALYZED</Badge>;
    }
  };

  return (
    <div className="flex flex-col gap-8">
      {/* 1. Header Area */}
      <div className="flex justify-between items-center">
        <SectionHeader 
          title="Investigations" 
          description="Recent Threat Analysis Cases"
          className="mb-0" 
        />
        <Button 
          variant="primary" 
          onClick={() => setIsCreatingNew(true)}
          className="gap-2"
        >
          <FileSearch className="w-4 h-4" />
          <span>New Case</span>
        </Button>
      </div>

      {/* 2. New Investigation Dropzone */}
      {isCreatingNew && !selectedCaseId && (
        <Card>
          <CardHeader className="flex flex-row justify-between items-center">
            <h2 className="text-[16px] font-[650] text-text-primary">Upload Evidence</h2>
            <Button variant="secondary" onClick={() => setIsCreatingNew(false)}>Cancel</Button>
          </CardHeader>
          <CardContent>
            <EmailUploadZone onUploadSuccess={handleUploadSuccess} />
          </CardContent>
        </Card>
      )}

      {/* 3. Live Investigation console */}
      {selectedCaseId && (
        <div className="flex flex-col gap-4">
          <div className="flex justify-between items-center">
            <h2 className="text-[18px] font-[650] text-text-primary flex items-center gap-2">
              <Shield className="w-5 h-5 text-primary" /> 
              Live Investigation: <span className="font-mono text-text-secondary">{selectedCaseId.slice(0,8)}...</span>
            </h2>
            <Button variant="secondary" onClick={() => setSelectedCaseId(null)}>Close View</Button>
          </div>
          <InvestigationDashboard caseId={selectedCaseId} />
        </div>
      )}

      {/* 4. Recent Investigations table */}
      {!selectedCaseId && !isCreatingNew && (
        <Card>
          <CardHeader className="flex flex-row items-center gap-2 py-3 bg-bg-panel-subtle">
            <History className="w-4 h-4 text-text-secondary" />
            <h3 className="text-sm font-[650] text-text-primary">Investigation History</h3>
          </CardHeader>
          <Table className="border-none rounded-none rounded-b-[8px]">
            <Thead>
              <Tr>
                <Th>Case ID</Th>
                <Th>Subject / File</Th>
                <Th>Risk Score</Th>
                <Th>Severity</Th>
                <Th>Upload Time</Th>
                <Th className="text-right">Actions</Th>
              </Tr>
            </Thead>
            <Tbody>
              {recentCases.length === 0 ? (
                <Tr>
                  <Td colSpan={6} className="text-center py-8 text-text-muted">
                    No investigation cases recorded.
                  </Td>
                </Tr>
              ) : (
                recentCases.map((item) => (
                  <Tr key={item.case_id}>
                    <Td className="font-mono text-info font-semibold">
                      {item.case_id.slice(0, 12)}...
                    </Td>
                    <Td className="max-w-[300px] truncate" title={item.subject || item.file_name}>
                      {item.subject || item.file_name}
                    </Td>
                    <Td>
                      <span className="font-mono font-medium">
                        {item.risk_score !== undefined ? `${item.risk_score} / 100` : "—"}
                      </span>
                    </Td>
                    <Td>{renderSeverityBadge(item.severity)}</Td>
                    <Td>
                      <span className="text-text-secondary text-xs block">
                        {new Date(item.created_at).toLocaleDateString()}
                      </span>
                      <span className="text-text-muted text-[11px] block mt-0.5">
                        {new Date(item.created_at).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })}
                      </span>
                    </Td>
                    <Td className="text-right">
                      <Button 
                        variant="secondary" 
                        onClick={() => setSelectedCaseId(item.case_id)}
                        className="h-7 px-3 text-xs gap-1.5"
                      >
                        <Eye className="w-3.5 h-3.5" />
                        <span>Inspect</span>
                      </Button>
                    </Td>
                  </Tr>
                ))
              )}
            </Tbody>
          </Table>
        </Card>
      )}
    </div>
  );
}
