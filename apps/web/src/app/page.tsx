import React, { useState, useEffect, useMemo } from "react";
import { useParams, useNavigate, useLocation, Link } from "react-router-dom";
import { EmailUploadZone } from "@/components/investigation/EmailUploadZone";
import { InvestigationDashboard } from "@/components/dashboard/InvestigationDashboard";
import { EmailUploadResponse } from "@/types";
import {
  Shield,
  History,
  Eye,
  Trash2,
  UploadCloud,
  FileCheck,
  Search,
  ArrowRight,
  Plus,
} from "lucide-react";
import {
  Button,
  Card,
  CardHeader,
  CardContent,
  Table,
  Thead,
  Tbody,
  Tr,
  Th,
  Td,
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
  const params = useParams<{ caseId?: string }>();
  const navigate = useNavigate();
  const location = useLocation();

  const [recentCases, setRecentCases] = useState<RecentCaseItem[]>([]);
  const [searchTerm, setSearchTerm] = useState("");

  // Pure route param: if on /investigation/:caseId it shows the case
  const activeCaseId = params.caseId || null;
  const isInvestigationsView = location.pathname === "/investigations";

  // Load ONLY real cases uploaded by analyst; purge any legacy demo data
  useEffect(() => {
    try {
      const stored = localStorage.getItem("threattrace_recent_cases");
      if (stored) {
        const parsed = JSON.parse(stored);
        // Exclude any legacy dummy demo cases
        const realCases = Array.isArray(parsed)
          ? parsed.filter((c: RecentCaseItem) => !c.case_id.startsWith("demo-"))
          : [];
        setRecentCases(realCases);
        localStorage.setItem("threattrace_recent_cases", JSON.stringify(realCases));
      } else {
        setRecentCases([]);
      }
    } catch {
      setRecentCases([]);
    }
  }, []);

  const handleUploadSuccess = (response: EmailUploadResponse) => {
    navigate(`/investigation/${response.case_id}`);

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
      const filtered = prev.filter((c) => c.case_id !== response.case_id && !c.case_id.startsWith("demo-"));
      const updated = [newCase, ...filtered].slice(0, 50);
      try {
        localStorage.setItem("threattrace_recent_cases", JSON.stringify(updated));
      } catch {
        // Ignore storage error
      }
      return updated;
    });
  };

  const handleSelectCase = (id: string) => {
    navigate(`/investigation/${id}`);
  };

  const handleBackToCases = () => {
    navigate("/investigations");
  };

  const handleClearHistory = () => {
    setRecentCases([]);
    try {
      localStorage.removeItem("threattrace_recent_cases");
    } catch {
      // Ignore
    }
  };

  // Filtered cases for the registry search
  const filteredCases = useMemo(() => {
    if (!searchTerm.trim()) return recentCases;
    const term = searchTerm.toLowerCase();
    return recentCases.filter(
      (c) =>
        c.file_name.toLowerCase().includes(term) ||
        c.case_id.toLowerCase().includes(term)
    );
  }, [recentCases, searchTerm]);

  // If a case is active, display the full SOC investigation dashboard
  if (activeCaseId) {
    return (
      <InvestigationDashboard
        caseId={activeCaseId}
        onBack={handleBackToCases}
      />
    );
  }

  // VIEW 1: Dedicated Investigations Registry (/investigations)
  if (isInvestigationsView) {
    return (
      <div className="flex flex-col gap-6 max-w-5xl mx-auto w-full">
        {/* Registry Header */}
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-2 border-b border-border">
          <div>
            <h1 className="text-xl font-bold text-text-primary flex items-center gap-2">
              <History className="w-5 h-5 text-primary" />
              <span>Investigation Registry</span>
            </h1>
            <p className="text-xs text-text-secondary mt-0.5">
              Review and inspect forensic analysis reports from all parsed email evidence.
            </p>
          </div>
          <Button
            variant="primary"
            onClick={() => navigate("/new-investigation")}
            className="gap-2 text-xs font-bold w-fit"
          >
            <Plus className="w-4 h-4" />
            <span>New Investigation</span>
          </Button>
        </div>

        {/* Search & Actions Bar */}
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <div className="relative flex-1 max-w-md">
            <Search className="w-4 h-4 text-text-muted absolute left-3 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              placeholder="Search investigations by filename or Case ID..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="w-full pl-9 pr-3 py-1.5 text-xs rounded-lg bg-bg-panel border border-border text-text-primary placeholder:text-text-muted focus:outline-none focus:border-primary transition-colors"
            />
          </div>

          {recentCases.length > 0 && (
            <div className="flex items-center gap-2">
              <span className="text-xs text-text-secondary">
                {filteredCases.length} of {recentCases.length} cases
              </span>
              <Button
                variant="secondary"
                onClick={handleClearHistory}
                className="gap-1 text-[11px] py-1 h-auto text-text-muted hover:text-danger"
                title="Clear investigation history"
              >
                <Trash2 className="w-3 h-3" />
                <span>Clear All</span>
              </Button>
            </div>
          )}
        </div>

        {/* Registry Table Card */}
        <Card className="shadow-sm border-border bg-bg-panel overflow-hidden">
          <CardContent className="p-0">
            {recentCases.length === 0 ? (
              <div className="py-16 px-4 text-center flex flex-col items-center justify-center">
                <div className="w-12 h-12 rounded-full bg-bg-panel-subtle border border-border flex items-center justify-center mb-3">
                  <FileCheck className="w-6 h-6 text-text-muted opacity-60" />
                </div>
                <h3 className="text-sm font-bold text-text-primary">
                  No investigations recorded yet
                </h3>
                <p className="text-xs text-text-secondary mt-1 max-w-md">
                  Upload an .eml file to inspect SPF/DKIM authentication, header hops, phishing heuristics, and cryptographic custody verification.
                </p>
                <Button
                  variant="primary"
                  onClick={() => navigate("/new-investigation")}
                  className="mt-5 gap-2 text-xs font-bold"
                >
                  <UploadCloud className="w-4 h-4" />
                  <span>Start New Investigation</span>
                </Button>
              </div>
            ) : filteredCases.length === 0 ? (
              <div className="py-12 px-4 text-center flex flex-col items-center justify-center">
                <p className="text-xs font-semibold text-text-primary">
                  No investigations match "{searchTerm}"
                </p>
                <Button
                  variant="secondary"
                  onClick={() => setSearchTerm("")}
                  className="mt-3 text-xs"
                >
                  Reset Filter
                </Button>
              </div>
            ) : (
              <Table className="border-none rounded-none">
                <Thead>
                  <Tr className="bg-bg-panel-subtle/50 border-b border-border text-[11px]">
                    <Th>INVESTIGATION TARGET</Th>
                    <Th className="w-[200px]">INGESTED AT</Th>
                    <Th className="w-[110px] text-right">ACTION</Th>
                  </Tr>
                </Thead>
                <Tbody>
                  {filteredCases.map((item) => (
                    <Tr
                      key={item.case_id}
                      className="cursor-pointer hover:bg-bg-panel-subtle transition-colors"
                      onClick={() => handleSelectCase(item.case_id)}
                    >
                      <Td>
                        <div className="flex flex-col gap-0.5">
                          <span className="text-xs font-bold text-text-primary">
                            {item.file_name}
                          </span>
                          <span className="text-[10px] font-mono text-text-muted">
                            Case ID: {item.case_id}
                          </span>
                        </div>
                      </Td>
                      <Td className="text-xs text-text-secondary">
                        {new Date(item.created_at).toLocaleString()}
                      </Td>
                      <Td className="text-right">
                        <Button
                          variant="secondary"
                          onClick={(e) => {
                            e.stopPropagation();
                            handleSelectCase(item.case_id);
                          }}
                          className="gap-1.5 text-xs py-1 h-auto"
                        >
                          <Eye className="w-3.5 h-3.5 text-primary" />
                          <span>Inspect</span>
                        </Button>
                      </Td>
                    </Tr>
                  ))}
                </Tbody>
              </Table>
            )}
          </CardContent>
        </Card>
      </div>
    );
  }

  // VIEW 2: New Investigation Ingestion (/new-investigation or /)
  return (
    <div className="flex flex-col gap-6 max-w-5xl mx-auto w-full">
      {/* Workspace Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-2 border-b border-border">
        <div>
          <h1 className="text-xl font-bold text-text-primary flex items-center gap-2">
            <Shield className="w-5 h-5 text-primary" />
            <span>Email Forensic Workspace</span>
          </h1>
          <p className="text-xs text-text-secondary mt-0.5">
            Ingest suspicious RFC 822 email files to perform cryptographic verification, header parsing, and AI risk heuristics.
          </p>
        </div>
        {recentCases.length > 0 && (
          <Button
            variant="secondary"
            onClick={() => navigate("/investigations")}
            className="gap-1.5 text-xs text-text-secondary hover:text-white w-fit"
          >
            <History className="w-3.5 h-3.5 text-primary" />
            <span>View All Investigations ({recentCases.length})</span>
            <ArrowRight className="w-3.5 h-3.5 ml-0.5" />
          </Button>
        )}
      </div>

      {/* Primary Action: EML Ingestion Dropzone */}
      <Card className="shadow-sm border-border bg-bg-panel overflow-hidden">
        <CardHeader className="p-4 sm:p-5 bg-bg-panel-subtle border-b border-border flex items-center justify-between">
          <div className="flex items-center gap-2.5">
            <div className="w-8 h-8 rounded-lg bg-primary-soft flex items-center justify-center">
              <UploadCloud className="w-4 h-4 text-primary" />
            </div>
            <div>
              <h2 className="text-sm font-bold text-text-primary">
                Ingest Suspicious Email (.eml)
              </h2>
              <p className="text-[11px] text-text-secondary">
                Drag and drop your raw .eml evidence file or click to browse (max 10MB)
              </p>
            </div>
          </div>
        </CardHeader>
        <CardContent className="p-5 sm:p-6">
          <EmailUploadZone onUploadSuccess={handleUploadSuccess} />
        </CardContent>
      </Card>

      {/* Quick Access to Recent Investigations (if any exist) */}
      {recentCases.length > 0 && (
        <Card className="shadow-sm border-border bg-bg-panel overflow-hidden">
          <CardHeader className="p-4 sm:p-5 bg-bg-panel-subtle border-b border-border flex items-center justify-between">
            <div className="flex items-center gap-2.5">
              <History className="w-4 h-4 text-text-secondary" />
              <h2 className="text-sm font-bold text-text-primary">
                Recent Investigations ({Math.min(recentCases.length, 5)})
              </h2>
            </div>
            <Link
              to="/investigations"
              className="text-xs font-semibold text-primary hover:underline flex items-center gap-1"
            >
              <span>See All ({recentCases.length})</span>
              <ArrowRight className="w-3 h-3" />
            </Link>
          </CardHeader>

          <CardContent className="p-0">
            <Table className="border-none rounded-none">
              <Thead>
                <Tr className="bg-bg-panel-subtle/50 border-b border-border text-[11px]">
                  <Th>INVESTIGATION TARGET</Th>
                  <Th className="w-[180px]">INGESTED AT</Th>
                  <Th className="w-[100px] text-right">ACTION</Th>
                </Tr>
              </Thead>
              <Tbody>
                {recentCases.slice(0, 5).map((item) => (
                  <Tr
                    key={item.case_id}
                    className="cursor-pointer hover:bg-bg-panel-subtle transition-colors"
                    onClick={() => handleSelectCase(item.case_id)}
                  >
                    <Td>
                      <div className="flex flex-col gap-0.5">
                        <span className="text-xs font-bold text-text-primary">
                          {item.file_name}
                        </span>
                        <span className="text-[10px] font-mono text-text-muted">
                          Case ID: {item.case_id}
                        </span>
                      </div>
                    </Td>
                    <Td className="text-xs text-text-secondary">
                      {new Date(item.created_at).toLocaleString()}
                    </Td>
                    <Td className="text-right">
                      <Button
                        variant="secondary"
                        onClick={(e) => {
                          e.stopPropagation();
                          handleSelectCase(item.case_id);
                        }}
                        className="gap-1 text-xs py-1 h-auto"
                      >
                        <Eye className="w-3.5 h-3.5 text-primary" />
                        <span>Inspect</span>
                      </Button>
                    </Td>
                  </Tr>
                ))}
              </Tbody>
            </Table>
          </CardContent>
        </Card>
      )}
    </div>
  );
}
