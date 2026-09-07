import React from "react";
import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { EvidenceIntegrityWidget } from "@/components/dashboard/EvidenceIntegrityWidget";
import * as emailApi from "@/lib/api/email";

vi.mock("@/lib/api/email", () => ({
  getCaseEvidence: vi.fn(),
  verifyCaseEvidence: vi.fn(),
}));

const mockEvidenceList = {
  case_id: "case-uuid-evidence",
  total_evidence_records: 2,
  records: [
    {
      id: "rec-1",
      case_id: "case-uuid-evidence",
      evidence_type: "ORIGINAL_EMAIL",
      sha256_hash: "a3f5c9e2d1b4a7f8c0e9d6b3a2f1e4c7a0b9d8e7f6a5c4b3a2f1e0d9c8b7a6f5",
      file_name: "phishing_email.eml",
      file_size_bytes: 4096,
      calculated_at_iso: "2026-08-24T00:00:00Z",
      metadata: {},
    },
    {
      id: "rec-2",
      case_id: "case-uuid-evidence",
      evidence_type: "INVESTIGATION_REPORT",
      sha256_hash: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
      file_name: "CaseForge_Investigation_Report_case-uuv.pdf",
      file_size_bytes: 12048,
      calculated_at_iso: "2026-08-24T00:05:00Z",
      metadata: {},
    },
  ],
};

const mockVerificationSuccess = {
  case_id: "case-uuid-evidence",
  total_verified: 2,
  all_valid: true,
  results: [
    {
      case_id: "case-uuid-evidence",
      evidence_type: "ORIGINAL_EMAIL",
      status: "VERIFIED",
      is_valid: true,
      expected_sha256: "a3f5c9e2d1b4a7f8c0e9d6b3a2f1e4c7a0b9d8e7f6a5c4b3a2f1e0d9c8b7a6f5",
      actual_sha256: "a3f5c9e2d1b4a7f8c0e9d6b3a2f1e4c7a0b9d8e7f6a5c4b3a2f1e0d9c8b7a6f5",
      file_name: "phishing_email.eml",
      verified_at_iso: "2026-08-24T00:10:00Z",
      details: { algorithm: "SHA-256" },
    },
    {
      case_id: "case-uuid-evidence",
      evidence_type: "INVESTIGATION_REPORT",
      status: "VERIFIED",
      is_valid: true,
      expected_sha256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
      actual_sha256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
      file_name: "CaseForge_Investigation_Report_case-uuv.pdf",
      verified_at_iso: "2026-08-24T00:10:00Z",
      details: { algorithm: "SHA-256" },
    },
  ],
};

function renderWidget() {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  });
  return render(
    <QueryClientProvider client={queryClient}>
      <EvidenceIntegrityWidget caseId="case-uuid-evidence" />
    </QueryClientProvider>
  );
}

describe("EvidenceIntegrityWidget Component", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    Object.assign(navigator, {
      clipboard: {
        writeText: vi.fn().mockResolvedValue(undefined),
      },
    });
  });

  it("renders evidence integrity records and SHA-256 hashes", async () => {
    vi.mocked(emailApi.getCaseEvidence).mockResolvedValue(mockEvidenceList);
    renderWidget();

    await waitFor(() => {
      expect(screen.getByText("Cryptographic Evidence & Chain of Custody")).toBeInTheDocument();
      expect(screen.getByText("phishing_email.eml")).toBeInTheDocument();
      expect(screen.getByText("ORIGINAL_EMAIL")).toBeInTheDocument();
      expect(screen.getByText("INVESTIGATION_REPORT")).toBeInTheDocument();
      expect(screen.getByText("a3f5c9e2d1b4a7f8c0e9d6b3a2f1e4c7a0b9d8e7f6a5c4b3a2f1e0d9c8b7a6f5")).toBeInTheDocument();
    });
  });

  it("triggers verify action and updates status badges upon successful verification", async () => {
    vi.mocked(emailApi.getCaseEvidence).mockResolvedValue(mockEvidenceList);
    vi.mocked(emailApi.verifyCaseEvidence).mockResolvedValue(mockVerificationSuccess);
    renderWidget();

    await waitFor(() => {
      expect(screen.getByText("Cryptographic Evidence & Chain of Custody")).toBeInTheDocument();
    });

    const verifyBtn = screen.getByRole("button", { name: /Verify Chain of Custody/i });
    fireEvent.click(verifyBtn);

    await waitFor(() => {
      expect(emailApi.verifyCaseEvidence).toHaveBeenCalledWith("case-uuid-evidence");
      expect(screen.getByText("Chain of Custody Intact & Verified Authentic")).toBeInTheDocument();
      expect(screen.getAllByText(/AUTHENTIC • SHA-256 MATCH/i)).toHaveLength(2);
    });
  });

  it("allows copying SHA-256 hash to clipboard", async () => {
    vi.mocked(emailApi.getCaseEvidence).mockResolvedValue(mockEvidenceList);
    renderWidget();

    await waitFor(() => {
      expect(screen.getByText("phishing_email.eml")).toBeInTheDocument();
    });

    const copyButtons = screen.getAllByRole("button", { name: /Copy SHA-256/i });
    fireEvent.click(copyButtons[0]);

    expect(navigator.clipboard.writeText).toHaveBeenCalledWith(
      "a3f5c9e2d1b4a7f8c0e9d6b3a2f1e4c7a0b9d8e7f6a5c4b3a2f1e0d9c8b7a6f5"
    );
  });
});
