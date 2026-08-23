import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import React from "react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { EmailForensicsInspector } from "@/components/investigation/EmailForensicsInspector";
import * as emailApi from "@/lib/api/email";
import { ParsedEmail } from "@/types";

vi.mock("@/lib/api/email", () => ({
  getParsedEmail: vi.fn(),
  parseEmailCase: vi.fn(),
}));

const mockParsedEmail: ParsedEmail = {
  id: "parsed-id-1",
  case_id: "case-id-1234",
  sender: "Security Desk <security@bank-alert.com>",
  from_name: "Security Desk",
  from_address: "security@bank-alert.com",
  recipients: ["Analyst Team <analyst@company.com>"],
  cc: [],
  bcc: [],
  reply_to: [],
  subject: "URGENT: Immediate Account Verification Required",
  date_raw: "Sun, 23 Aug 2026 14:00:00 +0000",
  date_parsed: "2026-08-23T14:00:00Z",
  message_id: "<msg-id-9988@bank-alert.com>",
  body_plain: "Please visit http://phish-portal.cc/verify immediately to avoid lockout.",
  body_html: "<html><body><a href=\"http://phish-portal.cc/verify\">Click Here</a></body></html>",
  extracted_urls: ["http://phish-portal.cc/verify"],
  attachments_metadata: [
    {
      filename: "invoice_august.pdf",
      extension: ".pdf",
      file_size_bytes: 4096,
      sha256: "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899",
      content_type: "application/pdf",
    },
  ],
  raw_headers: {
    "From": "Security Desk <security@bank-alert.com>",
    "Subject": "URGENT: Immediate Account Verification Required",
  },
  created_at: "2026-08-23T14:01:00Z",
};

const renderWithQuery = (ui: React.ReactElement) => {
  const queryClient = new QueryClient({
    defaultOptions: {
      queries: {
        retry: false,
      },
    },
  });
  return render(
    <QueryClientProvider client={queryClient}>
      {ui}
    </QueryClientProvider>
  );
};

describe("EmailForensicsInspector Component", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("renders loading state initially", () => {
    vi.mocked(emailApi.getParsedEmail).mockReturnValue(new Promise(() => {}));

    renderWithQuery(<EmailForensicsInspector caseId="case-id-1234" />);

    expect(screen.getByText(/Performing Deterministic EML Forensic Parsing/i)).toBeDefined();
  });

  it("renders parsed email headers and summary information", async () => {
    vi.mocked(emailApi.getParsedEmail).mockResolvedValueOnce(mockParsedEmail);

    renderWithQuery(<EmailForensicsInspector caseId="case-id-1234" />);

    await waitFor(() => {
      expect(screen.getByText(/Forensic Case Analysis: case-id-1234/i)).toBeDefined();
      expect(screen.getByText("URGENT: Immediate Account Verification Required")).toBeDefined();
      expect(screen.getByText("Security Desk <security@bank-alert.com>")).toBeDefined();
    });
  });

  it("navigates tabs to view extracted URLs, attachments, and headers", async () => {
    vi.mocked(emailApi.getParsedEmail).mockResolvedValueOnce(mockParsedEmail);

    renderWithQuery(<EmailForensicsInspector caseId="case-id-1234" />);

    await waitFor(() => {
      expect(screen.getByText(/Forensic Case Analysis: case-id-1234/i)).toBeDefined();
    });

    // 1. URLs Tab
    const urlsTab = screen.getByRole("button", { name: /Extracted URLs/i });
    fireEvent.click(urlsTab);
    expect(screen.getByText("http://phish-portal.cc/verify")).toBeDefined();

    // 2. Attachments Tab
    const attachmentsTab = screen.getByRole("button", { name: /Attachments/i });
    fireEvent.click(attachmentsTab);
    expect(screen.getByText("invoice_august.pdf")).toBeDefined();
    expect(screen.getByText(".pdf")).toBeDefined();
    expect(screen.getByText("aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899")).toBeDefined();

    // 3. Raw Headers Tab
    const headersTab = screen.getByRole("button", { name: /Raw RFC Headers/i });
    fireEvent.click(headersTab);
    expect(screen.getByText("From:")).toBeDefined();
  });
});
