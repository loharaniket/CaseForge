import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import React from "react";
import { EmailUploadZone } from "@/components/investigation/EmailUploadZone";
import { AuthContext, AuthContextValue } from "@/context/AuthContext";
import * as emailApi from "@/lib/api/email";

// Mock email API
vi.mock("@/lib/api/email", () => ({
  uploadEmailFile: vi.fn(),
}));

const mockAuthContext: AuthContextValue = {
  user: {
    id: 1,
    email: "analyst@threattrace.io",
    full_name: "Lead Analyst",
    role: "analyst",
    is_active: true,
    created_at: "2026-08-23T00:00:00Z",
  },
  token: "fake-jwt-token",
  isAuthenticated: true,
  isLoading: false,
  login: vi.fn(),
  logout: vi.fn(),
};

const renderWithAuth = (ui: React.ReactElement, authValue = mockAuthContext) => {
  return render(
    <AuthContext.Provider value={authValue}>
      {ui}
    </AuthContext.Provider>
  );
};

describe("EmailUploadZone Component", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("shows authentication required banner when not logged in", () => {
    const unauthContext: AuthContextValue = {
      ...mockAuthContext,
      user: null,
      token: null,
      isAuthenticated: false,
    };

    renderWithAuth(<EmailUploadZone />, unauthContext);

    expect(screen.getByText(/Analyst Authentication Required/i)).toBeDefined();
    expect(screen.getByText(/Sign In as Analyst/i)).toBeDefined();
  });

  it("renders active dropzone when authenticated", () => {
    renderWithAuth(<EmailUploadZone />);

    expect(screen.getByText(/Drag & Drop suspicious/i)).toBeDefined();
    expect(screen.getByText(/Max 10 MB/i)).toBeDefined();
  });

  it("rejects non-eml file uploads with error message", async () => {
    renderWithAuth(<EmailUploadZone />);

    const fileInput = screen.getByLabelText(/Upload suspicious EML file/i);
    const nonEmlFile = new File(["malware"], "malware.exe", { type: "application/x-msdownload" });

    fireEvent.change(fileInput, { target: { files: [nonEmlFile] } });

    await waitFor(() => {
      expect(screen.getByText(/Invalid file format. Please upload an RFC 822 \(\.eml\) email file/i)).toBeDefined();
    });
    expect(emailApi.uploadEmailFile).not.toHaveBeenCalled();
  });

  it("successfully uploads valid .eml file and displays SHA-256 fingerprint", async () => {
    const mockUploadResponse = {
      case_id: "case-uuid-9999",
      status: "received",
      file_name: "suspicious_alert.eml",
      file_size_bytes: 2048,
      sha256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
      created_at: "2026-08-23T12:00:00Z",
    };

    vi.mocked(emailApi.uploadEmailFile).mockResolvedValueOnce(mockUploadResponse);
    const onUploadSuccess = vi.fn();

    renderWithAuth(<EmailUploadZone onUploadSuccess={onUploadSuccess} />);

    const fileInput = screen.getByLabelText(/Upload suspicious EML file/i);
    const validEml = new File(["From: test@phish.com"], "suspicious_alert.eml", { type: "message/rfc822" });

    fireEvent.change(fileInput, { target: { files: [validEml] } });

    await waitFor(() => {
      expect(emailApi.uploadEmailFile).toHaveBeenCalledWith(validEml);
      expect(onUploadSuccess).toHaveBeenCalledWith(mockUploadResponse);
      expect(screen.getByText(/Evidence Ingested Successfully/i)).toBeDefined();
      expect(screen.getByText("case-uuid-9999")).toBeDefined();
      expect(screen.getByText("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")).toBeDefined();
    });
  });
});
