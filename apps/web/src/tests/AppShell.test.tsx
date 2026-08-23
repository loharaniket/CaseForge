import React from "react";
import { describe, it, expect, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import { AppShell } from "@/components/layout/AppShell";
import { QueryProvider } from "@/providers/QueryProvider";

// Mock useHealth hook to provide deterministic data
vi.mock("@/hooks/useHealth", () => ({
  useHealth: () => ({
    data: {
      status: "healthy",
      version: "0.1.0",
      environment: "development",
      database: "connected",
      timestamp: "2026-08-23T00:00:00Z",
    },
    isLoading: false,
    isError: false,
  }),
  useReadiness: () => ({
    data: {
      status: "ready",
      database: "connected",
      version: "0.1.0",
      timestamp: "2026-08-23T00:00:00Z",
    },
    isLoading: false,
    isError: false,
  }),
}));

describe("AppShell & Navigation", () => {
  it("renders branding, sidebar navigation items, and children", () => {
    render(
      <QueryProvider>
        <AppShell>
          <div data-testid="test-content">Investigation Content</div>
        </AppShell>
      </QueryProvider>
    );

    // 1. Verify header branding
    expect(screen.getByText("ThreatTrace AI")).toBeInTheDocument();
    expect(
      screen.getByText("Cybersecurity Email Investigation Platform")
    ).toBeInTheDocument();
    expect(screen.getByText("SOC Engine Ready")).toBeInTheDocument();

    // 2. Verify sidebar navigation
    expect(screen.getByText("INVESTIGATION MODULES")).toBeInTheDocument();
    expect(screen.getByText("SOC Overview")).toBeInTheDocument();
    expect(screen.getByText("Email Ingestion")).toBeInTheDocument();
    expect(screen.getByText("Header Forensics")).toBeInTheDocument();
    expect(screen.getByText("Threat Intelligence")).toBeInTheDocument();
    expect(screen.getByText("Reports & Evidence")).toBeInTheDocument();

    // 3. Verify content
    expect(screen.getByTestId("test-content")).toHaveTextContent(
      "Investigation Content"
    );

    // 4. Verify footer
    expect(
      screen.getByText(/ThreatTrace AI SOC Investigation Platform/i)
    ).toBeInTheDocument();
  });
});
