import React from "react";
import { describe, it, expect, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import { AppShell } from "@/components/layout/AppShell";
import { QueryProvider } from "@/providers/QueryProvider";
import { AuthProvider } from "@/context/AuthContext";

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

import { MemoryRouter } from "react-router-dom";

describe("AppShell & Navigation", () => {
  it("renders branding, sidebar navigation items, and children", () => {
    render(
      <QueryProvider>
        <AuthProvider>
          <MemoryRouter>
            <AppShell>
              <div data-testid="test-content">Investigation Content</div>
            </AppShell>
          </MemoryRouter>
        </AuthProvider>
      </QueryProvider>
    );

    // 1. Verify header branding
    expect(screen.getByText("CaseForge")).toBeInTheDocument();
    expect(
      screen.getByText("Enterprise SOC Platform")
    ).toBeInTheDocument();

    // 2. Verify top navigation
    const investigationsLink = screen.getByRole("link", { name: /investigations/i });
    expect(investigationsLink).toHaveAttribute("href", "/investigations");

    const newInvestigationLink = screen.getByRole("link", { name: /new investigation/i });
    expect(newInvestigationLink).toHaveAttribute("href", "/new-investigation");

    // 3. Verify content
    expect(screen.getByTestId("test-content")).toHaveTextContent(
      "Investigation Content"
    );

    // 4. Verify footer
    expect(
      screen.getByText(/CaseForge SOC Investigation Platform/i)
    ).toBeInTheDocument();
  });
});
