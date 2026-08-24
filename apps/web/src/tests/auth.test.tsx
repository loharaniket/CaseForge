import React from "react";
import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import LoginPage from "@/app/login/page";
import { AuthProvider } from "@/context/AuthContext";
import { Header } from "@/components/layout/Header";
import { QueryProvider } from "@/providers/QueryProvider";

// Mock next/navigation useRouter
const mockPush = vi.fn();
vi.mock("next/navigation", () => ({
  useRouter: () => ({
    push: mockPush,
  }),
  usePathname: () => "/",
}));

// Mock Health hook for Header test
vi.mock("@/hooks/useHealth", () => ({
  useHealth: () => ({
    data: { status: "healthy", version: "0.1.0" },
    isLoading: false,
    isError: false,
  }),
  useReadiness: () => ({
    data: { status: "ready", database: "connected" },
    isLoading: false,
    isError: false,
  }),
}));

describe("Authentication & Login UI", () => {
  beforeEach(() => {
    localStorage.clear();
    vi.restoreAllMocks();
  });

  it("renders login form fields and branding", () => {
    render(
      <AuthProvider>
        <LoginPage />
      </AuthProvider>
    );

    expect(screen.getByText("Analyst Authentication")).toBeInTheDocument();
    expect(screen.getByLabelText("Analyst Email")).toBeInTheDocument();
    expect(screen.getByLabelText("Passphrase / Credential")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /Access SOC Console/i })).toBeInTheDocument();
  });

  it("displays client-side validation error when email is malformed", async () => {
    render(
      <AuthProvider>
        <LoginPage />
      </AuthProvider>
    );

    fireEvent.change(screen.getByLabelText("Analyst Email"), {
      target: { value: "invalid-email-string" },
    });
    fireEvent.change(screen.getByLabelText("Passphrase / Credential"), {
      target: { value: "Password123!" },
    });

    fireEvent.click(screen.getByRole("button", { name: /Access SOC Console/i }));

    await waitFor(() => {
      expect(screen.getByRole("alert")).toHaveTextContent("Please enter a valid email address.");
    });
  });

  it("handles failed login and displays backend error message", async () => {
    global.fetch = vi.fn().mockResolvedValueOnce({
      ok: false,
      status: 401,
      json: async () => ({
        error: {
          code: "INVALID_CREDENTIALS",
          message: "Invalid email or password.",
        },
      }),
    });

    render(
      <AuthProvider>
        <LoginPage />
      </AuthProvider>
    );

    fireEvent.change(screen.getByLabelText("Analyst Email"), {
      target: { value: "analyst@threattrace.io" },
    });
    fireEvent.change(screen.getByLabelText("Passphrase / Credential"), {
      target: { value: "WrongPassword!" },
    });

    fireEvent.click(screen.getByRole("button", { name: /Access SOC Console/i }));

    await waitFor(() => {
      expect(screen.getByRole("alert")).toHaveTextContent("Invalid email or password.");
    });
  });

  it("handles successful login, stores token, and redirects to overview", async () => {
    const mockAuthResponse = {
      access_token: "mock.jwt.token.analyst",
      token_type: "bearer",
      expires_in: 28800,
      user: {
        id: 1,
        email: "analyst@threattrace.io",
        full_name: "Senior SOC Analyst",
        role: "analyst",
        is_active: true,
        created_at: "2026-08-23T00:00:00Z",
      },
    };

    global.fetch = vi.fn().mockResolvedValueOnce({
      ok: true,
      status: 200,
      json: async () => mockAuthResponse,
    });

    render(
      <AuthProvider>
        <LoginPage />
      </AuthProvider>
    );

    fireEvent.change(screen.getByLabelText("Analyst Email"), {
      target: { value: "analyst@threattrace.io" },
    });
    fireEvent.change(screen.getByLabelText("Passphrase / Credential"), {
      target: { value: "ValidPassword123!" },
    });

    fireEvent.click(screen.getByRole("button", { name: /Access SOC Console/i }));

    await waitFor(() => {
      expect(localStorage.getItem("threattrace_auth_token")).toBe("mock.jwt.token.analyst");
      expect(mockPush).toHaveBeenCalledWith("/");
    });
  });

  it("header renders Analyst Login link when unauthenticated", () => {
    render(
      <QueryProvider>
        <AuthProvider>
          <Header />
        </AuthProvider>
      </QueryProvider>
    );

    expect(screen.getByText("Analyst Login")).toBeInTheDocument();
  });
});
