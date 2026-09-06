import React from "react";
import { describe, it, expect } from "vitest";
import { render, screen } from "@testing-library/react";
import { ThreatScoreWidget } from "@/components/dashboard/ThreatScoreWidget";

describe("ThreatScoreWidget", () => {
  it("renders scores accurately from backend breakdown keys", () => {
    const mockRisk = {
      id: "risk-123",
      case_id: "case-123",
      total_score: 85.0,
      severity: "critical" as const,
      breakdown: {
        ai: 95.0,
        header_forensics: 80.0,
        domain_reputation: 70.0,
        ip_reputation: 65.0,
        url_analysis: 85.0,
      },
      weights_applied: {
        ai_analysis: 0.4,
        header_forensics: 0.25,
        domain_reputation: 0.15,
        ip_reputation: 0.1,
        url_analysis: 0.1,
      },
      missing_components: [],
    };

    const mockThreat = {
      case_id: "case-123",
      classification: "phishing" as const,
      confidence: 0.95,
      reasons: ["Credential harvesting detection"],
      model_version: "Heuristic-v1",
    };

    render(
      <ThreatScoreWidget
        risk={mockRisk}
        threat={mockThreat}
        caseId="case-123"
      />
    );

    // Verify Title
    expect(screen.getByText("Weighted Component Risk Breakdown")).toBeInTheDocument();

    // Verify each score is properly read from the backend schema and displayed
    expect(screen.getByText("95 / 100")).toBeInTheDocument();
    expect(screen.getByText("80 / 100")).toBeInTheDocument();
    expect(screen.getByText("70 / 100")).toBeInTheDocument();
    expect(screen.getByText("65 / 100")).toBeInTheDocument();
    expect(screen.getByText("85 / 100")).toBeInTheDocument();

    // Verify status badges
    expect(screen.getAllByText("HIGH RISK").length).toBeGreaterThan(0);
  });

  it("renders clean badges when an email has 0 risk", () => {
    const mockRisk = {
      id: "risk-clean",
      case_id: "case-clean",
      total_score: 0.0,
      severity: "low" as const,
      breakdown: {
        ai: 0.0,
        header_forensics: 0.0,
        domain_reputation: 0.0,
        ip_reputation: 0.0,
        url_analysis: 0.0,
      },
      weights_applied: {},
      missing_components: [],
    };

    const mockThreat = {
      case_id: "case-clean",
      classification: "normal" as const,
      confidence: 0.98,
      reasons: ["Valid SPF and DKIM signatures"],
      model_version: "Heuristic-v1",
    };

    render(
      <ThreatScoreWidget
        risk={mockRisk}
        threat={mockThreat}
        caseId="case-clean"
      />
    );

    expect(screen.getAllByText("CLEAN").length).toBe(5);
    expect(screen.getAllByText("0 / 100").length).toBe(5);
  });
});
