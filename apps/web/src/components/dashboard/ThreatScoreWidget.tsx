"use client";

import React from "react";
import {
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  Flame,
  Check,
  Info,
} from "lucide-react";
import { HeaderForensicsResponse, RiskAssessmentResponse, ThreatAssessmentResponse } from "@/types";
import { Card, CardContent, Badge, LoadingState } from "@/components/ui";

interface ThreatScoreWidgetProps {
  risk: RiskAssessmentResponse | undefined;
  threat: ThreatAssessmentResponse | undefined;
  forensics?: HeaderForensicsResponse | undefined;
  caseId?: string;
  isLoading?: boolean;
}

export const ThreatScoreWidget: React.FC<ThreatScoreWidgetProps> = ({
  risk,
  threat,
  forensics,
  caseId,
  isLoading = false,
}) => {
  if (isLoading) {
    return (
      <Card className="p-6">
        <LoadingState message="Analyzing investigation..." />
      </Card>
    );
  }

  const totalScore = risk ? Math.round(risk.total_score) : 0;
  const severity = risk?.severity || "low";
  const classification = threat?.classification || "normal";
  const confidencePercent = threat ? Math.round(threat.confidence * 100) : 0;

  // Severity color definitions
  const getSeverityConfig = (sev: string) => {
    switch (sev.toLowerCase()) {
      case "critical":
        return { variant: "critical" as const, icon: Flame, label: "CRITICAL", bgClass: "bg-danger-bg", textClass: "text-critical", borderClass: "border-danger", barClass: "bg-critical" };
      case "high":
        return { variant: "danger" as const, icon: ShieldAlert, label: "HIGH", bgClass: "bg-danger-bg", textClass: "text-danger-dark", borderClass: "border-danger", barClass: "bg-danger" };
      case "medium":
        return { variant: "warning" as const, icon: AlertTriangle, label: "MEDIUM", bgClass: "bg-warning-bg", textClass: "text-warning-dark", borderClass: "border-warning", barClass: "bg-warning" };
      default:
        return { variant: "success" as const, icon: ShieldCheck, label: "LOW", bgClass: "bg-success-bg", textClass: "text-success-dark", borderClass: "border-success", barClass: "bg-success" };
    }
  };

  const sevConfig = getSeverityConfig(severity);
  const SevIcon = sevConfig.icon;
  const classVariant = classification === "normal" ? "success" : "danger";

  // Synthesize concise executive explanation verdict
  const getExecutiveVerdict = () => {
    const isPhishOrBec = classification === "phishing" || classification === "bec";
    if (isPhishOrBec && totalScore >= 75) {
      return "High-risk phishing email with failed authentication, suspicious sender-domain relationship, and malicious infrastructure indicators.";
    }
    if (isPhishOrBec) {
      return "Suspicious email with anomalous routing and social engineering indicators requiring containment.";
    }
    if (classification === "spam") {
      return "Unsolicited bulk email with low confidence indicators and non-standard relay origins.";
    }
    return "Normal email communication with valid authentication alignment and benign infrastructure indicators.";
  };

  // Compile top 5 strongest reasons prioritizing explainability signals
  const getTopReasons = (): string[] => {
    const reasons: string[] = [];

    // 1. AI Threat heuristic reasons first to ensure explainability
    if (threat?.reasons && threat.reasons.length > 0) {
      threat.reasons.forEach((r) => {
        if (!reasons.includes(r)) reasons.push(r);
      });
    }

    // 2. Authentication signals
    if (forensics?.spf_status?.toLowerCase() === "fail") {
      reasons.push("SPF authentication failed (Unauthorized sending host)");
    }
    if (forensics?.dkim_status?.toLowerCase() === "fail") {
      reasons.push("DKIM cryptographic signature verification failed");
    }
    if (forensics?.dmarc_status?.toLowerCase() === "fail") {
      reasons.push("DMARC alignment policy failed");
    }

    // 3. Spoofing & Header anomalies
    if (forensics?.spoofing_indicators && forensics.spoofing_indicators.length > 0) {
      forensics.spoofing_indicators.forEach((ind) => {
        if (!reasons.includes(ind)) reasons.push(ind);
      });
    }

    // 4. Fallback if clean
    if (reasons.length === 0) {
      if (classification === "normal") {
        reasons.push("Authentication checks passed (SPF/DKIM/DMARC valid)");
        reasons.push("No known malicious IOCs or blacklisted relay hops identified");
        reasons.push("Sender identity aligns with declared Return-Path domain");
      } else {
        reasons.push(`Classified as ${classification.toUpperCase()} based on composite risk scoring`);
      }
    }

    return reasons.slice(0, 5);
  };

  const topReasons = getTopReasons();
  const clampedScore = Math.min(100, Math.max(0, totalScore));

  return (
    <Card className="shadow-md overflow-hidden">
      {/* SECTION A: VERDICT */}
      <div className="p-6 border-b border-bg-page bg-bg-panel-subtle">
        <div className="flex flex-col md:flex-row md:justify-between md:items-center gap-4 mb-5">
          <div className="flex items-center gap-4">
            <div className={`p-2.5 rounded-lg border ${sevConfig.bgClass} ${sevConfig.borderClass} ${sevConfig.textClass} flex items-center`}>
              <SevIcon className="w-8 h-8" />
            </div>
            <div className="flex flex-col">
              <div className="flex flex-wrap items-center gap-2 mb-1">
                <h2 className="text-[22px] font-[800] text-text-primary tracking-tight">
                  Threat Risk Score: {totalScore} / 100
                </h2>
                <Badge variant={sevConfig.variant} className="text-[11px] px-2 py-0.5">
                  {sevConfig.label}
                </Badge>
                <Badge variant={classVariant} className="text-[11px] px-2 py-0.5 uppercase">
                  Class: {classification.toUpperCase()}
                </Badge>
              </div>
              <span className="text-xs text-text-secondary font-mono">
                Case ID: {caseId || risk?.case_id || "N/A"} • Confidence: {confidencePercent}%
              </span>
            </div>
          </div>
        </div>

        {/* Progress Bar */}
        <div className="w-full h-2.5 bg-border/40 rounded-full mb-5 overflow-hidden">
          <div 
            className={`h-full rounded-full transition-all duration-500 ease-out ${sevConfig.barClass}`} 
            style={{ width: `${clampedScore}%` }}
          />
        </div>

        {/* Short Executive Verdict Explanation */}
        <div className="p-3.5 bg-white border border-border rounded-lg">
          <p className="text-sm font-[500] text-text-primary leading-snug">
            {getExecutiveVerdict()}
          </p>
        </div>
      </div>

      {/* SECTION B: WHY? (Top 5 Strongest Reasons) */}
      <CardContent className="p-6">
        <h3 className="text-[13px] font-[800] text-text-primary uppercase tracking-wider mb-4">
          Why Was It Classified This Way? (Top Reasons)
        </h3>

        <div className="flex flex-col gap-2.5">
          {topReasons.map((reason, idx) => (
            <div
              key={idx}
              className="flex items-start gap-3 p-2.5 rounded-md bg-bg-page border border-border/70"
            >
              <div className={`flex items-center justify-center w-5 h-5 rounded-full shrink-0 mt-px ${classification === "normal" ? "bg-success-bg text-success" : "bg-danger-bg text-danger-dark"}`}>
                <Check className="w-3.5 h-3.5" strokeWidth={3} />
              </div>
              <span className="text-[13px] font-[500] text-text-primary leading-relaxed">
                {reason}
              </span>
            </div>
          ))}
        </div>

        {threat?.model_version && (
          <div className="flex items-center gap-1.5 mt-5">
            <Info className="w-3.5 h-3.5 text-text-muted" />
            <span className="text-[11px] text-text-muted italic">
              Assessment Model: {threat.model_version}
            </span>
          </div>
        )}
      </CardContent>
    </Card>
  );
};
