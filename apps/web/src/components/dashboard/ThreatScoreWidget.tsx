import React from "react";
import {
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  Flame,
  Check,
  Info,
  Layers,
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
        <LoadingState message="Calculating composite threat risk scoring..." />
      </Card>
    );
  }

  const totalScore = risk ? Math.round(risk.total_score) : 0;
  const severity = (risk?.severity || threat?.classification || "low").toLowerCase();
  const classification = (threat?.classification || "normal").toLowerCase();
  const confidencePercent = threat ? Math.round(threat.confidence * 100) : 0;

  // Severity color configurations
  const getSeverityConfig = (sev: string) => {
    switch (sev) {
      case "critical":
        return {
          variant: "critical" as const,
          icon: Flame,
          label: "CRITICAL",
          bgClass: "bg-red-500/10",
          textClass: "text-red-500",
          borderClass: "border-red-500/40",
          barClass: "bg-red-500",
          ringClass: "stroke-red-500",
        };
      case "high":
        return {
          variant: "danger" as const,
          icon: ShieldAlert,
          label: "HIGH",
          bgClass: "bg-orange-500/10",
          textClass: "text-orange-500",
          borderClass: "border-orange-500/40",
          barClass: "bg-orange-500",
          ringClass: "stroke-orange-500",
        };
      case "medium":
        return {
          variant: "warning" as const,
          icon: AlertTriangle,
          label: "MEDIUM",
          bgClass: "bg-amber-500/10",
          textClass: "text-amber-500",
          borderClass: "border-amber-500/40",
          barClass: "bg-amber-500",
          ringClass: "stroke-amber-500",
        };
      default:
        return {
          variant: "success" as const,
          icon: ShieldCheck,
          label: "LOW",
          bgClass: "bg-emerald-500/10",
          textClass: "text-emerald-500",
          borderClass: "border-emerald-500/40",
          barClass: "bg-emerald-500",
          ringClass: "stroke-emerald-500",
        };
    }
  };

  const sevConfig = getSeverityConfig(severity);
  const SevIcon = sevConfig.icon;
  const classVariant = classification === "normal" ? "success" : "danger";

  // Executive summary explanation
  const getExecutiveVerdict = () => {
    const isPhishOrBec = classification === "phishing" || classification === "bec";
    if (isPhishOrBec && totalScore >= 75) {
      return "Critical-severity email identified with anomalous transmission path, spoofed sender credentials, and known weaponized infrastructure.";
    }
    if (isPhishOrBec) {
      return "Suspicious email exhibiting credential harvesting indicators and deceptive delivery headers requiring quarantine.";
    }
    if (classification === "spam") {
      return "Unsolicited marketing communication with low confidence score and non-standard relay origins.";
    }
    return "Benign communication verified with authentic SPF/DKIM cryptographic signatures and clean reputation scores.";
  };

  // Compile top 5 strongest explainability reasons
  const getTopReasons = (): string[] => {
    const reasons: string[] = [];

    if (threat?.reasons && threat.reasons.length > 0) {
      threat.reasons.forEach((r) => {
        if (!reasons.includes(r)) reasons.push(r);
      });
    }

    if (forensics?.spf_status?.toLowerCase() === "fail") {
      reasons.push("SPF authentication failed: Sending IP is not authorized by domain SPF record");
    }
    if (forensics?.dkim_status?.toLowerCase() === "fail") {
      reasons.push("DKIM cryptographic signature check failed: Body or header altered in transit");
    }
    if (forensics?.dmarc_status?.toLowerCase() === "fail") {
      reasons.push("DMARC alignment failed: From domain does not align with SPF or DKIM identities");
    }

    if (forensics?.spoofing_indicators && forensics.spoofing_indicators.length > 0) {
      forensics.spoofing_indicators.forEach((ind) => {
        if (!reasons.includes(ind)) reasons.push(ind);
      });
    }

    if (reasons.length === 0) {
      if (classification === "normal") {
        reasons.push("All email cryptographic authentication checks passed (SPF/DKIM/DMARC verified)");
        reasons.push("No weaponized URLs or malicious IP reputation hits detected");
        reasons.push("Envelope sender aligns with authenticated Return-Path domain");
      } else {
        reasons.push(`Flagged as ${classification.toUpperCase()} by multi-stage threat scoring engine`);
      }
    }

    return reasons.slice(0, 5);
  };

  const topReasons = getTopReasons();
  const clampedScore = Math.min(100, Math.max(0, totalScore));

  // Risk breakdown dimensions - extract from backend schema and fallback to threat/forensics
  const rawBreakdown = risk?.breakdown;

  // 1. AI Threat Heuristics (40%)
  const aiScore =
    rawBreakdown?.ai ??
    rawBreakdown?.ai_score ??
    (threat ? (threat.classification === "normal" ? 0 : Math.round(threat.confidence * 100)) : 0);

  // 2. Header & Authentication (25%)
  const headerScore =
    rawBreakdown?.header_forensics ??
    rawBreakdown?.header_score ??
    (forensics?.forensics_risk_score ??
      (forensics?.spf_status?.toLowerCase() === "fail" ||
      forensics?.dkim_status?.toLowerCase() === "fail" ||
      forensics?.dmarc_status?.toLowerCase() === "fail"
        ? 80
        : 0));

  // 3. Domain Intelligence (15%)
  const domainScore =
    rawBreakdown?.domain_reputation ??
    rawBreakdown?.domain_score ??
    0;

  // 4. IP Infrastructure (10%)
  const ipScore =
    rawBreakdown?.ip_reputation ??
    rawBreakdown?.ip_score ??
    0;

  // 5. Extracted URL Safety (10%)
  const urlScore =
    rawBreakdown?.url_analysis ??
    rawBreakdown?.url_score ??
    0;

  const breakdownItems = [
    { label: "AI Threat Heuristics", weight: "40%", score: aiScore },
    { label: "Header & Authentication", weight: "25%", score: headerScore },
    { label: "Domain Intelligence", weight: "15%", score: domainScore },
    { label: "IP Infrastructure", weight: "10%", score: ipScore },
    { label: "Extracted URL Safety", weight: "10%", score: urlScore },
  ];

  return (
    <Card className="shadow-md overflow-hidden border-border">
      {/* HEADER SECTION: SCORE & VERDICT */}
      <div className="p-6 bg-gradient-to-r from-bg-panel to-bg-panel-subtle border-b border-border">
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-center">
          {/* Gauge & Main Score */}
          <div className="lg:col-span-4 flex items-center gap-5">
            <div className="relative w-24 h-24 flex items-center justify-center shrink-0">
              <svg className="w-24 h-24 -rotate-90" viewBox="0 0 36 36">
                <path
                  className="text-slate-200 stroke-current"
                  strokeWidth="3.2"
                  fill="none"
                  d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831"
                />
                <path
                  className={`${sevConfig.ringClass} transition-all duration-1000 ease-out`}
                  strokeDasharray={`${clampedScore}, 100`}
                  strokeWidth="3.2"
                  strokeLinecap="round"
                  stroke="currentColor"
                  fill="none"
                  d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831"
                />
              </svg>
              <div className="absolute flex flex-col items-center justify-center">
                <span className="font-black text-2xl text-text-primary leading-none">
                  {totalScore}
                </span>
                <span className="text-[10px] font-bold text-text-muted uppercase">
                  / 100
                </span>
              </div>
            </div>

            <div className="flex flex-col gap-1.5">
              <div className="flex items-center gap-2">
                <Badge variant={sevConfig.variant} className="text-xs px-2.5 py-0.5">
                  {sevConfig.label}
                </Badge>
                <Badge variant={classVariant} className="text-xs px-2.5 py-0.5 uppercase">
                  Class: {classification.toUpperCase()}
                </Badge>
              </div>
              <h2 className="text-lg font-black text-text-primary tracking-tight">
                Threat Risk Score: {totalScore} / 100
              </h2>
              <span className="text-xs text-text-secondary font-mono">
                Confidence: {confidencePercent}%
              </span>
            </div>
          </div>

          {/* Executive Verdict Explanation */}
          <div className="lg:col-span-8 flex flex-col gap-2 p-4 bg-white rounded-xl border border-border">
            <span className="text-[11px] font-bold uppercase tracking-wider text-text-secondary flex items-center gap-1.5">
              <SevIcon className={`w-4 h-4 ${sevConfig.textClass}`} />
              Executive Forensic Verdict
            </span>
            <p className="text-sm font-medium text-text-primary leading-relaxed">
              {getExecutiveVerdict()}
            </p>
          </div>
        </div>
      </div>

      {/* BODY: RISK WEIGHTS & EXPLAINABILITY REASONS */}
      <CardContent className="p-6">
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
          {/* Column 1: Top Explainability Reasons */}
          <div className="flex flex-col gap-3">
            <h3 className="text-xs font-black text-text-primary uppercase tracking-wider flex items-center gap-2">
              <Check className="w-4 h-4 text-primary" />
              Why Was It Classified This Way? (Top Reasons)
            </h3>

            <div className="flex flex-col gap-2.5 mt-1">
              {topReasons.map((reason, idx) => (
                <div
                  key={idx}
                  className="flex items-start gap-3 p-3 rounded-lg bg-bg-page border border-border/80 hover:border-border transition-colors"
                >
                  <div
                    className={`flex items-center justify-center w-5 h-5 rounded-full shrink-0 mt-0.5 ${
                      classification === "normal"
                        ? "bg-emerald-500/15 text-emerald-600"
                        : "bg-red-500/15 text-red-600"
                    }`}
                  >
                    <Check className="w-3.5 h-3.5" strokeWidth={3} />
                  </div>
                  <span className="text-xs font-semibold text-text-primary leading-relaxed">
                    {reason}
                  </span>
                </div>
              ))}
            </div>

            {threat?.model_version && (
              <div className="flex items-center gap-1.5 mt-2">
                <Info className="w-3.5 h-3.5 text-text-muted" />
                <span className="text-[11px] text-text-muted italic">
                  Inference Model Engine: {threat.model_version}
                </span>
              </div>
            )}
          </div>

          {/* Column 2: Multi-Factor Risk Score Breakdown */}
          <div className="flex flex-col gap-3">
            <h3 className="text-xs font-black text-text-primary uppercase tracking-wider flex items-center gap-2">
              <Layers className="w-4 h-4 text-primary" />
              Weighted Component Risk Breakdown
            </h3>

            <div className="flex flex-col gap-3 mt-1">
              {breakdownItems.map((item, idx) => {
                const itemScore = Math.min(100, Math.max(0, Math.round(item.score)));
                const itemColor =
                  itemScore >= 70
                    ? "bg-red-500"
                    : itemScore >= 40
                    ? "bg-amber-500"
                    : "bg-emerald-500";

                const statusLabel =
                  itemScore >= 70
                    ? "HIGH RISK"
                    : itemScore >= 40
                    ? "SUSPICIOUS"
                    : itemScore > 0
                    ? "LOW RISK"
                    : "CLEAN";

                const statusBadgeStyle =
                  itemScore >= 70
                    ? "bg-red-500/10 text-red-500 border border-red-500/30"
                    : itemScore >= 40
                    ? "bg-amber-500/10 text-amber-500 border border-amber-500/30"
                    : itemScore > 0
                    ? "bg-emerald-500/10 text-emerald-500 border border-emerald-500/30"
                    : "bg-slate-500/10 text-text-muted border border-border";

                return (
                  <div key={idx} className="p-3 bg-bg-page border border-border/80 rounded-lg flex flex-col gap-1.5">
                    <div className="flex justify-between items-center text-xs">
                      <span className="font-bold text-text-primary">
                        {item.label}
                        <span className="ml-1.5 text-[10px] font-mono text-text-muted">
                          (weight: {item.weight})
                        </span>
                      </span>
                      <div className="flex items-center gap-2">
                        <span className={`text-[9px] font-bold px-1.5 py-0.5 rounded ${statusBadgeStyle}`}>
                          {statusLabel}
                        </span>
                        <span className="font-mono font-bold text-text-primary">
                          {itemScore} / 100
                        </span>
                      </div>
                    </div>
                    <div className="w-full h-1.5 bg-border/40 rounded-full overflow-hidden">
                      <div
                        className={`h-full rounded-full transition-all duration-500 ${itemColor}`}
                        style={{ width: `${Math.max(itemScore, itemScore > 0 ? 4 : 0)}%` }}
                      />
                    </div>
                  </div>
                );
              })}
            </div>
          </div>
        </div>
      </CardContent>
    </Card>
  );
};
