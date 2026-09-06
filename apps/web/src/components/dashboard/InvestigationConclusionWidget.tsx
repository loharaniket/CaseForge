"use client";

import React from "react";
import { useQuery } from "@tanstack/react-query";
import { 
  FileText, 
  AlertTriangle, 
  ShieldAlert, 
  ShieldCheck, 
  Info,
  MapPin
} from "lucide-react";
import { getInvestigationConclusion } from "@/lib/api/email";
import { Card, CardContent, CardHeader, Badge, LoadingState } from "@/components/ui";

interface InvestigationConclusionWidgetProps {
  caseId: string;
}

export const InvestigationConclusionWidget: React.FC<InvestigationConclusionWidgetProps> = ({ caseId }) => {
  const {
    data: conclusion,
    isLoading,
    isError,
    error,
  } = useQuery({
    queryKey: ["caseConclusion", caseId],
    queryFn: () => getInvestigationConclusion(caseId),
    retry: 2,
  });

  if (isLoading) {
    return (
      <Card className="mb-6 border-border shadow-sm">
        <CardHeader className="bg-bg-panel-subtle border-b border-border">
          <div className="flex items-center gap-2">
            <FileText className="w-5 h-5 text-primary" />
            <h3 className="font-semibold text-text-primary">Analyst Conclusion</h3>
          </div>
        </CardHeader>
        <CardContent>
          <LoadingState message="Synthesizing investigation conclusion..." />
        </CardContent>
      </Card>
    );
  }

  if (isError || !conclusion) {
    return (
      <Card className="mb-6 border-border shadow-sm">
        <CardHeader className="bg-bg-panel-subtle border-b border-border">
          <div className="flex items-center gap-2">
            <FileText className="w-5 h-5 text-primary" />
            <h3 className="font-semibold text-text-primary">Analyst Conclusion</h3>
          </div>
        </CardHeader>
        <CardContent>
          <div className="flex items-center space-x-2 text-danger text-sm p-4 bg-danger-bg border border-danger rounded-md">
            <AlertTriangle className="w-4 h-4 text-danger shrink-0" />
            <span>Failed to generate conclusion: {(error as Error)?.message || "Unknown error"}</span>
          </div>
        </CardContent>
      </Card>
    );
  }

  // Determine styling based on risk score
  const isHighRisk = conclusion.risk_score >= 50;
  const threatLevelText = 
    conclusion.risk_score >= 75 ? "CRITICAL RISK" :
    conclusion.risk_score >= 50 ? "HIGH RISK" :
    conclusion.risk_score >= 25 ? "MEDIUM RISK" : "LOW RISK";
    
  const ThreatIcon = isHighRisk ? ShieldAlert : ShieldCheck;
  const threatColor = isHighRisk ? "text-danger" : "text-success";
  const badgeColor = isHighRisk ? "bg-red-500/15 text-red-700 border-red-500/30" : "bg-emerald-500/15 text-emerald-700 border-emerald-500/30";

  return (
    <Card className="mb-6 border-border shadow-sm overflow-hidden relative bg-bg-panel">
      {/* Decorative accent line */}
      <div className={`absolute top-0 left-0 w-full h-1 ${isHighRisk ? 'bg-red-500' : 'bg-emerald-500'}`} />
      
      <CardHeader className="pb-3 border-b border-border bg-bg-panel-subtle">
        <div className="flex items-center gap-2">
          <FileText className="w-5 h-5 text-primary" />
          <h3 className="font-bold text-[16px] text-text-primary">Automated Analyst Conclusion</h3>
        </div>
      </CardHeader>
      
      <CardContent className="space-y-6 pt-5">
        {/* Top Summary Row */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <div className="flex flex-col space-y-1">
            <span className="text-xs text-text-secondary font-bold uppercase tracking-wider">Threat Level</span>
            <div className="flex items-center space-x-2">
              <ThreatIcon className={`w-5 h-5 ${threatColor}`} />
              <span className={`font-bold ${threatColor}`}>{threatLevelText}</span>
            </div>
          </div>
          
          <div className="flex flex-col space-y-1">
            <span className="text-xs text-text-secondary font-bold uppercase tracking-wider">Classification</span>
            <div className="flex items-center">
              <Badge className={badgeColor}>
                {conclusion.classification.replace(/_/g, " ")}
              </Badge>
            </div>
          </div>

          <div className="flex flex-col space-y-1">
            <span className="text-xs text-text-secondary font-bold uppercase tracking-wider">Confidence</span>
            <div className="flex items-center">
              <span className="text-xl font-mono font-bold text-text-primary">
                {(conclusion.confidence * 100).toFixed(0)}%
              </span>
            </div>
          </div>
        </div>

        <div className="h-px w-full bg-border" />

        {/* Findings and Infrastructure */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          <div className="space-y-4">
            <div>
              <h4 className="text-sm font-bold text-text-primary mb-2.5">Primary Findings:</h4>
              <ul className="space-y-2">
                {conclusion.primary_findings.map((finding, idx) => (
                  <li key={idx} className="flex items-start space-x-2 text-sm text-text-primary">
                    <span className="text-primary font-mono font-bold mt-0.5">{idx + 1}.</span>
                    <span className="leading-relaxed">{finding}</span>
                  </li>
                ))}
              </ul>
            </div>
            
            {conclusion.supporting_evidence.length > 0 && (
              <div>
                <h4 className="text-sm font-bold text-text-primary mb-2 mt-4">Supporting Evidence:</h4>
                <ul className="space-y-1.5">
                  {conclusion.supporting_evidence.map((evidence, idx) => (
                    <li key={idx} className="flex items-start space-x-2 text-xs text-text-secondary">
                      <span className="w-1.5 h-1.5 rounded-full bg-primary mt-1.5 flex-shrink-0" />
                      <span className="leading-relaxed">{evidence}</span>
                    </li>
                  ))}
                </ul>
              </div>
            )}
          </div>

          {/* Right Column: Probable Infrastructure & Limitations Card */}
          <div className="space-y-4">
            <div className="p-4 bg-bg-page rounded-lg border border-border space-y-4 shadow-sm">
              <div className="flex items-start space-x-3">
                <div className="w-8 h-8 rounded-lg bg-primary-soft flex items-center justify-center shrink-0 mt-0.5">
                  <MapPin className="w-4 h-4 text-primary" />
                </div>
                <div className="flex-1">
                  <span className="text-xs font-bold text-text-secondary uppercase tracking-wider block mb-1">
                    Probable Infrastructure
                  </span>
                  <p className="text-sm font-bold text-text-primary leading-snug">
                    {conclusion.probable_infrastructure}
                  </p>
                </div>
              </div>
              
              <div className="h-px w-full bg-border" />
              
              <div className="flex items-start space-x-3">
                <div className="w-8 h-8 rounded-lg bg-amber-500/15 flex items-center justify-center shrink-0 mt-0.5">
                  <Info className="w-4 h-4 text-amber-600" />
                </div>
                <div className="flex-1">
                  <span className="text-xs font-bold text-text-secondary uppercase tracking-wider block mb-1">
                    Limitations
                  </span>
                  <p className="text-xs text-text-secondary leading-relaxed italic bg-white p-2.5 rounded border border-border">
                    {conclusion.attribution_assessment}
                  </p>
                </div>
              </div>
            </div>
          </div>
        </div>
      </CardContent>
    </Card>
  );
};
