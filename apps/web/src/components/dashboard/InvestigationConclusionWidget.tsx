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
      <Card className="mb-6 border-slate-700/50">
        <CardHeader>
          <div className="flex items-center gap-2">
            <FileText className="w-5 h-5 text-slate-400" />
            <h3 className="font-semibold">Analyst Conclusion</h3>
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
      <Card className="mb-6 border-slate-700/50">
        <CardHeader>
          <div className="flex items-center gap-2">
            <FileText className="w-5 h-5 text-slate-400" />
            <h3 className="font-semibold">Analyst Conclusion</h3>
          </div>
        </CardHeader>
        <CardContent>
          <div className="flex items-center space-x-2 text-red-400 text-sm p-4 bg-red-500/10 rounded-md">
            <AlertTriangle className="w-4 h-4" />
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
  const threatColor = isHighRisk ? "text-red-400" : "text-emerald-400";
  const badgeColor = isHighRisk ? "bg-red-500/20 text-red-300 border-red-500/30" : "bg-emerald-500/20 text-emerald-300 border-emerald-500/30";

  return (
    <Card className="mb-6 border-slate-700/50 overflow-hidden relative">
      {/* Decorative accent line */}
      <div className={`absolute top-0 left-0 w-full h-1 ${isHighRisk ? 'bg-red-500' : 'bg-emerald-500'}`} />
      
      <CardHeader className="pb-2">
        <div className="flex items-center gap-2">
          <FileText className="w-5 h-5 text-slate-400" />
          <h3 className="font-semibold text-[16px] text-text-primary">Automated Analyst Conclusion</h3>
        </div>
      </CardHeader>
      
      <CardContent className="space-y-6 pt-4">
        {/* Top Summary Row */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <div className="flex flex-col space-y-1">
            <span className="text-xs text-slate-400 font-medium uppercase tracking-wider">Threat</span>
            <div className="flex items-center space-x-2">
              <ThreatIcon className={`w-5 h-5 ${threatColor}`} />
              <span className={`font-semibold ${threatColor}`}>{threatLevelText}</span>
            </div>
          </div>
          
          <div className="flex flex-col space-y-1">
            <span className="text-xs text-slate-400 font-medium uppercase tracking-wider">Classification</span>
            <div className="flex items-center">
              <Badge className={badgeColor}>
                {conclusion.classification.replace(/_/g, " ")}
              </Badge>
            </div>
          </div>

          <div className="flex flex-col space-y-1">
            <span className="text-xs text-slate-400 font-medium uppercase tracking-wider">Confidence</span>
            <div className="flex items-center">
              <span className="text-lg font-mono text-slate-200">
                {(conclusion.confidence * 100).toFixed(0)}%
              </span>
            </div>
          </div>
        </div>

        <div className="h-px w-full bg-slate-700/50" />

        {/* Findings and Infrastructure */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-8">
          <div className="space-y-4">
            <div>
              <h4 className="text-sm font-medium text-slate-300 mb-2">Primary Findings:</h4>
              <ul className="space-y-2">
                {conclusion.primary_findings.map((finding, idx) => (
                  <li key={idx} className="flex items-start space-x-2 text-sm text-slate-400">
                    <span className="text-slate-500 font-mono mt-0.5">{idx + 1}.</span>
                    <span>{finding}</span>
                  </li>
                ))}
              </ul>
            </div>
            
            {conclusion.supporting_evidence.length > 0 && (
              <div>
                <h4 className="text-sm font-medium text-slate-300 mb-2 mt-4">Supporting Evidence:</h4>
                <ul className="space-y-1">
                  {conclusion.supporting_evidence.map((evidence, idx) => (
                    <li key={idx} className="flex items-start space-x-2 text-sm text-slate-500">
                      <span className="w-1 h-1 rounded-full bg-slate-600 mt-1.5 flex-shrink-0" />
                      <span>{evidence}</span>
                    </li>
                  ))}
                </ul>
              </div>
            )}
          </div>

          <div className="space-y-4">
            <div className="p-4 bg-slate-800/50 rounded-lg border border-slate-700/50 space-y-3">
              <div className="flex items-start space-x-2">
                <MapPin className="w-4 h-4 text-indigo-400 mt-0.5 flex-shrink-0" />
                <div>
                  <span className="text-xs text-slate-400 font-medium uppercase block mb-1">Probable Infrastructure</span>
                  <p className="text-sm text-slate-200">{conclusion.probable_infrastructure}</p>
                </div>
              </div>
              
              <div className="h-px w-full bg-slate-700/50" />
              
              <div className="flex items-start space-x-2">
                <Info className="w-4 h-4 text-slate-400 mt-0.5 flex-shrink-0" />
                <div>
                  <span className="text-xs text-slate-400 font-medium uppercase block mb-1">Limitations</span>
                  <p className="text-sm text-slate-400 italic">
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
