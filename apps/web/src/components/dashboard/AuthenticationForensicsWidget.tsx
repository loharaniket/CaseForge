"use client";

import React from "react";
import {
  ShieldCheck,
  ShieldAlert,
  ShieldX,
  AlertOctagon,
  KeyRound,
  FileCheck,
} from "lucide-react";
import { HeaderForensicsResponse } from "@/types";
import { Card, CardContent, Badge } from "@/components/ui";

interface AuthenticationForensicsWidgetProps {
  forensics: HeaderForensicsResponse | undefined;
  isLoading?: boolean;
}

export const AuthenticationForensicsWidget: React.FC<AuthenticationForensicsWidgetProps> = ({
  forensics,
  isLoading = false,
}) => {
  if (isLoading || !forensics) {
    return null;
  }

  const getStatusBadge = (protocol: string, statusVal: string) => {
    const s = (statusVal || "none").toLowerCase();
    let variant: "success" | "danger" | "warning" | "neutral" = "neutral";
    let Icon = ShieldAlert;

    if (s === "pass") {
      variant = "success";
      Icon = ShieldCheck;
    } else if (s.includes("fail") || s === "permerror") {
      variant = "danger";
      Icon = ShieldX;
    } else if (s === "softfail" || s === "neutral" || s === "temperror") {
      variant = "warning";
      Icon = ShieldAlert;
    }

    return (
      <Badge variant={variant} className="gap-1 px-2 py-1 text-xs">
        <Icon className="w-3.5 h-3.5" />
        {protocol}: {statusVal.toUpperCase()}
      </Badge>
    );
  };

  const authDetails = forensics.authentication_details || {};
  const spfDetail = authDetails.spf;
  const dkimDetail = authDetails.dkim;
  const dmarcDetail = authDetails.dmarc;

  return (
    <Card>
      <CardContent className="p-6">
        {/* Header */}
        <div className="flex flex-col sm:flex-row sm:justify-between sm:items-center gap-2 mb-4">
          <div className="flex items-center gap-2">
            <FileCheck className="w-5 h-5 text-primary" />
            <h3 className="text-[18px] font-[700] text-text-primary">
              Email Authentication Forensics
            </h3>
          </div>
          <div className="flex flex-wrap gap-2">
            {getStatusBadge("SPF", forensics.spf_status)}
            {getStatusBadge("DKIM", forensics.dkim_status)}
            {getStatusBadge("DMARC", forensics.dmarc_status)}
          </div>
        </div>
        
        <p className="text-sm text-text-secondary mb-6">
          Cryptographic verification of sender identity and authorization protocols.
        </p>

        {/* Spoofing Alerts if any */}
        {forensics.spoofing_indicators && forensics.spoofing_indicators.length > 0 && (
          <div className="mb-6 flex flex-col gap-2">
            {forensics.spoofing_indicators.map((ind, idx) => (
              <div key={idx} className="flex items-start gap-2 p-3 bg-danger-bg border border-danger rounded-[6px]">
                <AlertOctagon className="w-4 h-4 text-danger mt-0.5 shrink-0" />
                <div className="flex flex-col">
                  <span className="text-[13px] text-critical">
                    <strong className="font-semibold mr-1">Spoofing Warning:</strong> 
                    {ind}
                  </span>
                </div>
              </div>
            ))}
          </div>
        )}

        {/* SPF Panel */}
        <div className="mb-4 bg-bg-page border border-border rounded-[8px] overflow-hidden">
          <div className="px-4 py-3 bg-bg-panel-subtle border-b border-border flex justify-between items-center">
            <div className="flex items-center gap-2">
              <KeyRound className="w-4 h-4 text-text-secondary" />
              <span className="text-sm font-[650] text-text-primary">SPF (Sender Policy Framework)</span>
            </div>
            {getStatusBadge("Result", forensics.spf_status)}
          </div>
          <div className="p-4 grid grid-cols-1 md:grid-cols-2 gap-4">
            <div className="flex flex-col gap-1">
              <span className="text-[11px] font-[600] text-text-muted uppercase tracking-wider">Authenticated Domain</span>
              <span className="font-mono text-[13px] text-text-primary bg-bg-panel-subtle px-2 py-1 rounded inline-block w-fit">
                {spfDetail?.domain || "N/A"}
              </span>
            </div>
            <div className="flex flex-col gap-1">
              <span className="text-[11px] font-[600] text-text-muted uppercase tracking-wider">Authorized IP</span>
              <span className="font-mono text-[13px] text-text-primary">
                {spfDetail?.sender_ip || "N/A"}
              </span>
            </div>
          </div>
        </div>

        {/* DKIM Panel */}
        <div className="mb-4 bg-bg-page border border-border rounded-[8px] overflow-hidden">
          <div className="px-4 py-3 bg-bg-panel-subtle border-b border-border flex justify-between items-center">
            <div className="flex items-center gap-2">
              <ShieldCheck className="w-4 h-4 text-text-secondary" />
              <span className="text-sm font-[650] text-text-primary">DKIM (DomainKeys Identified Mail)</span>
            </div>
            {getStatusBadge("Result", forensics.dkim_status)}
          </div>
          <div className="p-4 grid grid-cols-1 md:grid-cols-2 gap-4">
            <div className="flex flex-col gap-1">
              <span className="text-[11px] font-[600] text-text-muted uppercase tracking-wider">Signing Domain (d=)</span>
              <span className="font-mono text-[13px] text-text-primary bg-bg-panel-subtle px-2 py-1 rounded inline-block w-fit">
                {dkimDetail?.domain || "N/A"}
              </span>
            </div>
            <div className="flex flex-col gap-1">
              <span className="text-[11px] font-[600] text-text-muted uppercase tracking-wider">Selector (s=)</span>
              <span className="font-mono text-[13px] text-text-primary">
                {dkimDetail?.selector || "N/A"}
              </span>
            </div>
          </div>
        </div>

        {/* DMARC Panel */}
        <div className="bg-bg-page border border-border rounded-[8px] overflow-hidden">
          <div className="px-4 py-3 bg-bg-panel-subtle border-b border-border flex justify-between items-center">
            <div className="flex items-center gap-2">
              <AlertOctagon className="w-4 h-4 text-text-secondary" />
              <span className="text-sm font-[650] text-text-primary">DMARC (Domain-based Message Authentication)</span>
            </div>
            {getStatusBadge("Result", forensics.dmarc_status)}
          </div>
          <div className="p-4 flex flex-col gap-3">
            <div className="flex flex-col gap-1">
              <span className="text-[11px] font-[600] text-text-muted uppercase tracking-wider">Policy Record</span>
              <span className="font-mono text-[12px] text-text-primary bg-bg-panel-subtle p-2 rounded block break-all">
                {dmarcDetail?.source_header || "No DMARC record found"}
              </span>
            </div>
            
            {(!forensics.dmarc_status || forensics.dmarc_status.toLowerCase() !== "pass") && (
              <div className="flex items-start gap-2 p-3 bg-warning-bg border border-warning rounded-[6px] mt-2">
                <AlertOctagon className="w-4 h-4 text-warning mt-0.5 shrink-0" />
                <div className="flex flex-col">
                  <span className="text-[13px] font-[650] text-warning-dark">DMARC Alignment Failure</span>
                  <span className="text-[12px] text-warning-dark opacity-90 mt-1">
                    The organizational domain in the From header does not align with the SPF or DKIM authenticated domains. 
                    This is a strong indicator of domain spoofing.
                  </span>
                </div>
              </div>
            )}
          </div>
        </div>
      </CardContent>
    </Card>
  );
};
