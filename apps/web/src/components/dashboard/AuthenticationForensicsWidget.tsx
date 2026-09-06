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
      <Badge variant={variant} className="gap-1 px-2 py-1 text-xs font-bold">
        <Icon className="w-3.5 h-3.5" />
        {protocol}: {statusVal.toUpperCase()}
      </Badge>
    );
  };

  const authDetails = (forensics.authentication_details || {}) as Record<string, any>;
  const spfDetail = authDetails.spf;
  const dkimDetail = authDetails.dkim;
  const dmarcDetail = authDetails.dmarc;

  const rawAuth = (authDetails.raw_auth_results || "") as string;
  const spfExpl = (authDetails.spf_details || spfDetail?.explanation || "") as string;
  const dkimExpl = (authDetails.dkim_details || dkimDetail?.explanation || "") as string;
  const dmarcExpl = (authDetails.dmarc_details || dmarcDetail?.explanation || "") as string;
  const spoofAlerts = forensics.spoofing_indicators || [];

  // Helper to extract clean domain
  const cleanDomain = (val: string | null | undefined): string | null => {
    if (!val) return null;
    const cleaned = val.replace(/[<>"'()]/g, "").trim();
    if (cleaned.includes("@")) {
      return cleaned.split("@").pop() || null;
    }
    return cleaned || null;
  };

  // 1. Resolve SPF Authenticated Domain
  let spfDomain = cleanDomain(spfDetail?.domain);
  if (!spfDomain) {
    const domMatch =
      spfExpl.match(/domain ['"]([^'"]+)['"]/i) ||
      rawAuth.match(/smtp\.mailfrom=([^\s;>]+)/i) ||
      rawAuth.match(/domain of ([^\s;>)]+)/i);
    if (domMatch) spfDomain = cleanDomain(domMatch[1]);
  }
  if (!spfDomain) {
    for (const alert of spoofAlerts) {
      const m = alert.match(/Return-Path \('([^']+)'\)/i);
      if (m) {
        spfDomain = cleanDomain(m[1]);
        break;
      }
    }
  }

  // 2. Resolve SPF Authorized IP
  let spfIp = spfDetail?.sender_ip || null;
  if (!spfIp) {
    const ipMatch =
      spfExpl.match(/IP ([0-9a-fA-F:.]+)/i) ||
      rawAuth.match(/(?:client-ip|sender IP is|ip)=([0-9a-fA-F:.]+)/i) ||
      rawAuth.match(/designates ([0-9a-fA-F:.]+)/i);
    if (ipMatch) spfIp = ipMatch[1];
  }
  if (!spfIp && forensics.probable_origin_ip) {
    spfIp = forensics.probable_origin_ip;
  }

  // 3. Resolve DKIM Signing Domain
  let dkimDomain = cleanDomain(dkimDetail?.domain);
  if (!dkimDomain) {
    const dMatch =
      dkimExpl.match(/domain ['"]([^'"]+)['"]/i) ||
      rawAuth.match(/header\.(?:d|i)=@?([^\s;]+)/i) ||
      rawAuth.match(/\bd=([^\s;]+)/i);
    if (dMatch) dkimDomain = cleanDomain(dMatch[1]);
  }

  // 4. Resolve DKIM Selector
  let dkimSelector = dkimDetail?.selector || null;
  if (!dkimSelector) {
    const sMatch =
      dkimExpl.match(/selector ['"]([^'"]+)['"]/i) ||
      rawAuth.match(/header\.s=([^\s;]+)/i) ||
      rawAuth.match(/\bs=([^\s;]+)/i);
    if (sMatch) dkimSelector = sMatch[1].replace(/[<>"'()]/g, "").trim();
  }

  // 5. Resolve DMARC Protected Domain
  let dmarcDomain = cleanDomain(dmarcDetail?.domain);
  if (!dmarcDomain) {
    const dmarcMatch =
      dmarcExpl.match(/domain ['"]([^'"]+)['"]/i) ||
      rawAuth.match(/header\.from=([^\s;]+)/i);
    if (dmarcMatch) dmarcDomain = cleanDomain(dmarcMatch[1]);
  }
  if (!dmarcDomain) {
    for (const alert of spoofAlerts) {
      const m = alert.match(/From \('([^']+)'\)/i);
      if (m) {
        dmarcDomain = cleanDomain(m[1]);
        break;
      }
    }
  }

  // 6. Resolve DMARC Policy Record / Status
  let dmarcPolicy = dmarcDetail?.evidence || null;
  if (!dmarcPolicy) {
    const polMatch = rawAuth.match(/dmarc=[a-z]+\s*\(([^)]+)\)/i);
    if (polMatch) dmarcPolicy = polMatch[1];
  }
  if (!dmarcPolicy) {
    if (forensics.dmarc_status?.toLowerCase() === "pass") {
      dmarcPolicy = dmarcDomain
        ? `Alignment validated: From domain ('${dmarcDomain}') aligns with SPF/DKIM authentication`
        : "Alignment validated: From domain aligns with cryptographic identity";
    } else {
      dmarcPolicy =
        dmarcExpl ||
        (dmarcDetail?.source_header && dmarcDetail.source_header !== "authentication-results"
          ? dmarcDetail.source_header
          : "No published DMARC record found in authentication headers");
    }
  }

  return (
    <Card className="shadow-md overflow-hidden border-border">
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
        {spoofAlerts.length > 0 && (
          <div className="mb-6 flex flex-col gap-2">
            {spoofAlerts.map((ind, idx) => (
              <div
                key={idx}
                className="flex items-start gap-2 p-3 bg-danger-bg border border-danger rounded-[6px]"
              >
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
              <span className="text-sm font-[650] text-text-primary">
                SPF (Sender Policy Framework)
              </span>
            </div>
            {getStatusBadge("Result", forensics.spf_status)}
          </div>
          <div className="p-4 grid grid-cols-1 md:grid-cols-2 gap-4">
            <div className="flex flex-col gap-1">
              <span className="text-[11px] font-[600] text-text-muted uppercase tracking-wider">
                Authenticated Domain
              </span>
              <span className="font-mono text-[13px] text-text-primary bg-bg-panel-subtle px-2 py-1 rounded inline-block w-fit">
                {spfDomain || "N/A"}
              </span>
            </div>
            <div className="flex flex-col gap-1">
              <span className="text-[11px] font-[600] text-text-muted uppercase tracking-wider">
                Authorized IP
              </span>
              <span className="font-mono text-[13px] text-text-primary bg-bg-panel-subtle px-2 py-1 rounded inline-block w-fit">
                {spfIp || "N/A"}
              </span>
            </div>
          </div>
        </div>

        {/* DKIM Panel */}
        <div className="mb-4 bg-bg-page border border-border rounded-[8px] overflow-hidden">
          <div className="px-4 py-3 bg-bg-panel-subtle border-b border-border flex justify-between items-center">
            <div className="flex items-center gap-2">
              <ShieldCheck className="w-4 h-4 text-text-secondary" />
              <span className="text-sm font-[650] text-text-primary">
                DKIM (DomainKeys Identified Mail)
              </span>
            </div>
            {getStatusBadge("Result", forensics.dkim_status)}
          </div>
          <div className="p-4 grid grid-cols-1 md:grid-cols-2 gap-4">
            <div className="flex flex-col gap-1">
              <span className="text-[11px] font-[600] text-text-muted uppercase tracking-wider">
                Signing Domain (d=)
              </span>
              <span className="font-mono text-[13px] text-text-primary bg-bg-panel-subtle px-2 py-1 rounded inline-block w-fit">
                {dkimDomain || "N/A"}
              </span>
            </div>
            <div className="flex flex-col gap-1">
              <span className="text-[11px] font-[600] text-text-muted uppercase tracking-wider">
                Selector (s=)
              </span>
              <span className="font-mono text-[13px] text-text-primary bg-bg-panel-subtle px-2 py-1 rounded inline-block w-fit">
                {dkimSelector || "N/A"}
              </span>
            </div>
          </div>
        </div>

        {/* DMARC Panel */}
        <div className="bg-bg-page border border-border rounded-[8px] overflow-hidden">
          <div className="px-4 py-3 bg-bg-panel-subtle border-b border-border flex justify-between items-center">
            <div className="flex items-center gap-2">
              <AlertOctagon className="w-4 h-4 text-text-secondary" />
              <span className="text-sm font-[650] text-text-primary">
                DMARC (Domain-based Message Authentication)
              </span>
            </div>
            {getStatusBadge("Result", forensics.dmarc_status)}
          </div>
          <div className="p-4 grid grid-cols-1 md:grid-cols-2 gap-4">
            <div className="flex flex-col gap-1">
              <span className="text-[11px] font-[600] text-text-muted uppercase tracking-wider">
                Protected Domain
              </span>
              <span className="font-mono text-[13px] text-text-primary bg-bg-panel-subtle px-2 py-1 rounded inline-block w-fit">
                {dmarcDomain || "N/A"}
              </span>
            </div>
            <div className="flex flex-col gap-1">
              <span className="text-[11px] font-[600] text-text-muted uppercase tracking-wider">
                Policy & Alignment Status
              </span>
              <span className="font-mono text-[12px] text-text-primary bg-bg-panel-subtle p-2 rounded block break-all">
                {dmarcPolicy}
              </span>
            </div>
          </div>

          {/* Show failure alert only when DMARC actually failed */}
          {forensics.dmarc_status &&
            forensics.dmarc_status.toLowerCase() !== "pass" &&
            forensics.dmarc_status.toLowerCase() !== "none" && (
              <div className="p-4 pt-0">
                <div className="flex items-start gap-2 p-3 bg-warning-bg border border-warning rounded-[6px]">
                  <AlertOctagon className="w-4 h-4 text-warning mt-0.5 shrink-0" />
                  <div className="flex flex-col">
                    <span className="text-[13px] font-[650] text-warning-dark">
                      DMARC Alignment Failure
                    </span>
                    <span className="text-[12px] text-warning-dark opacity-90 mt-1">
                      The organizational domain in the From header does not align with the SPF or
                      DKIM authenticated domains. This is a strong indicator of potential domain
                      spoofing.
                    </span>
                  </div>
                </div>
              </div>
            )}
        </div>
      </CardContent>
    </Card>
  );
};
