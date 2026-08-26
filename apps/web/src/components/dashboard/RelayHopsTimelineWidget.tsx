"use client";

import React from "react";
import {
  Network,
  Clock,
  ArrowDown,
  Globe,
  Lock,
} from "lucide-react";
import { HeaderForensicsResponse } from "@/types";
import { Card, CardContent, Badge } from "@/components/ui";

interface RelayHopsTimelineWidgetProps {
  forensics: HeaderForensicsResponse | undefined;
  isLoading?: boolean;
}

export const RelayHopsTimelineWidget: React.FC<RelayHopsTimelineWidgetProps> = ({
  forensics,
  isLoading = false,
}) => {
  if (isLoading || !forensics) {
    return null;
  }

  const hops = forensics.relay_hops || [];
  const probableOrigin = forensics.probable_origin_ip;

  return (
    <Card>
      <CardContent className="p-6">
        <div className="flex flex-col sm:flex-row justify-between sm:items-center gap-2 mb-2">
          <div className="flex items-center gap-3">
            <Network className="w-5 h-5 text-primary" />
            <h3 className="text-[16px] font-[700] text-text-primary">
              Mail Relay Path
            </h3>
          </div>

          <div className="flex items-center gap-2 shrink-0">
            <Badge variant="neutral" className="bg-primary-soft text-primary font-[600] border-transparent px-2 py-0.5">
              {hops.length} Relay Hops
            </Badge>
            {probableOrigin && (
              <Badge variant="neutral" className="font-[600] font-mono border-primary text-primary bg-transparent px-2 py-0.5">
                Origin IP: {probableOrigin}
              </Badge>
            )}
          </div>
        </div>

        <span className="text-xs text-text-secondary block mb-6">
          Chronological hop sequence from source origin to receiving Mail Transfer Agent (MTA).
        </span>

        {hops.length === 0 ? (
          <div className="p-6 text-center text-sm text-text-secondary">
            No Received header hops available in this message.
          </div>
        ) : (
          <div className="flex flex-col gap-2">
            {hops.map((hop, idx) => {
              const isSource = idx === 0;
              const isDestination = idx === hops.length - 1;
              const label = isSource ? "Source Candidate" : isDestination ? "Destination" : "Relay";
              const isProbableOrigin = forensics.origin_analysis?.candidate_ip === hop.ip_address;
              
              return (
              <div key={idx} className="flex flex-col">
                <div
                  className={`p-4 bg-bg-panel-subtle rounded-[8px] border ${
                    isProbableOrigin ? "border-primary" : (hop.untrusted_node ? "border-destructive" : "border-border")
                  }`}
                >
                  <div className="flex flex-col sm:flex-row justify-between sm:items-start gap-2 mb-3">
                    <div className="flex flex-col gap-1">
                      <div className="flex items-center gap-2">
                        <Badge variant="neutral" className="bg-text-muted text-white text-[11px] font-[700] px-1.5 py-0">
                          {label} (Hop #{hop.hop_number})
                        </Badge>
                        {hop.is_private_relay ? (
                          <Badge variant="neutral" className="gap-1 bg-bg-page text-text-secondary text-[11px] px-1.5 py-0">
                            <Lock className="w-3 h-3" />
                            Private Subnet (RFC1918)
                          </Badge>
                        ) : (
                          <Badge variant="success" className="gap-1 text-[11px] px-1.5 py-0">
                            <Globe className="w-3 h-3" />
                            Public Gateway
                          </Badge>
                        )}
                      </div>
                      
                      {isProbableOrigin && forensics.origin_analysis && (
                        <div className="mt-2 text-[12px] bg-primary/10 p-2 rounded text-text-primary">
                           <strong className="block text-primary mb-1">Earliest reliable sending node</strong>
                           <ul className="list-disc pl-4 text-text-secondary space-y-0.5">
                             {forensics.origin_analysis.reasons.map((r, i) => <li key={i}>{r}</li>)}
                           </ul>
                        </div>
                      )}
                      
                      {hop.validation_issues && hop.validation_issues.length > 0 && (
                        <div className="mt-1 text-[11px] text-destructive">
                           <strong>Anomalies:</strong> {hop.validation_issues.join(", ")}
                        </div>
                      )}
                    </div>

                    {hop.delay_seconds !== null && hop.delay_seconds > 0 && (
                      <div className="flex items-center gap-1 text-text-secondary text-[11px] italic">
                        <Clock className="w-3 h-3" />
                        <span>Transit Delay: +{hop.delay_seconds}s</span>
                      </div>
                    )}
                  </div>

                  <GridContainer fromHost={hop.from_host} byHost={hop.by_host} withProto={hop.with_protocol} ips={hop.ip_address ? [hop.ip_address] : []} />

                  {hop.timestamp_raw && (
                    <span className="text-[11px] text-text-secondary block mt-3">
                      Timestamp: {hop.timestamp_iso ? new Date(hop.timestamp_iso).toUTCString() : hop.timestamp_raw}
                    </span>
                  )}
                </div>

                {idx < hops.length - 1 && (
                  <div className="flex justify-center my-1.5">
                    <ArrowDown className="w-4 h-4 text-text-muted" />
                  </div>
                )}
              </div>
            )})}
          </div>

        )}
      </CardContent>
    </Card>
  );
};

const GridContainer: React.FC<{
  fromHost: string | null;
  byHost: string | null;
  withProto: string | null;
  ips: string[];
}> = ({ fromHost, byHost, withProto, ips }) => (
  <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 mt-2">
    <span className="text-[11px] text-text-secondary font-mono truncate" title={fromHost || "Unknown"}>
      <strong className="font-semibold mr-1">From:</strong> {fromHost || "Unknown"}
    </span>
    <span className="text-[11px] text-text-secondary font-mono truncate" title={byHost || "Unknown"}>
      <strong className="font-semibold mr-1">By:</strong> {byHost || "Unknown"}
    </span>
    {withProto && (
      <span className="text-[11px] text-text-secondary font-mono truncate" title={withProto}>
        <strong className="font-semibold mr-1">Protocol:</strong> {withProto}
      </span>
    )}
    {ips && ips.length > 0 && (
      <span className="text-[11px] text-text-secondary font-mono truncate" title={ips.join(", ")}>
        <strong className="font-semibold mr-1">IPs:</strong> {ips.join(", ")}
      </span>
    )}
  </div>
);
