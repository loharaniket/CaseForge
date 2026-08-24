"use client";

import React from "react";
import {
  Clock,
  Mail,
  Network,
  ShieldCheck,
  UploadCloud,
  FileText,
  AlertTriangle,
  Globe2,
  MapPin,
  ArrowDown,
  Info,
  Calendar,
} from "lucide-react";
import { ForensicTimelineResponse, TimelineEvent } from "@/types";
import { Card, CardContent, Badge } from "@/components/ui";

interface ForensicTimelineWidgetProps {
  timeline?: ForensicTimelineResponse;
  timelineData?: ForensicTimelineResponse;
  isLoading?: boolean;
}

export const ForensicTimelineWidget: React.FC<ForensicTimelineWidgetProps> = ({
  timeline,
  timelineData,
  isLoading = false,
}) => {
  const activeTimeline = timeline || timelineData;

  if (isLoading || !activeTimeline) {
    return null;
  }

  const events = activeTimeline.events || [];

  const getEventIcon = (type: string) => {
    switch (type) {
      case "EMAIL_DATE":
        return <Mail className="w-4 h-4 text-primary" />;
      case "MTA_RELAY":
        return <Network className="w-4 h-4 text-[#3b82f6]" />;
      case "AUTHENTICATION":
        return <ShieldCheck className="w-4 h-4 text-success" />;
      case "INGESTION_STARTED":
        return <UploadCloud className="w-4 h-4 text-primary" />;
      case "PARSING_COMPLETED":
        return <FileText className="w-4 h-4 text-primary" />;
      case "THREAT_ASSESSMENT":
        return <AlertTriangle className="w-4 h-4 text-warning-dark" />;
      case "INTEL_ENRICHMENT":
        return <Globe2 className="w-4 h-4 text-info" />;
      case "GEO_ENRICHMENT":
        return <MapPin className="w-4 h-4 text-success" />;
      default:
        return <Clock className="w-4 h-4 text-text-secondary" />;
    }
  };

  const getQualityBadge = (quality: string) => {
    switch (quality) {
      case "EXACT":
      case "SERVER_INGESTION":
        return (
          <Badge variant="success" className="text-[10px] px-1.5 py-0">
            {quality}
          </Badge>
        );
      case "HEADER_DECLARED":
        return (
          <Badge variant="neutral" className="text-[10px] px-1.5 py-0 bg-primary-soft text-primary border-transparent">
            HEADER DECLARED
          </Badge>
        );
      case "DERIVED":
        return (
          <Badge variant="warning" className="text-[10px] px-1.5 py-0">
            DERIVED
          </Badge>
        );
      case "MISSING":
        return (
          <Badge variant="danger" className="text-[10px] px-1.5 py-0">
            TIMESTAMP MISSING
          </Badge>
        );
      default:
        return (
          <Badge variant="neutral" className="text-[10px] px-1.5 py-0">
            {quality}
          </Badge>
        );
    }
  };

  const formatDelay = (seconds: number | null | undefined) => {
    if (seconds === null || seconds === undefined || seconds <= 0) {
      return null;
    }
    if (seconds < 60) {
      return `+${seconds.toFixed(0)}s`;
    }
    const mins = Math.floor(seconds / 60);
    const remSec = Math.round(seconds % 60);
    return `+${mins}m ${remSec}s`;
  };

  return (
    <Card>
      <CardContent className="p-6">
        {/* Header */}
        <div className="flex flex-col sm:flex-row justify-between sm:items-center gap-2 mb-6">
          <div className="flex items-center gap-3">
            <Clock className="w-5 h-5 text-primary" />
            <div className="flex flex-col">
              <h3 className="text-[16px] font-[700] text-text-primary">
                Chronological Forensic Timeline
              </h3>
              <span className="text-[12px] text-text-secondary">
                Transmission sequence and analysis milestones reconstructed from available evidence headers.
              </span>
            </div>
          </div>

          <div className="flex items-center gap-2 shrink-0">
            <Badge variant="neutral" className="font-[700] bg-primary-soft text-primary border-primary/20">
              {activeTimeline.total_events} Milestones
            </Badge>
          </div>
        </div>

        {/* Missing Timestamps Alert if applicable */}
        {activeTimeline.has_missing_timestamps && (
          <div className="flex items-start gap-2 p-3 bg-info-bg border border-info rounded-[6px] mb-4 text-info-dark text-xs">
            <Info className="w-4 h-4 shrink-0 mt-0.5" />
            <span>
              Some transmission hops or headers lacked parseable timestamps. No synthetic timestamps were fabricated; original unparsed values are preserved.
            </span>
          </div>
        )}

        {/* Events Vertical Sequence */}
        {events.length === 0 ? (
          <div className="p-8 text-center text-sm text-text-secondary">
            No timeline events recorded for this case.
          </div>
        ) : (
          <div className="flex flex-col gap-2">
            {events.map((event: TimelineEvent, idx: number) => {
              const delayStr = formatDelay(event.delay_from_previous_seconds);

              return (
                <div key={event.event_id || idx} className="flex flex-col">
                  <div className="p-4 rounded-[8px] bg-bg-page border border-border/60">
                    <div className="flex flex-col sm:flex-row justify-between sm:items-center gap-2 mb-2">
                      <div className="flex items-center gap-2">
                        <div className="flex items-center justify-center">
                          {getEventIcon(event.event_type)}
                        </div>
                        <span className="text-[13px] font-[700] text-text-primary">
                          {event.title}
                        </span>
                        {getQualityBadge(event.timestamp_quality)}
                      </div>

                      {delayStr && (
                        <div className="flex items-center gap-1 px-2 py-0.5 rounded-full bg-warning-bg text-warning-dark border border-warning/30 text-[11px] font-mono">
                          <Clock className="w-3 h-3" />
                          <span>Transit Delay: {delayStr}</span>
                        </div>
                      )}
                    </div>

                    <p className="text-[12px] text-text-secondary mb-3">
                      {event.description}
                    </p>

                    <div className="flex flex-col sm:flex-row justify-between sm:items-center gap-2 pt-3 border-t border-border/50">
                      <div className="flex items-center gap-1.5 text-text-secondary">
                        <Calendar className="w-3.5 h-3.5" />
                        <span className="font-mono text-[11px]">
                          {event.timestamp_iso
                            ? new Date(event.timestamp_iso).toUTCString()
                            : event.timestamp_raw || "Timestamp unrecorded"}
                        </span>
                      </div>

                      <span className="font-mono text-[10px] text-text-muted">
                        Source: {event.source}
                      </span>
                    </div>
                  </div>

                  {idx < events.length - 1 && (
                    <div className="flex justify-center my-1.5">
                      <ArrowDown className="w-4 h-4 text-text-muted" />
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        )}
      </CardContent>
    </Card>
  );
};
