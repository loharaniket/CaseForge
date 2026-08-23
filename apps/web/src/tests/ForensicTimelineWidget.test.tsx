import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import React from "react";
import { ForensicTimelineWidget } from "../components/dashboard/ForensicTimelineWidget";
import { ForensicTimelineResponse } from "@/types";

describe("ForensicTimelineWidget", () => {
  const mockTimeline: ForensicTimelineResponse = {
    case_id: "test-case-123",
    total_events: 3,
    earliest_timestamp: "2026-08-23T10:00:00Z",
    latest_timestamp: "2026-08-23T10:05:00Z",
    has_missing_timestamps: false,
    events: [
      {
        event_id: "event-1",
        event_type: "EMAIL_DATE",
        title: "Email Message Date Declared",
        description: "Message origin date declared by sender: attacker@evil.com",
        source: "header.date",
        timestamp_iso: "2026-08-23T10:00:00Z",
        timestamp_raw: "Sun, 23 Aug 2026 10:00:00 +0000",
        timestamp_quality: "HEADER_DECLARED",
        delay_from_previous_seconds: 0,
      },
      {
        event_id: "event-2",
        event_type: "MTA_RELAY",
        title: "MTA Relay Hop #1: relay.gateway.net",
        description: "Transmitted from mail.evil.com to relay.gateway.net",
        source: "header.received[0]",
        timestamp_iso: "2026-08-23T10:00:45Z",
        timestamp_raw: "Sun, 23 Aug 2026 10:00:45 +0000",
        timestamp_quality: "HEADER_DECLARED",
        delay_from_previous_seconds: 45,
      },
      {
        event_id: "event-3",
        event_type: "INGESTION_STARTED",
        title: "Evidence Ingested & SHA-256 Hashed",
        description: "Raw evidence file ingested with SHA-256 hash",
        source: "system.ingestion",
        timestamp_iso: "2026-08-23T10:05:00Z",
        timestamp_quality: "SERVER_INGESTION",
        delay_from_previous_seconds: 255,
      },
    ],
  };

  it("renders chronological timeline title, milestones count, and events", () => {
    render(<ForensicTimelineWidget timeline={mockTimeline} />);

    expect(screen.getByText("Chronological Forensic Timeline")).toBeInTheDocument();
    expect(screen.getByText("3 Milestones")).toBeInTheDocument();
    expect(screen.getByText("Email Message Date Declared")).toBeInTheDocument();
    expect(screen.getByText("MTA Relay Hop #1: relay.gateway.net")).toBeInTheDocument();
    expect(screen.getByText("Evidence Ingested & SHA-256 Hashed")).toBeInTheDocument();
  });

  it("displays transit delay badges correctly", () => {
    render(<ForensicTimelineWidget timeline={mockTimeline} />);

    expect(screen.getByText("Transit Delay: +45s")).toBeInTheDocument();
    expect(screen.getByText("Transit Delay: +4m 15s")).toBeInTheDocument();
  });

  it("displays alert for missing timestamps when flag is set", () => {
    const missingTimeline: ForensicTimelineResponse = {
      ...mockTimeline,
      has_missing_timestamps: true,
      events: [
        {
          event_id: "event-missing",
          event_type: "EMAIL_DATE",
          title: "Malformed Date Event",
          description: "Unparseable date header in message",
          source: "header.date",
          timestamp_iso: null,
          timestamp_raw: "Invalid-Date-String",
          timestamp_quality: "MISSING",
          delay_from_previous_seconds: null,
        },
      ],
    };

    render(<ForensicTimelineWidget timeline={missingTimeline} />);

    expect(screen.getByText(/Some transmission hops or headers lacked parseable timestamps/i)).toBeInTheDocument();
    expect(screen.getByText("TIMESTAMP MISSING")).toBeInTheDocument();
  });
});
