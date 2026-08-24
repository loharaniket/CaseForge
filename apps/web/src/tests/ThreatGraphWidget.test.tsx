import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import React from "react";
import { ThreatGraphWidget } from "../components/dashboard/ThreatGraphWidget";
import { CaseThreatGraphResponse } from "@/types";

describe("ThreatGraphWidget", () => {
  const mockGraph: CaseThreatGraphResponse = {
    case_id: "case-graph-123",
    status: "available",
    total_nodes: 5,
    total_relationships: 4,
    node_counts: {
      Email: 1,
      EmailAddress: 1,
      Domain: 1,
      IP: 1,
      Country: 1,
    },
    relationship_counts: {
      SENT_FROM: 1,
      USES_DOMAIN: 1,
      RESOLVES_TO: 1,
      LOCATED_IN: 1,
    },
    nodes: [
      {
        id: "email:case-graph-123",
        label: "Urgent Phishing Alert",
        type: "Email",
        properties: { subject: "Urgent Phishing Alert" },
      },
      {
        id: "email_addr:attacker@evil.com",
        label: "attacker@evil.com",
        type: "EmailAddress",
      },
      {
        id: "domain:evil.com",
        label: "evil.com",
        type: "Domain",
      },
      {
        id: "ip:185.220.101.5",
        label: "185.220.101.5",
        type: "IP",
      },
      {
        id: "country:Germany",
        label: "Germany",
        type: "Country",
      },
    ],
    relationships: [
      {
        id: "rel-1",
        source: "email:case-graph-123",
        target: "email_addr:attacker@evil.com",
        type: "SENT_FROM",
      },
      {
        id: "rel-2",
        source: "email:case-graph-123",
        target: "domain:evil.com",
        type: "USES_DOMAIN",
      },
      {
        id: "rel-3",
        source: "domain:evil.com",
        target: "ip:185.220.101.5",
        type: "RESOLVES_TO",
      },
      {
        id: "rel-4",
        source: "ip:185.220.101.5",
        target: "country:Germany",
        type: "LOCATED_IN",
      },
    ],
    error_message: null,
  };

  it("renders graph title, node count badges, and legend items", () => {
    render(<ThreatGraphWidget graph={mockGraph} />);

    expect(screen.getByText("Investigation Threat Relationship Graph")).toBeInTheDocument();
    expect(screen.getByText("5 Nodes")).toBeInTheDocument();
    expect(screen.getByText("4 Relationships")).toBeInTheDocument();
    expect(screen.getByText("Email (1)")).toBeInTheDocument();
    expect(screen.getByText("Domain (1)")).toBeInTheDocument();
    expect(screen.getByText("IP (1)")).toBeInTheDocument();
    expect(screen.getByText("Country (1)")).toBeInTheDocument();
  });

  it("renders relationships inside the SVG canvas", () => {
    render(<ThreatGraphWidget graph={mockGraph} />);

    expect(screen.getByText("SENT_FROM")).toBeInTheDocument();
    expect(screen.getByText("USES_DOMAIN")).toBeInTheDocument();
    expect(screen.getByText("RESOLVES_TO")).toBeInTheDocument();
    expect(screen.getByText("LOCATED_IN")).toBeInTheDocument();
  });

  it("displays node telemetry details upon clicking a node", () => {
    render(<ThreatGraphWidget graph={mockGraph} />);

    // Click Germany country node
    const countryLabel = screen.getByText("Germany");
    fireEvent.click(countryLabel);

    expect(screen.getByText("Node Telemetry")).toBeInTheDocument();
    expect(screen.getByText("country:Germany")).toBeInTheDocument();
  });

  it("renders empty state when no nodes are available", () => {
    const emptyGraph: CaseThreatGraphResponse = {
      case_id: "empty-case",
      status: "available",
      total_nodes: 0,
      total_relationships: 0,
      node_counts: {},
      relationship_counts: {},
      nodes: [],
      relationships: [],
      error_message: null,
    };

    render(<ThreatGraphWidget graph={emptyGraph} />);
    expect(
      screen.getByText("No graph relationships recorded for this investigation case.")
    ).toBeInTheDocument();
  });

  it("renders warning alert when graph database is unavailable", () => {
    const unavailableGraph: CaseThreatGraphResponse = {
      case_id: "offline-case",
      status: "unavailable",
      total_nodes: 0,
      total_relationships: 0,
      node_counts: {},
      relationship_counts: {},
      nodes: [],
      relationships: [],
      error_message: "Neo4j connection timeout",
    };

    render(<ThreatGraphWidget graph={unavailableGraph} />);
    expect(screen.getByText("Neo4j connection timeout")).toBeInTheDocument();
  });
});
