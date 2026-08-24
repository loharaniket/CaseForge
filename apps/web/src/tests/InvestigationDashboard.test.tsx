import React from "react";
import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { InvestigationDashboard } from "@/components/dashboard/InvestigationDashboard";
import * as emailApi from "@/lib/api/email";

// Mock API functions
vi.mock("@/lib/api/email", () => ({
  getParsedEmail: vi.fn(),
  getCaseRisk: vi.fn(),
  getThreatAnalysis: vi.fn(),
  getHeaderForensics: vi.fn(),
  getCaseIOCs: vi.fn(),
  getCaseThreatIntel: vi.fn(),
  getCaseGeoInfrastructure: vi.fn(),
  getCaseTimeline: vi.fn(),
  downloadInvestigationReport: vi.fn(),
  getCaseEvidence: vi.fn(),
  verifyCaseEvidence: vi.fn(),
}));

const mockParsed = {
  id: "case-uuid-1234",
  case_id: "case-uuid-1234",
  sender: "phisher@attacker-infra.com",
  from_name: "Security Alert Desk",
  from_address: "phisher@attacker-infra.com",
  recipients: ["analyst@victim-corp.com"],
  cc: [],
  bcc: [],
  reply_to: ["drop@dark-web.org"],
  subject: "URGENT: Verify Your Credentials Immediately",
  date_raw: "Sun, 23 Aug 2026 12:00:00 +0000",
  date_parsed: "2026-08-23T12:00:00Z",
  message_id: "<msg123@attacker-infra.com>",
  body_plain: "Please click http://198.51.100.45/login to verify your account.",
  body_html: "<p>Please verify</p>",
  extracted_urls: ["http://198.51.100.45/login"],
  attachments_metadata: [
    {
      filename: "invoice.pdf",
      extension: "pdf",
      file_size_bytes: 10240,
      sha256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
      content_type: "application/pdf",
    },
  ],
  raw_headers: { "From": "phisher@attacker-infra.com" },
  created_at: "2026-08-23T12:00:00Z",
};

const mockRisk = {
  case_id: "case-uuid-1234",
  total_score: 87.5,
  severity: "critical" as const,
  breakdown: {
    ai_score: 95.0,
    header_score: 80.0,
    domain_score: 90.0,
    ip_score: 85.0,
    url_score: 80.0,
    total_score: 87.5,
  },
  weights_applied: { ai: 0.4, headers: 0.25, domain: 0.15, ip: 0.1, url: 0.1 },
  missing_components: [],
};

const mockThreat = {
  case_id: "case-uuid-1234",
  classification: "phishing" as const,
  confidence: 0.95,
  reasons: ["Urgency language detected", "Suspicious credential harvesting link"],
  model_version: "HeuristicThreatDetector-v0.1.0-dev",
};

const mockForensics = {
  case_id: "case-uuid-1234",
  relay_hops: [
    {
      hop_number: 1,
      from_host: "attacker-mta.net",
      by_host: "mx.victim-corp.com",
      with_protocol: "ESMTPS",
      timestamp_raw: "Sun, 23 Aug 2026 12:00:00 +0000",
      timestamp_iso: "2026-08-23T12:00:00Z",
      delay_seconds: 2,
      ip_addresses: ["198.51.100.200"],
      is_private_relay: false,
    },
  ],
  origin_ip_candidates: ["198.51.100.200"],
  probable_origin_ip: "198.51.100.200",
  spf_status: "fail",
  dkim_status: "none",
  dmarc_status: "fail",
  authentication_details: {
    spf: {
      status: "fail",
      domain: "attacker-infra.com",
      selector: null,
      sender_ip: "198.51.100.200",
      matching_clause: "ip4:198.51.100.200",
      source_header: "Received-SPF",
      explanation: "Sender IP 198.51.100.200 is not authorized in SPF record.",
    },
  },
  spoofing_indicators: ["From domain does not align with Return-Path"],
  anomalies: [],
  forensics_risk_score: 80.0,
};

const mockIocs = {
  case_id: "case-uuid-1234",
  total_count: 3,
  by_type: { ipv4: 1, domain: 1, email: 1 },
  iocs: [
    {
      ioc_type: "ipv4" as const,
      value: "198.51.100.200",
      source: "header.received",
      confidence: 0.98,
    },
    {
      ioc_type: "domain" as const,
      value: "attacker-infra.com",
      source: "body.text",
      confidence: 0.95,
    },
    {
      ioc_type: "email" as const,
      value: "phisher@attacker-infra.com",
      source: "header.from",
      confidence: 1.0,
    },
  ],
};

const mockIntel = {
  case_id: "case-uuid-1234",
  ip_provider: "AbuseIPDB",
  domain_provider: "VirusTotal",
  ip_lookups_count: 1,
  domain_lookups_count: 1,
  max_ip_score: 95.0,
  max_domain_score: 90.0,
  avg_ip_score: 95.0,
  avg_domain_score: 90.0,
  malicious_ips: ["198.51.100.200"],
  malicious_domains: ["attacker-infra.com"],
  ip_results: [
    {
      indicator: "198.51.100.200",
      indicator_type: "ip" as const,
      provider_name: "AbuseIPDB",
      status: "SUCCESS",
      reputation_score: 95.0,
      is_malicious: true,
      threat_tags: ["botnet", "phishing"],
      details: { total_reports: 120 },
      cached: false,
    },
  ],
  domain_results: [
    {
      indicator: "attacker-infra.com",
      indicator_type: "domain" as const,
      provider_name: "VirusTotal",
      status: "SUCCESS",
      reputation_score: 90.0,
      is_malicious: true,
      threat_tags: ["phishing"],
      details: { malicious_count: 12 },
      cached: false,
    },
  ],
};

const mockGeo = {
  case_id: "case-uuid-1234",
  provider_name: "MockGeoIPProvider",
  candidate_origin_ip: "198.51.100.200",
  probable_infrastructure_origin: "Frankfurt am Main, Hessen, Germany",
  origin_country: "Germany",
  origin_country_code: "DE",
  origin_asn: 24940,
  origin_isp: "Hetzner Online GmbH",
  disclaimer:
    "Geolocation describes network infrastructure and does not establish the physical location or identity of an attacker.",
  total_ips_analyzed: 1,
  ip_infrastructure: [
    {
      ip: "198.51.100.200",
      status: "SUCCESS",
      is_private: false,
      probable_infrastructure_origin: "Frankfurt am Main, Hessen, Germany",
      country_code: "DE",
      country_name: "Germany",
      region_name: "Hessen",
      city_name: "Frankfurt am Main",
      postal_code: "60313",
      latitude: 50.1109,
      longitude: 8.6821,
      asn_number: 24940,
      asn_org: "Hetzner Online GmbH",
      isp: "Hetzner Online",
      organization: "Hetzner Infrastructure",
      is_hosting_provider: true,
      data_quality: "city_level",
      disclaimer:
        "Geolocation describes network infrastructure and does not establish the physical location or identity of an attacker.",
      provider_name: "MockGeoIPProvider",
      cached: false,
    },
  ],
};

const mockTimeline = {
  case_id: "case-uuid-1234",
  total_events: 2,
  earliest_timestamp: "2026-08-23T12:00:00Z",
  latest_timestamp: "2026-08-23T12:00:15Z",
  has_missing_timestamps: false,
  events: [
    {
      event_id: "evt-1",
      event_type: "EMAIL_DATE",
      title: "Email Message Date Declared",
      description: "Message origin date declared by sender: phisher@attacker-infra.com",
      source: "header.date",
      timestamp_iso: "2026-08-23T12:00:00Z",
      timestamp_quality: "HEADER_DECLARED",
      delay_from_previous_seconds: 0,
    },
  ],
};

function renderDashboard(caseId: string = "case-uuid-1234") {
  const queryClient = new QueryClient({
    defaultOptions: {
      queries: { retry: false },
    },
  });
  return render(
    <QueryClientProvider client={queryClient}>
      <InvestigationDashboard caseId={caseId} />
    </QueryClientProvider>
  );
}

describe("InvestigationDashboard", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.mocked(emailApi.getParsedEmail).mockResolvedValue(mockParsed);
    vi.mocked(emailApi.getCaseRisk).mockResolvedValue(mockRisk);
    vi.mocked(emailApi.getThreatAnalysis).mockResolvedValue(mockThreat);
    vi.mocked(emailApi.getHeaderForensics).mockResolvedValue(mockForensics);
    vi.mocked(emailApi.getCaseIOCs).mockResolvedValue(mockIocs);
    vi.mocked(emailApi.getCaseThreatIntel).mockResolvedValue(mockIntel);
    vi.mocked(emailApi.getCaseGeoInfrastructure).mockResolvedValue(mockGeo);
    vi.mocked(emailApi.getCaseTimeline).mockResolvedValue(mockTimeline);
    vi.mocked(emailApi.getCaseEvidence).mockResolvedValue({
      case_id: "case-uuid-1234",
      total_evidence_records: 1,
      records: [
        {
          id: "rec-1",
          case_id: "case-uuid-1234",
          evidence_type: "ORIGINAL_EMAIL",
          sha256_hash: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
          file_name: "credential_phishing.eml",
          file_size_bytes: 4096,
          calculated_at_iso: "2026-08-24T00:00:00Z",
          metadata: {},
        },
      ],
    });
  });

  it("renders loading state when initial case data is resolving", () => {
    vi.mocked(emailApi.getParsedEmail).mockReturnValue(new Promise(() => {}));
    renderDashboard();
    expect(screen.getByText(/Loading Investigation Telemetry/i)).toBeInTheDocument();
  });

  it("renders full investigation dashboard with risk score and severity", async () => {
    renderDashboard();

    await waitFor(() => {
      expect(screen.getByText("Case Investigation Console")).toBeInTheDocument();
    });

    // Risk score
    expect(screen.getByText(/Threat Risk Score: 88 \/ 100/i)).toBeInTheDocument();
    expect(screen.getByText("CRITICAL")).toBeInTheDocument();
    expect(screen.getByText("Class: PHISHING")).toBeInTheDocument();
    expect(screen.getByText(/Confidence: 95%/i)).toBeInTheDocument();

    // Subject and sender
    expect(screen.getByText("URGENT: Verify Your Credentials Immediately")).toBeInTheDocument();
    expect(screen.getAllByText("phisher@attacker-infra.com").length).toBeGreaterThan(0);
  });

  it("renders explainability reasons for AI classification", async () => {
    renderDashboard();

    await waitFor(() => {
      expect(screen.getByText("Urgency language detected")).toBeInTheDocument();
      expect(screen.getByText("Suspicious credential harvesting link")).toBeInTheDocument();
    });
  });

  it("switches to Authentication & Relays tab and displays SPF/DKIM/DMARC status", async () => {
    renderDashboard();

    await waitFor(() => {
      expect(screen.getByText("Case Investigation Console")).toBeInTheDocument();
    });

    const authTab = screen.getByRole("tab", { name: /Authentication & Relays/i });
    fireEvent.click(authTab);

    await waitFor(() => {
      expect(screen.getByText("Email Authentication Forensics")).toBeInTheDocument();
      expect(screen.getByText("MTA Relay Pathway Timeline")).toBeInTheDocument();
      expect(screen.getAllByText("SPF: FAIL").length).toBeGreaterThan(0);
      expect(screen.getAllByText("DMARC: FAIL").length).toBeGreaterThan(0);
    });
  });

  it("switches to Threat Intel & Geo tab and verifies Rule 14 disclaimer and terminology", async () => {
    renderDashboard();

    await waitFor(() => {
      expect(screen.getByText("Case Investigation Console")).toBeInTheDocument();
    });

    const intelTab = screen.getByRole("tab", { name: /Threat Intel & Geo/i });
    fireEvent.click(intelTab);

    await waitFor(() => {
      expect(screen.getByText("Probable Infrastructure Origin")).toBeInTheDocument();
      expect(screen.getByText("Frankfurt am Main, Hessen, Germany")).toBeInTheDocument();
      expect(
        screen.getByText(/Geolocation describes network infrastructure and does not establish/i)
      ).toBeInTheDocument();
      expect(screen.queryByText(/Attacker Location/i)).not.toBeInTheDocument();
    });
  });

  it("switches to IOC Indicators tab and renders interactive table", async () => {
    renderDashboard();

    await waitFor(() => {
      expect(screen.getByText("Case Investigation Console")).toBeInTheDocument();
    });

    const iocTab = screen.getByRole("tab", { name: /IOC Indicators/i });
    fireEvent.click(iocTab);

    await waitFor(() => {
      expect(screen.getByText("Extracted Indicators of Compromise (IOCs)")).toBeInTheDocument();
      expect(screen.getByText("198.51.100.200")).toBeInTheDocument();
      expect(screen.getByText("attacker-infra.com")).toBeInTheDocument();
    });
  });

  it("switches to Forensic Timeline tab and renders chronological events", async () => {
    renderDashboard();

    await waitFor(() => {
      expect(screen.getByText("Case Investigation Console")).toBeInTheDocument();
    });

    const timelineTab = screen.getByRole("tab", { name: /Forensic Timeline/i });
    fireEvent.click(timelineTab);

    await waitFor(() => {
      expect(screen.getByText("Chronological Forensic Timeline")).toBeInTheDocument();
      expect(screen.getByText("Email Message Date Declared")).toBeInTheDocument();
    });
  });

  it("triggers PDF report download when Export PDF Report button is clicked", async () => {
    vi.mocked(emailApi.downloadInvestigationReport).mockResolvedValue();
    renderDashboard();

    await waitFor(() => {
      expect(screen.getByText("Case Investigation Console")).toBeInTheDocument();
    });

    const exportBtn = screen.getByRole("button", { name: /Export PDF Report/i });
    fireEvent.click(exportBtn);

    expect(emailApi.downloadInvestigationReport).toHaveBeenCalledWith("case-uuid-1234");
  });

  it("switches to Evidence & Custody Integrity tab and renders evidence widget", async () => {
    vi.mocked(emailApi.getCaseEvidence).mockResolvedValue({
      case_id: "case-uuid-1234",
      total_evidence_records: 1,
      records: [
        {
          id: "rec-1",
          case_id: "case-uuid-1234",
          evidence_type: "ORIGINAL_EMAIL",
          sha256_hash: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
          file_name: "test_email.eml",
          file_size_bytes: 1024,
          calculated_at_iso: "2026-08-24T00:00:00Z",
          metadata: {},
        },
      ],
    });
    renderDashboard();

    await waitFor(() => {
      expect(screen.getByText("Case Investigation Console")).toBeInTheDocument();
    });

    const evidenceTab = screen.getByRole("tab", { name: /Evidence & Custody Integrity/i });
    fireEvent.click(evidenceTab);

    await waitFor(() => {
      expect(screen.getByText("Cryptographic Evidence & Chain of Custody")).toBeInTheDocument();
      expect(screen.getByText("test_email.eml")).toBeInTheDocument();
    });
  });

  it("renders error state when case fails to load", async () => {
    vi.mocked(emailApi.getParsedEmail).mockRejectedValue(new Error("Case not found on server"));
    renderDashboard();

    await waitFor(() => {
      expect(screen.getByText(/Investigation Loading Notice/i)).toBeInTheDocument();
      expect(screen.getByText(/Case not found on server/i)).toBeInTheDocument();
    });
  });
});
