export * from "./auth";

export type HealthStatus = "healthy" | "degraded" | "unhealthy";
export type DatabaseStatus = "connected" | "disconnected" | "not_configured";

export interface HealthResponse {
  status: HealthStatus;
  version: string;
  environment: string;
  database: DatabaseStatus;
  timestamp: string;
}

export interface EmailUploadResponse {
  case_id: string;
  status: string;
  file_name: string;
  file_size_bytes: number;
  sha256: string;
  created_at: string;
}

export interface AttachmentMetadata {
  filename: string;
  extension: string;
  file_size_bytes: number;
  sha256: string;
  content_type: string;
}

export interface ParsedEmail {
  id: string;
  case_id: string;
  sender: string | null;
  from_name: string | null;
  from_address: string | null;
  recipients: string[];
  cc: string[];
  bcc: string[];
  reply_to: string[];
  subject: string | null;
  date_raw: string | null;
  date_parsed: string | null;
  message_id: string | null;
  body_plain: string | null;
  body_html: string | null;
  extracted_urls: string[];
  attachments_metadata: AttachmentMetadata[];
  raw_headers: Record<string, string | string[]>;
  created_at: string;
}

export type ThreatSeverity = "low" | "medium" | "high" | "critical";

export type ThreatCategory =
  | "normal"
  | "spam"
  | "phishing"
  | "bec"
  | "unknown";

export interface ThreatAssessmentResponse {
  case_id: string;
  classification: ThreatCategory;
  confidence: number;
  reasons: string[];
  model_version: string;
}

export interface ProtocolAuthDetail {
  status: string;
  domain: string | null;
  selector: string | null;
  sender_ip: string | null;
  matching_clause: string | null;
  source_header: string | null;
  explanation: string;
}

export interface RelayHop {
  hop_number: number;
  from_host: string | null;
  by_host: string | null;
  with_protocol: string | null;
  timestamp_raw: string | null;
  timestamp_iso: string | null;
  delay_seconds: number | null;
  ip_address: string | null;
  is_private_relay: boolean;
  untrusted_node?: boolean;
  validation_issues?: string[];
  parser_confidence?: number;
}


export interface OriginCandidateAnalysis {
  candidate_ip: string;
  candidate_score: number;
  reasons: string[];
  confidence: number;
  limitations: string[];
}

export interface HeaderForensicsResponse {
  case_id: string;
  relay_hops: RelayHop[];
  origin_ip_candidates: string[];
  origin_analysis?: OriginCandidateAnalysis | null;
  probable_origin_ip: string | null;
  spf_status: string;
  dkim_status: string;
  dmarc_status: string;
  authentication_details: Record<string, ProtocolAuthDetail>;
  spoofing_indicators: string[];
  anomalies: string[];
  forensics_risk_score: number;
}

export interface RiskScoreBreakdown {
  ai_score: number | null;
  header_score: number | null;
  domain_score: number | null;
  ip_score: number | null;
  url_score: number | null;
  total_score: number;
}

export interface RiskAssessmentResponse {
  case_id: string;
  total_score: number;
  severity: ThreatSeverity;
  breakdown: RiskScoreBreakdown;
  weights_applied: Record<string, number>;
  missing_components: string[];
}

export interface IOCRecord {
  id?: string;
  case_id?: string;
  ioc_type: "ipv4" | "ipv6" | "domain" | "url" | "email" | "sha256";
  type?: "ipv4" | "ipv6" | "domain" | "url" | "email" | "sha256";
  value: string;
  source: string;
  confidence: number;
  context?: string | null;
  created_at?: string;
}

export interface CaseIOCListResponse {
  case_id: string;
  total_count: number;
  by_type: Record<string, number>;
  iocs: IOCRecord[];
}

export interface ReputationResult {
  indicator: string;
  indicator_type: "ip" | "domain";
  provider_name: string;
  status: string;
  reputation_score: number | null;
  is_malicious: boolean | null;
  threat_tags: string[];
  details: Record<string, unknown>;
  attribution?: string | null;
  cached: boolean;
  error_message?: string | null;
}

export interface CaseThreatIntelResponse {
  case_id: string;
  ip_provider: string;
  domain_provider: string;
  ip_lookups_count: number;
  domain_lookups_count: number;
  max_ip_score: number | null;
  max_domain_score: number | null;
  avg_ip_score: number | null;
  avg_domain_score: number | null;
  malicious_ips: string[];
  malicious_domains: string[];
  ip_results: ReputationResult[];
  domain_results: ReputationResult[];
}

export interface GeoLocationResult {
  ip: string;
  status: string;
  is_private: boolean;
  probable_infrastructure_origin: string | null;
  country_code: string | null;
  country_name: string | null;
  region_name: string | null;
  city_name: string | null;
  postal_code: string | null;
  latitude: number | null;
  longitude: number | null;
  asn_number: number | null;
  asn_org: string | null;
  isp: string | null;
  organization: string | null;
  is_hosting_provider: boolean | null;
  data_quality: string;
  disclaimer: string;
  provider_name: string;
  cached: boolean;
  error_message?: string | null;
  details?: Record<string, unknown>;
}

export interface CaseGeoInfrastructureResponse {
  case_id: string;
  provider_name: string;
  candidate_origin_ip: string | null;
  probable_infrastructure_origin: string | null;
  origin_country: string | null;
  origin_country_code: string | null;
  origin_asn: number | null;
  origin_isp: string | null;
  disclaimer: string;
  total_ips_analyzed: number;
  ip_infrastructure: GeoLocationResult[];
}

export type TimelineEventType =
  | "EMAIL_DATE"
  | "RECEIVED_HOP"
  | "MTA_RELAY"
  | "AUTHENTICATION"
  | "INGESTION_STARTED"
  | "PARSING_COMPLETED"
  | "THREAT_ASSESSMENT"
  | "INTEL_ENRICHMENT"
  | "GEO_ENRICHMENT";

export type TimestampQuality =
  | "EXACT"
  | "HEADER_DECLARED"
  | "SERVER_INGESTION"
  | "DERIVED"
  | "ESTIMATED"
  | "MISSING";

export interface TimelineEvent {
  event_id: string;
  event_type: TimelineEventType | string;
  title: string;
  description: string;
  source: string;
  timestamp_iso: string | null;
  timestamp_raw?: string | null;
  timestamp_quality: TimestampQuality | string;
  delay_from_previous_seconds?: number | null;
  details?: Record<string, unknown>;
}

export interface ForensicTimelineResponse {
  case_id: string;
  total_events: number;
  earliest_timestamp: string | null;
  latest_timestamp: string | null;
  has_missing_timestamps: boolean;
  events: TimelineEvent[];
}

export interface InvestigationReportData {
  report_title: string;
  system_name: string;
  version: string;
  generated_at_iso: string;
  case_id: string;
  file_name: string;
  file_size_bytes: number;
  sha256_hash: string;
  case_status: string;
  analyst_name?: string | null;
  analyst_email?: string | null;
  incident_summary: string;
  threat_classification: string;
  threat_confidence: number;
  threat_model_version: string;
  threat_score: number;
  threat_severity: string;
  score_breakdown: Record<string, number>;
  explainability_reasons: string[];
  subject: string;
  sender: string;
  from_name: string;
  from_address: string;
  recipients: string[];
  cc: string[];
  reply_to: string[];
  date_declared: string;
  message_id: string;
  spf_status: string;
  dkim_status: string;
  dmarc_status: string;
  authentication_details: Record<string, unknown>;
  probable_origin_ip: string;
  origin_ip_candidates: string[];
  relay_hops_count: number;
  relay_hops: Record<string, unknown>[];
  spoofing_indicators: string[];
  header_anomalies: string[];
  total_iocs_count: number;
  iocs: Record<string, unknown>[];
  ip_intel_provider: string;
  domain_intel_provider: string;
  max_ip_risk_score?: number | null;
  max_domain_risk_score?: number | null;
  malicious_ips: string[];
  malicious_domains: string[];
  ip_intel_results: Record<string, unknown>[];
  domain_intel_results: Record<string, unknown>[];
  probable_infrastructure_origin: string;
  origin_country: string;
  origin_asn?: number | null;
  origin_isp: string;
  geo_disclaimer: string;
  timeline_events_count: number;
  timeline_events: Record<string, unknown>[];
  recommendations: string[];
  evidence_sha256: string;
  custody_verification: string;
}

export type EvidenceType =
  | "ORIGINAL_EMAIL"
  | "INVESTIGATION_REPORT"
  | "ATTACHMENT";

export type EvidenceIntegrityStatus = "VERIFIED" | "CORRUPTED" | "MISSING";

export interface EvidenceRecord {
  id: string;
  case_id: string;
  evidence_type: EvidenceType | string;
  sha256_hash: string;
  file_name: string | null;
  file_size_bytes: number;
  calculated_at_iso: string;
  metadata?: Record<string, unknown>;
}

export interface CaseEvidenceListResponse {
  case_id: string;
  total_evidence_records: number;
  records: EvidenceRecord[];
}

export interface EvidenceVerificationResult {
  case_id: string;
  evidence_type: string;
  status: EvidenceIntegrityStatus | string;
  is_valid: boolean;
  expected_sha256: string | null;
  actual_sha256: string | null;
  file_name: string | null;
  verified_at_iso: string;
  details?: Record<string, unknown>;
}

export interface CaseEvidenceVerificationResponse {
  case_id: string;
  total_verified: number;
  all_valid: boolean;
  results: EvidenceVerificationResult[];
}

export type GraphNodeType =
  | "Email"
  | "EmailAddress"
  | "Domain"
  | "IP"
  | "Country"
  | "AttachmentHash";

export type GraphRelationshipType =
  | "SENT_FROM"
  | "USES_DOMAIN"
  | "RESOLVES_TO"
  | "LOCATED_IN"
  | "CONTAINS_HASH";

export interface GraphNode {
  id: string;
  label: string;
  type: GraphNodeType | string;
  node_type?: GraphNodeType | string;
  properties?: Record<string, unknown>;
}

export interface GraphRelationship {
  id: string;
  source: string;
  target: string;
  type: GraphRelationshipType | string;
  rel_type?: GraphRelationshipType | string;
  properties?: Record<string, unknown>;
}

export interface CaseThreatGraphResponse {
  case_id: string;
  status: "available" | "unavailable" | string;
  total_nodes: number;
  total_relationships: number;
  node_counts: Record<string, number>;
  relationship_counts: Record<string, number>;
  nodes: GraphNode[];
  relationships: GraphRelationship[];
  error_message: string | null;
}

export type InvestigationGraphResponse = CaseThreatGraphResponse;
