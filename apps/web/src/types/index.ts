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
  | "phishing"
  | "spear_phishing"
  | "bec"
  | "malware"
  | "spam"
  | "benign"
  | "unknown";

export interface ThreatClassification {
  classification: ThreatCategory;
  confidence: number;
  reasons: string[];
  modelVersion: string;
}

export interface RiskScoreBreakdown {
  aiAnalysis: number;
  headerForensics: number;
  domainReputation: number;
  ipReputation: number;
  urlAnalysis: number;
  totalScore: number;
}
