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
