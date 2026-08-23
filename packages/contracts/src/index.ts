/**
 * ThreatTrace AI Shared Contracts & Type Definitions
 */

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
  aiAnalysis: number;      // Weight: 40%
  headerForensics: number; // Weight: 25%
  domainReputation: number;// Weight: 15%
  ipReputation: number;    // Weight: 10%
  urlAnalysis: number;     // Weight: 10%
  totalScore: number;
}
