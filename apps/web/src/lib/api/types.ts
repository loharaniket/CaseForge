export type HealthStatus = "healthy" | "degraded" | "unhealthy";
export type ReadyStatus = "ready" | "not_ready";
export type DatabaseStatus = "connected" | "disconnected" | "not_configured";

export interface LivenessResponse {
  status: HealthStatus;
  version: string;
  environment: string;
  timestamp: string;
}

export interface ReadinessResponse {
  status: ReadyStatus;
  database: DatabaseStatus;
  version: string;
  timestamp: string;
  details?: Record<string, unknown> | null;
}

export interface HealthResponse {
  status: HealthStatus;
  version: string;
  environment: string;
  database: DatabaseStatus;
  timestamp: string;
}

export interface ApiErrorDetail {
  code: string;
  message: string;
  details?: unknown;
}

export interface ApiErrorPayload {
  error: ApiErrorDetail;
}
