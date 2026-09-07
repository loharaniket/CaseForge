import { apiClient } from "./client";
import { HealthResponse, LivenessResponse, ReadinessResponse } from "./types";

export async function getLiveness(): Promise<LivenessResponse> {
  return apiClient.get<LivenessResponse>("api/health");
}

export async function getReadiness(): Promise<ReadinessResponse> {
  return apiClient.get<ReadinessResponse>("api/ready");
}

export async function getHealthDiagnostic(): Promise<HealthResponse> {
  return apiClient.get<HealthResponse>("api/v1/health");
}
