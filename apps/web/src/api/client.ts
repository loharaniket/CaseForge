import { HealthResponse } from "@/types";
import { HealthResponseSchema } from "@/validation";

const getApiBaseUrl = (): string => {
  if (typeof import.meta !== "undefined" && (import.meta as any).env?.VITE_API_URL) {
    return (import.meta as any).env.VITE_API_URL;
  }
  if (typeof process !== "undefined" && process.env?.NEXT_PUBLIC_API_URL) {
    return process.env.NEXT_PUBLIC_API_URL;
  }
  return "";
};

const API_BASE_URL = getApiBaseUrl();

export class ApiError extends Error {
  constructor(public status: number, message: string) {
    super(message);
    this.name = "ApiError";
  }
}

export async function fetchHealth(): Promise<HealthResponse> {
  try {
    const response = await fetch(`${API_BASE_URL}/api/v1/health`, {
      method: "GET",
      headers: {
        "Accept": "application/json",
      },
      cache: "no-store",
    });

    if (!response.ok) {
      throw new ApiError(response.status, `Health check failed with status ${response.status}`);
    }

    const data = await response.json();
    return HealthResponseSchema.parse(data);
  } catch (error) {
    if (error instanceof ApiError) {
      throw error;
    }
    // Network / unreachable fallback
    return {
      status: "unhealthy",
      version: "0.1.0",
      environment: "offline",
      database: "disconnected",
      timestamp: new Date().toISOString(),
    };
  }
}
