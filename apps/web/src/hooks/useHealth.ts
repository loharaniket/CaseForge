"use client";

import { useQuery } from "@tanstack/react-query";
import { getHealthDiagnostic, getReadiness } from "@/lib/api/health";
import { HealthResponse, ReadinessResponse } from "@/lib/api/types";

export function useHealth() {
  return useQuery<HealthResponse, Error>({
    queryKey: ["health"],
    queryFn: getHealthDiagnostic,
    refetchInterval: 10000,
    retry: 1,
  });
}

export function useReadiness() {
  return useQuery<ReadinessResponse, Error>({
    queryKey: ["readiness"],
    queryFn: getReadiness,
    refetchInterval: 10000,
    retry: 1,
  });
}
