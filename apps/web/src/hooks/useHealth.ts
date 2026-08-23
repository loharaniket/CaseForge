"use client";

import { useQuery } from "@tanstack/react-query";
import { fetchHealth } from "@/api/client";
import { HealthResponse } from "@/types";

export function useHealth() {
  return useQuery<HealthResponse, Error>({
    queryKey: ["health"],
    queryFn: fetchHealth,
    refetchInterval: 10000,
  });
}
