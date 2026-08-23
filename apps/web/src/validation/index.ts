import { z } from "zod";

export const HealthResponseSchema = z.object({
  status: z.enum(["healthy", "degraded", "unhealthy"]),
  version: z.string(),
  environment: z.string(),
  database: z.enum(["connected", "disconnected", "not_configured"]),
  timestamp: z.string(),
});

export type ValidatedHealthResponse = z.infer<typeof HealthResponseSchema>;
