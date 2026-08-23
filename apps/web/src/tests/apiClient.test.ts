import { describe, it, expect, vi, beforeEach } from "vitest";
import { ApiClient, ApiError } from "@/lib/api/client";
import { getLiveness, getReadiness, getHealthDiagnostic } from "@/lib/api/health";

describe("ApiClient", () => {
  let client: ApiClient;

  beforeEach(() => {
    client = new ApiClient("http://localhost:8000");
    vi.restoreAllMocks();
  });

  it("should perform successful GET request and return parsed JSON", async () => {
    const mockData = { status: "healthy", version: "0.1.0" };
    global.fetch = vi.fn().mockResolvedValueOnce({
      ok: true,
      status: 200,
      json: async () => mockData,
    });

    const result = await client.get<typeof mockData>("api/health");
    expect(result).toEqual(mockData);
    expect(global.fetch).toHaveBeenCalledWith(
      "http://localhost:8000/api/health",
      expect.objectContaining({
        method: "GET",
        headers: expect.objectContaining({
          Accept: "application/json",
          "Content-Type": "application/json",
        }),
      })
    );
  });

  it("should append query parameters to URL", async () => {
    global.fetch = vi.fn().mockResolvedValueOnce({
      ok: true,
      status: 200,
      json: async () => ({ results: [] }),
    });

    await client.get("search", { params: { query: "phish", limit: 10 } });
    expect(global.fetch).toHaveBeenCalledWith(
      "http://localhost:8000/search?query=phish&limit=10",
      expect.anything()
    );
  });

  it("should parse structured API error responses from backend", async () => {
    const errorPayload = {
      error: {
        code: "VALIDATION_ERROR",
        message: "Invalid email payload structure",
        details: [{ location: "body -> raw_eml", message: "Field required" }],
      },
    };

    global.fetch = vi.fn().mockResolvedValueOnce({
      ok: false,
      status: 422,
      json: async () => errorPayload,
    });

    try {
      await client.post("api/v1/analyze", {});
      expect.fail("Expected ApiError to be thrown");
    } catch (err) {
      expect(err).toBeInstanceOf(ApiError);
      const apiErr = err as ApiError;
      expect(apiErr.status).toBe(422);
      expect(apiErr.code).toBe("VALIDATION_ERROR");
      expect(apiErr.message).toBe("Invalid email payload structure");
      expect(apiErr.details).toEqual(errorPayload.error.details);
    }
  });

  it("should handle network failure gracefully with NETWORK_ERROR code", async () => {
    global.fetch = vi.fn().mockRejectedValueOnce(new Error("Connection refused"));

    try {
      await client.get("api/ready");
      expect.fail("Expected ApiError to be thrown");
    } catch (err) {
      expect(err).toBeInstanceOf(ApiError);
      const apiErr = err as ApiError;
      expect(apiErr.code).toBe("NETWORK_ERROR");
      expect(apiErr.message).toContain("Connection refused");
    }
  });
});

describe("Health API Functions", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it("getLiveness calls /api/health", async () => {
    const mockLiveness = {
      status: "healthy",
      version: "0.1.0",
      environment: "development",
      timestamp: "2026-08-23T00:00:00Z",
    };
    global.fetch = vi.fn().mockResolvedValueOnce({
      ok: true,
      status: 200,
      json: async () => mockLiveness,
    });

    const result = await getLiveness();
    expect(result.status).toBe("healthy");
    expect(global.fetch).toHaveBeenCalledWith(
      expect.stringContaining("/api/health"),
      expect.anything()
    );
  });

  it("getReadiness calls /api/ready", async () => {
    const mockReadiness = {
      status: "ready",
      database: "connected",
      version: "0.1.0",
      timestamp: "2026-08-23T00:00:00Z",
    };
    global.fetch = vi.fn().mockResolvedValueOnce({
      ok: true,
      status: 200,
      json: async () => mockReadiness,
    });

    const result = await getReadiness();
    expect(result.status).toBe("ready");
    expect(result.database).toBe("connected");
  });

  it("getHealthDiagnostic calls /api/v1/health", async () => {
    const mockHealth = {
      status: "healthy",
      version: "0.1.0",
      environment: "development",
      database: "connected",
      timestamp: "2026-08-23T00:00:00Z",
    };
    global.fetch = vi.fn().mockResolvedValueOnce({
      ok: true,
      status: 200,
      json: async () => mockHealth,
    });

    const result = await getHealthDiagnostic();
    expect(result.status).toBe("healthy");
  });
});
