import { ApiErrorPayload } from "./types";

export class ApiError extends Error {
  constructor(
    public status: number,
    public code: string,
    message: string,
    public details?: unknown
  ) {
    super(message);
    this.name = "ApiError";
  }
}

export interface RequestOptions extends RequestInit {
  timeoutMs?: number;
  params?: Record<string, string | number | boolean>;
}

export class ApiClient {
  private baseUrl: string;
  private authToken: string | null = null;

  constructor(baseUrl?: string) {
    const envUrl =
      (typeof import.meta !== "undefined" && (import.meta as any).env?.VITE_API_URL) ||
      (typeof process !== "undefined" && process.env?.NEXT_PUBLIC_API_URL) ||
      "";
    this.baseUrl = (baseUrl || envUrl).replace(/\/$/, "");
  }

  public getBaseUrl(): string {
    return this.baseUrl;
  }

  public setAuthToken(token: string | null): void {
    this.authToken = token;
  }

  public getAuthToken(): string | null {
    return this.authToken;
  }

  public async request<T>(endpoint: string, options: RequestOptions = {}): Promise<T> {
    const { timeoutMs = 10000, params, headers = {}, ...restOptions } = options;

    let url = `${this.baseUrl}/${endpoint.replace(/^\//, "")}`;

    if (params) {
      const searchParams = new URLSearchParams();
      for (const [key, value] of Object.entries(params)) {
        if (value !== undefined && value !== null) {
          searchParams.append(key, String(value));
        }
      }
      const qs = searchParams.toString();
      if (qs) {
        url += (url.includes("?") ? "&" : "?") + qs;
      }
    }

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);

    const isFormData = restOptions.body instanceof FormData;

    const requestHeaders: Record<string, string> = {
      Accept: "application/json",
      ...(headers as Record<string, string>),
    };

    if (!isFormData && !requestHeaders["Content-Type"]) {
      requestHeaders["Content-Type"] = "application/json";
    }

    if (this.authToken && !requestHeaders["Authorization"]) {
      requestHeaders["Authorization"] = `Bearer ${this.authToken}`;
    }

    try {
      const response = await fetch(url, {
        ...restOptions,
        headers: requestHeaders,
        signal: controller.signal,
      });

      clearTimeout(timer);

      if (!response.ok) {
        let errorCode = `HTTP_${response.status}`;
        let errorMessage = `Request failed with status ${response.status}`;
        let errorDetails: unknown = null;

        try {
          const body: ApiErrorPayload = await response.json();
          if (body && body.error) {
            errorCode = body.error.code || errorCode;
            errorMessage = body.error.message || errorMessage;
            errorDetails = body.error.details ?? null;
          }
        } catch {
          // Non-JSON error body fallback
        }

        throw new ApiError(response.status, errorCode, errorMessage, errorDetails);
      }

      return (await response.json()) as T;
    } catch (err: unknown) {
      clearTimeout(timer);
      if (err instanceof ApiError) {
        throw err;
      }
      if (err instanceof DOMException && err.name === "AbortError") {
        throw new ApiError(408, "TIMEOUT", "Request timed out.");
      }
      throw new ApiError(
        0,
        "NETWORK_ERROR",
        err instanceof Error ? err.message : "Network error occurred."
      );
    }
  }

  public get<T>(endpoint: string, options?: RequestOptions): Promise<T> {
    return this.request<T>(endpoint, { ...options, method: "GET" });
  }

  public post<T>(endpoint: string, body?: unknown, options?: RequestOptions): Promise<T> {
    return this.request<T>(endpoint, {
      ...options,
      method: "POST",
      body: body ? JSON.stringify(body) : undefined,
    });
  }

  public postFormData<T>(endpoint: string, formData: FormData, options?: RequestOptions): Promise<T> {
    return this.request<T>(endpoint, {
      ...options,
      method: "POST",
      body: formData,
    });
  }

  public async downloadBlob(endpoint: string, options: RequestOptions = {}): Promise<Blob> {
    const { timeoutMs = 20000, headers = {}, ...restOptions } = options;
    const url = `${this.baseUrl}/${endpoint.replace(/^\//, "")}`;
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);

    const requestHeaders: Record<string, string> = {
      Accept: "application/pdf, application/octet-stream, */*",
      ...(headers as Record<string, string>),
    };
    if (this.authToken && !requestHeaders["Authorization"]) {
      requestHeaders["Authorization"] = `Bearer ${this.authToken}`;
    }

    try {
      const response = await fetch(url, {
        ...restOptions,
        headers: requestHeaders,
        signal: controller.signal,
      });
      clearTimeout(timer);
      if (!response.ok) {
        throw new ApiError(response.status, `HTTP_${response.status}`, `Failed to download file`);
      }
      return await response.blob();
    } catch (err: unknown) {
      clearTimeout(timer);
      if (err instanceof ApiError) throw err;
      if (err instanceof DOMException && err.name === "AbortError") {
        throw new ApiError(408, "TIMEOUT", "Download request timed out.");
      }
      throw new ApiError(
        0,
        "NETWORK_ERROR",
        err instanceof Error ? err.message : "Download network error occurred."
      );
    }
  }
}

export const apiClient = new ApiClient();
