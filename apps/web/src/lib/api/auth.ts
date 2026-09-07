import { apiClient } from "./client";
import { LoginCredentials, TokenResponse, User } from "@/types/auth";

export async function loginUser(credentials: LoginCredentials): Promise<TokenResponse> {
  return apiClient.post<TokenResponse>("api/v1/auth/login", credentials);
}

export async function getCurrentUser(): Promise<User> {
  return apiClient.get<User>("api/v1/auth/me");
}
