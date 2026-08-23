"use client";

import React, { createContext, useContext, useEffect, useState } from "react";
import { LoginCredentials, User } from "@/types/auth";
import { getCurrentUser, loginUser } from "@/lib/api/auth";
import { apiClient } from "@/lib/api/client";

export interface AuthContextValue {
  user: User | null;
  token: string | null;
  isAuthenticated: boolean;
  isLoading: boolean;
  login: (credentials: LoginCredentials) => Promise<User>;
  logout: () => void;
}

export const AuthContext = createContext<AuthContextValue | undefined>(undefined);

const TOKEN_STORAGE_KEY = "threattrace_auth_token";

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const [user, setUser] = useState<User | null>(null);
  const [token, setToken] = useState<string | null>(null);
  const [isLoading, setIsLoading] = useState<boolean>(true);

  // Restore session from localStorage on mount
  useEffect(() => {
    async function restoreSession() {
      try {
        const storedToken = localStorage.getItem(TOKEN_STORAGE_KEY);
        if (storedToken) {
          setToken(storedToken);
          apiClient.setAuthToken(storedToken);
          const currentUser = await getCurrentUser();
          setUser(currentUser);
        }
      } catch (err) {
        console.warn("Failed to restore previous authentication session:", err);
        localStorage.removeItem(TOKEN_STORAGE_KEY);
        apiClient.setAuthToken(null);
        setToken(null);
        setUser(null);
      } finally {
        setIsLoading(false);
      }
    }

    restoreSession();
  }, []);

  const login = async (credentials: LoginCredentials): Promise<User> => {
    setIsLoading(true);
    try {
      const response = await loginUser(credentials);
      const authToken = response.access_token;
      const authUser = response.user;

      setToken(authToken);
      setUser(authUser);
      apiClient.setAuthToken(authToken);
      localStorage.setItem(TOKEN_STORAGE_KEY, authToken);

      return authUser;
    } finally {
      setIsLoading(false);
    }
  };

  const logout = () => {
    localStorage.removeItem(TOKEN_STORAGE_KEY);
    apiClient.setAuthToken(null);
    setToken(null);
    setUser(null);
  };

  return (
    <AuthContext.Provider
      value={{
        user,
        token,
        isAuthenticated: !!user,
        isLoading,
        login,
        logout,
      }}
    >
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth(): AuthContextValue {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error("useAuth must be used within an AuthProvider");
  }
  return context;
}
