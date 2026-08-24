"use client";

import React, { useState } from "react";
import { useRouter } from "next/navigation";
import { Shield, Lock, Mail, AlertCircle, ArrowRight, RefreshCw } from "lucide-react";
import { useAuth } from "@/context/AuthContext";
import { ApiError } from "@/lib/api/client";

export default function LoginPage() {
  const router = useRouter();
  const { login } = useAuth();

  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const [isSubmitting, setIsSubmitting] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setErrorMsg(null);

    // Basic validation
    if (!email.trim()) {
      setErrorMsg("Email address is required.");
      return;
    }
    if (!email.includes("@")) {
      setErrorMsg("Please enter a valid email address.");
      return;
    }
    if (!password) {
      setErrorMsg("Password is required.");
      return;
    }

    setIsSubmitting(true);
    try {
      await login({ email: email.trim(), password });
      router.push("/");
    } catch (err: unknown) {
      if (err instanceof ApiError) {
        setErrorMsg(err.message);
      } else if (err instanceof Error) {
        setErrorMsg(err.message);
      } else {
        setErrorMsg("Authentication failed. Please verify credentials.");
      }
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <div style={{ backgroundColor: "#17212B", minHeight: "100vh", display: "flex", alignItems: "center", justifyContent: "center", padding: "24px" }}>
      <div style={{ width: "400px", backgroundColor: "#FFFFFF", borderRadius: "8px", padding: "32px", boxShadow: "0 4px 6px -1px rgba(0,0,0,0.1)" }}>
        {/* Header Branding */}
        <div style={{ textAlign: "center", marginBottom: "24px" }}>
          <div style={{ width: "48px", height: "48px", borderRadius: "12px", backgroundColor: "#EAF2F8", display: "flex", alignItems: "center", justifyContent: "center", margin: "0 auto 16px" }}>
            <Shield style={{ width: "24px", height: "24px", color: "#1F4E79" }} />
          </div>
          <h1 style={{ fontSize: "20px", fontWeight: "700", color: "#17212B", margin: "0 0 4px 0" }}>Analyst Authentication</h1>
          <p style={{ fontSize: "12px", color: "#52606D" }}>
            ThreatTrace AI Security Operations Center
          </p>
        </div>

        {/* Error Alert */}
        {errorMsg && (
          <div role="alert" style={{ display: "flex", alignItems: "center", gap: "8px", padding: "12px", backgroundColor: "#FDECEC", border: "1px solid #C53030", borderRadius: "6px", marginBottom: "20px" }}>
            <AlertCircle style={{ width: "16px", height: "16px", color: "#C53030", flexShrink: 0 }} />
            <span style={{ fontSize: "13px", color: "#9B1C1C" }}>{errorMsg}</span>
          </div>
        )}

        {/* Login Form */}
        <form onSubmit={handleSubmit} noValidate style={{ display: "flex", flexDirection: "column", gap: "16px" }}>
          <div>
            <label htmlFor="email-input" style={{ display: "block", fontSize: "13px", fontWeight: "650", color: "#17212B", marginBottom: "6px" }}>
              Analyst Email
            </label>
            <div style={{ position: "relative" }}>
              <Mail style={{ width: "16px", height: "16px", color: "#52606D", position: "absolute", left: "12px", top: "50%", transform: "translateY(-50%)" }} />
              <input
                id="email-input"
                type="email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                placeholder="analyst@threattrace.io"
                disabled={isSubmitting}
                style={{ width: "100%", height: "36px", padding: "0 12px 0 36px", borderRadius: "6px", border: "1px solid #D9E0E7", fontSize: "13px", color: "#17212B", outline: "none" }}
                autoComplete="email"
                required
              />
            </div>
          </div>

          <div>
            <label htmlFor="password-input" style={{ display: "block", fontSize: "13px", fontWeight: "650", color: "#17212B", marginBottom: "6px" }}>
              Passphrase / Credential
            </label>
            <div style={{ position: "relative" }}>
              <Lock style={{ width: "16px", height: "16px", color: "#52606D", position: "absolute", left: "12px", top: "50%", transform: "translateY(-50%)" }} />
              <input
                id="password-input"
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="••••••••••••"
                disabled={isSubmitting}
                style={{ width: "100%", height: "36px", padding: "0 12px 0 36px", borderRadius: "6px", border: "1px solid #D9E0E7", fontSize: "13px", color: "#17212B", outline: "none" }}
                autoComplete="current-password"
                required
              />
            </div>
          </div>

          <button
            type="submit"
            disabled={isSubmitting}
            className="action-btn primary"
            style={{ width: "100%", justifyContent: "center", marginTop: "8px" }}
          >
            {isSubmitting ? (
              <>
                <RefreshCw style={{ width: "16px", height: "16px", animation: "spin 1s linear infinite" }} />
                <span>Authenticating...</span>
              </>
            ) : (
              <>
                <span>Access SOC Console</span>
                <ArrowRight style={{ width: "16px", height: "16px" }} />
              </>
            )}
          </button>
        </form>

        <div style={{ marginTop: "24px", paddingTop: "16px", borderTop: "1px solid #D9E0E7", textAlign: "center" }}>
          <p style={{ fontSize: "11px", color: "#7B8794" }}>
            Restricted access. All analyst activities are audited with tamper-evident logs.
          </p>
        </div>
      </div>
    </div>
  );
}
