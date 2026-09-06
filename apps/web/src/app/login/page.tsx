import React, { useState } from "react";
import { useNavigate } from "react-router-dom";
import { Shield, Lock, Mail, ArrowRight, RefreshCw, AlertCircle } from "lucide-react";
import { useAuth } from "@/context/AuthContext";
import { ApiError } from "@/lib/api/client";
import { Button, Input } from "@/components/ui";

export default function LoginPage() {
  const navigate = useNavigate();
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
      navigate("/");
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

  const handleFillDemoCredentials = () => {
    setEmail("analyst@threattrace.io");
    setPassword("Password123!");
    setErrorMsg(null);
  };

  return (
    <div className="min-h-screen flex items-center justify-center p-6 bg-nav-bg">
      <div className="w-[400px] bg-bg-panel rounded-[8px] p-8 shadow-sm">
        {/* Header Branding */}
        <div className="text-center mb-6">
          <div className="w-12 h-12 rounded-[12px] bg-primary-soft flex items-center justify-center mx-auto mb-4">
            <Shield className="w-6 h-6 text-primary" />
          </div>
          <h1 className="text-xl font-[700] text-text-primary mb-1">Analyst Authentication</h1>
          <p className="text-xs text-text-secondary">CaseForge Security Operations Center</p>
        </div>

        {/* Error Alert */}
        {errorMsg && (
          <div role="alert" className="flex items-center gap-2 p-3 bg-danger-bg border border-danger rounded-[6px] mb-5">
            <AlertCircle className="w-4 h-4 text-danger shrink-0" />
            <span className="text-[13px] text-critical">{errorMsg}</span>
          </div>
        )}

        {/* Login Form */}
        <form onSubmit={handleSubmit} noValidate className="flex flex-col gap-4">
          <div>
            <label htmlFor="email-input" className="block text-[13px] font-[650] text-text-primary mb-1.5">
              Analyst Email
            </label>
            <div className="relative">
              <Mail className="w-4 h-4 text-text-secondary absolute left-3 top-1/2 -translate-y-1/2" />
              <Input
                id="email-input"
                type="email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                placeholder="analyst@threattrace.io"
                disabled={isSubmitting}
                className="pl-9"
                autoComplete="email"
                required
              />
            </div>
          </div>

          <div>
            <label htmlFor="password-input" className="block text-[13px] font-[650] text-text-primary mb-1.5">
              Passphrase / Credential
            </label>
            <div className="relative">
              <Lock className="w-4 h-4 text-text-secondary absolute left-3 top-1/2 -translate-y-1/2" />
              <Input
                id="password-input"
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="••••••••••••"
                disabled={isSubmitting}
                className="pl-9"
                autoComplete="current-password"
                required
              />
            </div>
          </div>

          <Button
            type="submit"
            variant="primary"
            disabled={isSubmitting}
            className="w-full mt-2 gap-2"
          >
            {isSubmitting ? (
              <>
                <RefreshCw className="w-4 h-4 animate-spin" />
                <span>Authenticating...</span>
              </>
            ) : (
              <>
                <span>Access SOC Console</span>
                <ArrowRight className="w-4 h-4" />
              </>
            )}
          </Button>
        </form>

        {/* Quick Demo Credentials shortcut */}
        <div className="mt-4 pt-3 border-t border-border text-center">
          <button
            type="button"
            onClick={handleFillDemoCredentials}
            className="text-xs text-primary hover:text-primary/80 font-semibold underline underline-offset-2 transition-colors"
          >
            Quick Fill Analyst Credentials (analyst@threattrace.io)
          </button>
        </div>

        {/* Footer info */}
        <div className="mt-4 pt-3 border-t border-border/50 text-center">
          <p className="text-[11px] text-text-muted">
            Restricted access. All analyst activities are audited with tamper-evident logs.
          </p>
        </div>
      </div>
    </div>
  );
}
