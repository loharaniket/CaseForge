"use client";

import React from "react";
import { RefreshCw, Shield } from "lucide-react";

interface LoadingViewProps {
  message?: string;
}

export const LoadingView: React.FC<LoadingViewProps> = ({
  message = "Initializing CaseForge SOC telemetry...",
}) => {
  return (
    <div className="loading-container">
      <div className="loading-box">
        <div className="loading-icon-wrap">
          <Shield className="w-8 h-8 text-cyan-400" />
          <RefreshCw className="w-4 h-4 text-cyan-400 animate-spin loading-spinner" />
        </div>
        <p className="loading-text">{message}</p>
      </div>
    </div>
  );
};
