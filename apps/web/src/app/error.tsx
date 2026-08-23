"use client";

import React, { useEffect } from "react";
import { AlertTriangle, RefreshCw } from "lucide-react";

export default function Error({
  error,
  reset,
}: {
  error: Error & { digest?: string };
  reset: () => void;
}) {
  useEffect(() => {
    // Log the error to console / monitoring
    console.error("SOC Application Exception:", error);
  }, [error]);

  return (
    <div className="error-container">
      <div className="error-box">
        <div className="w-12 h-12 rounded-full bg-rose-500/10 border border-rose-500/30 flex items-center justify-center">
          <AlertTriangle className="w-6 h-6 text-rose-400" />
        </div>
        <div>
          <h2 className="text-lg font-bold text-white mb-1">SOC Interface Anomaly</h2>
          <p className="text-sm text-gray-400">
            {error.message || "An unexpected error interrupted the investigation interface."}
          </p>
          {error.digest && (
            <p className="text-xs text-gray-500 font-mono mt-1">Digest: {error.digest}</p>
          )}
        </div>
        <button onClick={() => reset()} className="action-btn">
          <RefreshCw className="w-4 h-4" />
          <span>Reload Interface</span>
        </button>
      </div>
    </div>
  );
}
