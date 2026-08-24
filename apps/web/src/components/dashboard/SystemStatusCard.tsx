"use client";

import React from "react";
import { useHealth, useReadiness } from "@/hooks/useHealth";
import { StatusBadge } from "@/components/common/StatusBadge";
import { Server, Database, Activity, RefreshCw } from "lucide-react";

export const SystemStatusCard: React.FC = () => {
  const {
    data: health,
    isLoading: healthLoading,
    isError: healthError,
    refetch: refetchHealth,
    isFetching: healthFetching,
  } = useHealth();

  const {
    data: readiness,
    isLoading: readyLoading,
    isError: readyError,
    refetch: refetchReady,
    isFetching: readyFetching,
  } = useReadiness();

  const isRefreshing = healthFetching || readyFetching;

  const handleRefresh = () => {
    refetchHealth();
    refetchReady();
  };

  return (
    <div className="card">
      <div className="card-header">
        <div className="flex items-center gap-2">
          <Activity className="w-5 h-5 text-[#1F4E79]" />
          <h2 className="card-title">System Infrastructure Status</h2>
        </div>
        <button
          onClick={handleRefresh}
          disabled={isRefreshing}
          className="refresh-button"
          title="Refresh status"
          aria-label="Refresh telemetry status"
        >
          <RefreshCw
            className={`w-4 h-4 ${isRefreshing ? "animate-spin text-[#1F4E79]" : ""}`}
          />
        </button>
      </div>

      <div className="status-grid">
        {/* API Gateway Status */}
        <div className="status-item">
          <div className="status-item-header">
            <Server className="w-4 h-4 text-[#1F4E79]" />
            <span className="status-item-label">FastAPI Gateway</span>
          </div>
          <div className="status-item-value">
            {healthLoading ? (
              <StatusBadge status="Checking..." variant="loading" />
            ) : healthError || !health ? (
              <StatusBadge status="Offline" variant="offline" />
            ) : (
              <StatusBadge
                status={health.status}
                variant={health.status === "healthy" ? "healthy" : "degraded"}
              />
            )}
          </div>
        </div>

        {/* PostgreSQL Database Status */}
        <div className="status-item">
          <div className="status-item-header">
            <Database className="w-4 h-4 text-[#1F4E79]" />
            <span className="status-item-label">PostgreSQL Database</span>
          </div>
          <div className="status-item-value">
            {readyLoading ? (
              <StatusBadge status="Checking..." variant="loading" />
            ) : readyError || !readiness ? (
              <StatusBadge status="Offline" variant="offline" />
            ) : (
              <StatusBadge
                status={readiness.database}
                variant={readiness.database === "connected" ? "ready" : "warning"}
              />
            )}
          </div>
        </div>

        {/* System Version */}
        <div className="status-item">
          <div className="status-item-header">
            <span className="status-item-label">Core Version</span>
          </div>
          <div className="status-item-meta">
            v{health?.version || "0.1.0"}
          </div>
        </div>

        {/* Environment */}
        <div className="status-item">
          <div className="status-item-header">
            <span className="status-item-label">Environment</span>
          </div>
          <div className="status-item-meta">
            {health?.environment || "development"}
          </div>
        </div>
      </div>

      {health?.timestamp && (
        <div className="card-footer">
          <span>Last telemetry ping: {new Date(health.timestamp).toLocaleTimeString()}</span>
        </div>
      )}
    </div>
  );
};
