"use client";

import React from "react";
import { useHealth } from "@/hooks/useHealth";
import { Server, Database, Activity, RefreshCw } from "lucide-react";

export const SystemStatusCard: React.FC = () => {
  const { data: health, isLoading, isError, refetch, isFetching } = useHealth();

  return (
    <div className="card">
      <div className="card-header">
        <div className="flex items-center gap-2">
          <Activity className="w-5 h-5 text-cyan-400" />
          <h2 className="card-title">System Infrastructure Status</h2>
        </div>
        <button
          onClick={() => refetch()}
          disabled={isFetching}
          className="refresh-button"
          title="Refresh status"
        >
          <RefreshCw className={`w-4 h-4 ${isFetching ? "animate-spin text-cyan-400" : ""}`} />
        </button>
      </div>

      <div className="status-grid">
        {/* API Gateway Status */}
        <div className="status-item">
          <div className="status-item-header">
            <Server className="w-4 h-4 text-cyan-400" />
            <span className="status-item-label">FastAPI Gateway</span>
          </div>
          <div className="status-item-value">
            {isLoading ? (
              <span className="status-pill loading">Checking...</span>
            ) : isError || !health ? (
              <span className="status-pill offline">Offline</span>
            ) : (
              <span className={`status-pill ${health.status === "healthy" ? "healthy" : "degraded"}`}>
                {health.status.toUpperCase()}
              </span>
            )}
          </div>
        </div>

        {/* Database Status */}
        <div className="status-item">
          <div className="status-item-header">
            <Database className="w-4 h-4 text-cyan-400" />
            <span className="status-item-label">PostgreSQL Database</span>
          </div>
          <div className="status-item-value">
            {isLoading ? (
              <span className="status-pill loading">Checking...</span>
            ) : isError || !health ? (
              <span className="status-pill offline">Unknown</span>
            ) : (
              <span className={`status-pill ${health.database === "connected" ? "healthy" : "warning"}`}>
                {health.database.toUpperCase()}
              </span>
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
