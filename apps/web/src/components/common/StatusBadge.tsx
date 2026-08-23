"use client";

import React from "react";

export type StatusVariant =
  | "healthy"
  | "ready"
  | "degraded"
  | "not_ready"
  | "warning"
  | "offline"
  | "loading"
  | "planned";

interface StatusBadgeProps {
  status: string;
  variant?: StatusVariant;
  className?: string;
}

export const StatusBadge: React.FC<StatusBadgeProps> = ({
  status,
  variant,
  className = "",
}) => {
  const normalizedVariant =
    variant ||
    (status.toLowerCase() as StatusVariant);

  return (
    <span className={`status-pill ${normalizedVariant} ${className}`}>
      {status.toUpperCase()}
    </span>
  );
};
