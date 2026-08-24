import React from 'react';
import { AlertCircle, Loader2 } from 'lucide-react';

export const SectionHeader = ({ title, description, className = '' }: { title: string; description?: string; className?: string }) => (
  <div className={`flex flex-col gap-1 mb-6 ${className}`}>
    <h2 className="text-[16px] font-[650] text-text-primary">{title}</h2>
    {description && <p className="text-sm text-text-secondary">{description}</p>}
  </div>
);

export const LoadingState = ({ message = "Loading...", className = '' }: { message?: string, className?: string }) => (
  <div className={`flex flex-col items-center justify-center p-8 gap-3 text-text-muted ${className}`}>
    <Loader2 className="w-6 h-6 animate-spin text-primary" />
    <span className="text-sm">{message}</span>
  </div>
);

export const EmptyState = ({ message = "No data available.", className = '' }: { message?: string, className?: string }) => (
  <div className={`flex flex-col items-center justify-center p-8 border border-dashed border-border rounded-[8px] bg-bg-panel-subtle text-text-secondary ${className}`}>
    <span className="text-sm">{message}</span>
  </div>
);

export const ErrorState = ({ message = "An error occurred.", onRetry, className = '' }: { message?: string, onRetry?: () => void, className?: string }) => (
  <div className={`flex flex-col items-center justify-center p-6 bg-danger-bg border border-danger rounded-[8px] gap-3 ${className}`}>
    <div className="flex items-center gap-2 text-danger">
      <AlertCircle className="w-5 h-5" />
      <span className="text-sm font-semibold">{message}</span>
    </div>
    {onRetry && (
      <button onClick={onRetry} className="text-sm font-semibold text-danger underline hover:text-critical transition-colors">
        Retry
      </button>
    )}
  </div>
);
