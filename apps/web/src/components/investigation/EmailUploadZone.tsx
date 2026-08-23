"use client";

import React, { useRef, useState } from "react";
import Link from "next/link";
import {
  UploadCloud,
  FileCheck,
  AlertCircle,
  Hash,
  ArrowRight,
  RefreshCw,
  Lock,
} from "lucide-react";
import { uploadEmailFile } from "@/lib/api/email";
import { EmailUploadResponse } from "@/types";
import { useAuth } from "@/context/AuthContext";
import { ApiError } from "@/lib/api/client";

interface EmailUploadZoneProps {
  onUploadSuccess?: (response: EmailUploadResponse) => void;
}

export const EmailUploadZone: React.FC<EmailUploadZoneProps> = ({ onUploadSuccess }) => {
  const { isAuthenticated } = useAuth();
  const fileInputRef = useRef<HTMLInputElement>(null);

  const [isDragging, setIsDragging] = useState(false);
  const [isUploading, setIsUploading] = useState(false);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const [lastUploaded, setLastUploaded] = useState<EmailUploadResponse | null>(null);

  const handleFile = async (file: File) => {
    setErrorMsg(null);

    // Extension validation
    if (!file.name.toLowerCase().endsWith(".eml")) {
      setErrorMsg("Invalid file format. Please upload an RFC 822 (.eml) email file.");
      return;
    }

    // Size validation (10 MB limit)
    if (file.size > 10 * 1024 * 1024) {
      setErrorMsg("File exceeds maximum allowed upload size of 10 MB.");
      return;
    }

    if (file.size === 0) {
      setErrorMsg("Uploaded email file is empty (0 bytes).");
      return;
    }

    setIsUploading(true);
    try {
      const response = await uploadEmailFile(file);
      setLastUploaded(response);
      if (onUploadSuccess) {
        onUploadSuccess(response);
      }
    } catch (err: unknown) {
      if (err instanceof ApiError) {
        setErrorMsg(err.message);
      } else if (err instanceof Error) {
        setErrorMsg(err.message);
      } else {
        setErrorMsg("Failed to upload evidence file.");
      }
    } finally {
      setIsUploading(false);
    }
  };

  const handleDragOver = (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(true);
  };

  const handleDragLeave = (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(false);
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(false);
    if (!isAuthenticated) return;

    if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
      handleFile(e.dataTransfer.files[0]);
    }
  };

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files.length > 0) {
      handleFile(e.target.files[0]);
    }
  };

  return (
    <div className="card">
      <div className="card-header">
        <div className="flex items-center gap-2">
          <UploadCloud className="w-5 h-5 text-cyan-400" />
          <h2 className="card-title">Evidence Ingestion Dropzone</h2>
        </div>
        <span className="text-xs font-mono text-gray-400">RFC 822 (.eml) Format</span>
      </div>

      {!isAuthenticated ? (
        <div className="unauth-dropzone-banner">
          <div className="w-10 h-10 rounded-full bg-cyan-500/10 border border-cyan-500/30 flex items-center justify-center mb-2">
            <Lock className="w-5 h-5 text-cyan-400" />
          </div>
          <h3 className="text-sm font-semibold text-white">Analyst Authentication Required</h3>
          <p className="text-xs text-gray-400 max-w-md mt-1 mb-3">
            In compliance with SOC chain-of-custody protocols, evidence ingestion requires an active analyst session.
          </p>
          <Link href="/login" className="action-btn">
            <span>Sign In as Analyst</span>
            <ArrowRight className="w-4 h-4" />
          </Link>
        </div>
      ) : (
        <div className="flex flex-col gap-4">
          <input
            ref={fileInputRef}
            type="file"
            accept=".eml"
            onChange={handleFileChange}
            className="hidden"
            aria-label="Upload suspicious EML file"
          />

          <div
            onDragOver={handleDragOver}
            onDragLeave={handleDragLeave}
            onDrop={handleDrop}
            onClick={() => !isUploading && fileInputRef.current?.click()}
            className={`dropzone-box ${isDragging ? "dragging" : ""} ${isUploading ? "uploading" : ""}`}
            role="button"
            tabIndex={0}
          >
            {isUploading ? (
              <div className="flex flex-col items-center gap-2">
                <RefreshCw className="w-8 h-8 text-cyan-400 animate-spin" />
                <p className="text-sm font-semibold text-white">Ingesting Evidence & Hashing...</p>
                <p className="text-xs text-gray-400 font-mono">Computing SHA-256 evidence fingerprint</p>
              </div>
            ) : (
              <div className="flex flex-col items-center gap-2">
                <div className="dropzone-icon-wrap">
                  <UploadCloud className="w-7 h-7 text-cyan-400" />
                </div>
                <p className="text-sm font-semibold text-white">
                  Drag & Drop suspicious <span className="text-cyan-400 font-mono">.eml</span> evidence here
                </p>
                <p className="text-xs text-gray-400">or click to browse your local filesystem</p>
                <div className="flex items-center gap-2 mt-1">
                  <span className="file-limit-pill">Max 10 MB</span>
                  <span className="file-limit-pill">SHA-256 Verified</span>
                </div>
              </div>
            )}
          </div>

          {errorMsg && (
            <div className="auth-error-alert" role="alert">
              <AlertCircle className="w-4 h-4 text-rose-400 flex-shrink-0" />
              <span className="text-xs text-rose-300">{errorMsg}</span>
            </div>
          )}

          {lastUploaded && (
            <div className="evidence-receipt-card">
              <div className="flex items-center justify-between pb-2 border-b border-gray-800">
                <div className="flex items-center gap-2">
                  <FileCheck className="w-4 h-4 text-emerald-400" />
                  <span className="text-xs font-semibold text-gray-200">Evidence Ingested Successfully</span>
                </div>
                <span className="status-pill ready">RECEIVED</span>
              </div>

              <div className="evidence-receipt-grid">
                <div>
                  <span className="evidence-label">Case Identifier</span>
                  <p className="evidence-val font-mono text-cyan-400">{lastUploaded.case_id}</p>
                </div>
                <div>
                  <span className="evidence-label">Original Filename</span>
                  <p className="evidence-val font-mono">{lastUploaded.file_name}</p>
                </div>
                <div>
                  <span className="evidence-label">Evidence Size</span>
                  <p className="evidence-val font-mono">{(lastUploaded.file_size_bytes / 1024).toFixed(1)} KB</p>
                </div>
                <div>
                  <span className="evidence-label">Ingestion Timestamp</span>
                  <p className="evidence-val font-mono">{new Date(lastUploaded.created_at).toLocaleTimeString()}</p>
                </div>
              </div>

              <div className="sha256-receipt-box">
                <div className="flex items-center gap-1.5 mb-1">
                  <Hash className="w-3.5 h-3.5 text-cyan-400" />
                  <span className="text-xs font-mono font-bold text-gray-300">SHA-256 Evidence Fingerprint</span>
                </div>
                <p className="font-mono text-xs text-cyan-300 break-all select-all">{lastUploaded.sha256}</p>
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
};
