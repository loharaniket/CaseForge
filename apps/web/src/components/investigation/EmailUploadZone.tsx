"use client";

import React, { useRef, useState } from "react";
import Link from "next/link";
import {
  UploadCloud,
  FileCheck,
  AlertCircle,
  Hash,
  ArrowRight,
  Loader2,
  Lock,
} from "lucide-react";
import { uploadEmailFile } from "@/lib/api/email";
import { EmailUploadResponse } from "@/types";
import { useAuth } from "@/context/AuthContext";
import { ApiError } from "@/lib/api/client";
import { Button, Badge } from "@/components/ui";

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

    if (!file.name.toLowerCase().endsWith(".eml")) {
      setErrorMsg("Invalid file format. Please upload an RFC 822 (.eml) email file.");
      return;
    }
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
    <div className="flex flex-col gap-6">
      {!isAuthenticated ? (
        <div className="flex flex-col items-center text-center p-8 border border-dashed border-border rounded-[8px] bg-bg-page">
          <div className="w-12 h-12 rounded-full bg-primary-soft flex items-center justify-center mb-4">
            <Lock className="w-6 h-6 text-primary" />
          </div>
          <h3 className="text-[15px] font-[650] text-text-primary mb-2">Analyst Authentication Required</h3>
          <p className="text-sm text-text-secondary max-w-[400px] mx-auto mb-6">
            In compliance with SOC chain-of-custody protocols, evidence ingestion requires an active analyst session.
          </p>
          <Link href="/login" className="no-underline">
            <Button variant="primary" className="gap-2">
              <span>Sign In as Analyst</span>
              <ArrowRight className="w-4 h-4" />
            </Button>
          </Link>
        </div>
      ) : (
        <div className="flex flex-col gap-6">
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
            className={`flex flex-col items-center justify-center p-12 text-center rounded-[8px] transition-all duration-200 ${isUploading ? "cursor-default border-2 border-dashed border-border bg-bg-page" : "cursor-pointer"} ${isDragging ? "border-2 border-dashed border-primary bg-primary-soft" : "border-2 border-dashed border-border bg-bg-page hover:bg-bg-panel-subtle"}`}
            role="button"
            tabIndex={0}
          >
            {isUploading ? (
              <div className="flex flex-col items-center gap-4">
                <Loader2 className="w-8 h-8 animate-spin text-primary" />
                <div className="flex flex-col">
                  <span className="text-[14px] font-[650] text-text-primary">Ingesting Evidence & Hashing...</span>
                  <span className="text-[12px] text-text-secondary font-mono mt-1">Computing SHA-256 evidence fingerprint</span>
                </div>
              </div>
            ) : (
              <div className="flex flex-col items-center gap-3">
                <div className="p-3 rounded-full bg-white shadow-sm mb-2">
                  <UploadCloud className="w-7 h-7 text-primary" />
                </div>
                <div className="text-[14px] font-[600] text-text-primary">
                  Drag & Drop suspicious <span className="font-mono text-primary bg-primary-soft px-1 rounded">.eml</span> evidence here
                </div>
                <div className="text-[13px] text-text-secondary">
                  or click to browse your local filesystem
                </div>
                <div className="flex gap-2 mt-3">
                  <Badge variant="neutral">Max 10 MB</Badge>
                  <Badge variant="neutral">SHA-256 Verified</Badge>
                </div>
              </div>
            )}
          </div>

          {errorMsg && (
            <div className="flex items-center gap-2 p-4 bg-danger-bg border border-danger rounded-[8px]">
              <AlertCircle className="w-4 h-4 text-danger shrink-0" />
              <span className="text-[13px] font-[500] text-critical">{errorMsg}</span>
            </div>
          )}

          {lastUploaded && (
            <div className="p-6 border border-success bg-success-bg rounded-[8px]">
              <div className="flex justify-between items-center pb-4 mb-4 border-b border-[#237A57]/20">
                <div className="flex items-center gap-2">
                  <FileCheck className="w-4 h-4 text-[#18533B]" />
                  <span className="text-[14px] font-[650] text-[#18533B]">Evidence Ingested Successfully</span>
                </div>
                <Badge variant="success" className="bg-success text-white border-success tracking-wide px-2 py-0.5">RECEIVED</Badge>
              </div>
              
              <div className="grid grid-cols-2 gap-4 mb-5">
                <div className="flex flex-col">
                  <span className="text-[11px] text-[#18533B] opacity-80 uppercase tracking-wider font-semibold">Case Identifier</span>
                  <span className="font-mono font-[600] text-[13px] text-[#18533B]">{lastUploaded.case_id}</span>
                </div>
                <div className="flex flex-col">
                  <span className="text-[11px] text-[#18533B] opacity-80 uppercase tracking-wider font-semibold">Original Filename</span>
                  <span className="font-mono text-[13px] text-[#18533B] truncate" title={lastUploaded.file_name}>{lastUploaded.file_name}</span>
                </div>
                <div className="flex flex-col">
                  <span className="text-[11px] text-[#18533B] opacity-80 uppercase tracking-wider font-semibold">Evidence Size</span>
                  <span className="font-mono text-[13px] text-[#18533B]">{(lastUploaded.file_size_bytes / 1024).toFixed(1)} KB</span>
                </div>
                <div className="flex flex-col">
                  <span className="text-[11px] text-[#18533B] opacity-80 uppercase tracking-wider font-semibold">Ingestion Timestamp</span>
                  <span className="font-mono text-[13px] text-[#18533B]">{new Date(lastUploaded.created_at).toLocaleTimeString()}</span>
                </div>
              </div>

              <div className="bg-white/70 p-4 rounded-[6px]">
                <div className="flex items-center gap-1.5 mb-1">
                  <Hash className="w-3.5 h-3.5 text-[#18533B]" />
                  <span className="text-[12px] font-[700] text-[#18533B]">SHA-256 Evidence Fingerprint</span>
                </div>
                <span className="font-mono text-[13px] break-all select-all text-[#18533B]">
                  {lastUploaded.sha256}
                </span>
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
};
