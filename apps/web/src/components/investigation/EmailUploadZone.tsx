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
import { Box, Typography, Button, Paper, CircularProgress, Chip } from "@mui/material";

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
    <Box>
      {!isAuthenticated ? (
        <Paper 
          elevation={0}
          sx={{ 
            p: 4, 
            textAlign: "center", 
            border: "1px dashed #D9E0E7", 
            bgcolor: "#F5F7FA" 
          }}
        >
          <Box sx={{ width: 48, height: 48, borderRadius: "50%", bgcolor: "#EAF2F8", display: "flex", alignItems: "center", justifyContent: "center", mx: "auto", mb: 2 }}>
            <Lock size={24} color="#1F4E79" />
          </Box>
          <Typography variant="subtitle1" gutterBottom>Analyst Authentication Required</Typography>
          <Typography variant="body2" color="text.secondary" sx={{ maxWidth: 400, mx: "auto", mb: 3 }}>
            In compliance with SOC chain-of-custody protocols, evidence ingestion requires an active analyst session.
          </Typography>
          <Link href="/login" passHref style={{ textDecoration: "none" }}>
            <Button variant="contained" color="primary" endIcon={<ArrowRight size={16} />}>
              Sign In as Analyst
            </Button>
          </Link>
        </Paper>
      ) : (
        <Box sx={{ display: "flex", flexDirection: "column", gap: 3 }}>
          <input
            ref={fileInputRef}
            type="file"
            accept=".eml"
            onChange={handleFileChange}
            style={{ display: "none" }}
            aria-label="Upload suspicious EML file"
          />

          <Paper
            elevation={0}
            onDragOver={handleDragOver}
            onDragLeave={handleDragLeave}
            onDrop={handleDrop}
            onClick={() => !isUploading && fileInputRef.current?.click()}
            sx={{
              p: 6,
              textAlign: "center",
              cursor: isUploading ? "default" : "pointer",
              border: isDragging ? "2px dashed #1F4E79" : "2px dashed #D9E0E7",
              bgcolor: isDragging ? "#EAF2F8" : "#F5F7FA",
              transition: "all 0.2s ease"
            }}
            role="button"
            tabIndex={0}
          >
            {isUploading ? (
              <Box sx={{ display: "flex", flexDirection: "column", alignItems: "center", gap: 2 }}>
                <CircularProgress size={32} thickness={4} sx={{ color: "#1F4E79" }} />
                <Typography variant="subtitle2">Ingesting Evidence & Hashing...</Typography>
                <Typography variant="caption" color="text.secondary" sx={{ fontFamily: "monospace" }}>
                  Computing SHA-256 evidence fingerprint
                </Typography>
              </Box>
            ) : (
              <Box sx={{ display: "flex", flexDirection: "column", alignItems: "center", gap: 2 }}>
                <Box sx={{ p: 2, borderRadius: "50%", bgcolor: "#FFFFFF", boxShadow: "0 1px 3px rgba(16,24,40,0.06)" }}>
                  <UploadCloud size={28} color="#1F4E79" />
                </Box>
                <Typography variant="subtitle2">
                  Drag & Drop suspicious <span style={{ fontFamily: "monospace", color: "#1F4E79" }}>.eml</span> evidence here
                </Typography>
                <Typography variant="body2" color="text.secondary">
                  or click to browse your local filesystem
                </Typography>
                <Box sx={{ display: "flex", gap: 1, mt: 1 }}>
                  <Chip label="Max 10 MB" size="small" variant="outlined" />
                  <Chip label="SHA-256 Verified" size="small" variant="outlined" />
                </Box>
              </Box>
            )}
          </Paper>

          {errorMsg && (
            <Box sx={{ p: 2, display: "flex", alignItems: "center", gap: 1, bgcolor: "#FDECEC", border: "1px solid #C53030", borderRadius: 1 }}>
              <AlertCircle size={16} color="#C53030" />
              <Typography variant="body2" sx={{ color: "#9B1C1C", fontWeight: 500 }}>{errorMsg}</Typography>
            </Box>
          )}

          {lastUploaded && (
            <Paper elevation={0} sx={{ p: 3, border: "1px solid #237A57", bgcolor: "#E8F5EF" }}>
              <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "center", mb: 2, pb: 2, borderBottom: "1px solid rgba(35,122,87,0.2)" }}>
                <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                  <FileCheck size={16} color="#18533B" />
                  <Typography variant="subtitle2" sx={{ color: "#18533B" }}>Evidence Ingested Successfully</Typography>
                </Box>
                <Chip label="RECEIVED" size="small" sx={{ bgcolor: "#237A57", color: "white", fontWeight: 600, fontSize: "10px" }} />
              </Box>
              
              <Box sx={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 2, mb: 3 }}>
                <Box>
                  <Typography variant="caption" sx={{ color: "#18533B", opacity: 0.8 }}>Case Identifier</Typography>
                  <Typography variant="body2" sx={{ fontFamily: "monospace", fontWeight: 600, color: "#18533B" }}>{lastUploaded.case_id}</Typography>
                </Box>
                <Box>
                  <Typography variant="caption" sx={{ color: "#18533B", opacity: 0.8 }}>Original Filename</Typography>
                  <Typography variant="body2" sx={{ fontFamily: "monospace", color: "#18533B" }}>{lastUploaded.file_name}</Typography>
                </Box>
                <Box>
                  <Typography variant="caption" sx={{ color: "#18533B", opacity: 0.8 }}>Evidence Size</Typography>
                  <Typography variant="body2" sx={{ fontFamily: "monospace", color: "#18533B" }}>{(lastUploaded.file_size_bytes / 1024).toFixed(1)} KB</Typography>
                </Box>
                <Box>
                  <Typography variant="caption" sx={{ color: "#18533B", opacity: 0.8 }}>Ingestion Timestamp</Typography>
                  <Typography variant="body2" sx={{ fontFamily: "monospace", color: "#18533B" }}>{new Date(lastUploaded.created_at).toLocaleTimeString()}</Typography>
                </Box>
              </Box>

              <Box sx={{ bgcolor: "rgba(255,255,255,0.7)", p: 2, borderRadius: 1 }}>
                <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 0.5 }}>
                  <Hash size={14} color="#18533B" />
                  <Typography variant="caption" sx={{ fontWeight: 700, color: "#18533B" }}>SHA-256 Evidence Fingerprint</Typography>
                </Box>
                <Typography variant="body2" sx={{ fontFamily: "monospace", wordBreak: "break-all", userSelect: "all", color: "#18533B" }}>
                  {lastUploaded.sha256}
                </Typography>
              </Box>
            </Paper>
          )}
        </Box>
      )}
    </Box>
  );
};
