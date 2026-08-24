"use client";

import React, { useState } from "react";
import {
  Box,
  Card,
  CardContent,
  Chip,
  IconButton,
  InputAdornment,
  Stack,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  TextField,
  Typography,
  Tooltip,
} from "@mui/material";
import {
  Fingerprint,
  Search,
  Copy,
  Check,
  Globe,
  Mail,
  Hash,
  Radio,
  ExternalLink,
} from "lucide-react";
import { CaseIOCListResponse } from "@/types";

interface IOCTableWidgetProps {
  iocData: CaseIOCListResponse | undefined;
  isLoading?: boolean;
}

export const IOCTableWidget: React.FC<IOCTableWidgetProps> = ({
  iocData,
  isLoading = false,
}) => {
  const [selectedType, setSelectedType] = useState<string>("all");
  const [searchQuery, setSearchQuery] = useState<string>("");
  const [copiedValue, setCopiedValue] = useState<string | null>(null);

  if (isLoading || !iocData) {
    return null;
  }

  const iocs = iocData.iocs || [];

  const handleCopy = (val: string) => {
    navigator.clipboard.writeText(val);
    setCopiedValue(val);
    setTimeout(() => setCopiedValue(null), 2000);
  };

  const filteredIocs = iocs.filter((ioc) => {
    const iocType = ioc.ioc_type || ioc.type || "";
    const matchesType = selectedType === "all" || iocType.toLowerCase() === selectedType.toLowerCase();
    const matchesSearch =
      ioc.value.toLowerCase().includes(searchQuery.toLowerCase()) ||
      ioc.source.toLowerCase().includes(searchQuery.toLowerCase());
    return matchesType && matchesSearch;
  });

  const getTypeIcon = (type: string) => {
    switch (type.toLowerCase()) {
      case "ipv4":
      case "ipv6":
        return <Radio size={12} />;
      case "domain":
        return <Globe size={12} />;
      case "url":
        return <ExternalLink size={12} />;
      case "email":
        return <Mail size={12} />;
      case "sha256":
        return <Hash size={12} />;
      default:
        return <Fingerprint size={12} />;
    }
  };

  const typeOptions = ["all", "ipv4", "ipv6", "domain", "url", "email", "sha256"];

  return (
    <Card
      sx={{
        bgcolor: "background.paper",
        border: "1px solid",
        borderColor: "divider",
        borderRadius: 2,
      }}
    >
      <CardContent sx={{ p: 3 }}>
        {/* Header */}
        <Stack direction={{ xs: "column", sm: "row" }} justifyContent="space-between" alignItems={{ xs: "flex-start", sm: "center" }} spacing={1} mb={2}>
          <Stack direction="row" alignItems="center" spacing={1.5}>
            <Fingerprint className="w-5 h-5 text-[#1F4E79]" />
            <Typography variant="h6" fontWeight={700} color="text.primary">
              Extracted Indicators of Compromise (IOCs)
            </Typography>
          </Stack>

          <Chip
            label={`${iocs.length} Total IOCs`}
            size="small"
            sx={{ bgcolor: "#EAF2F8", color: "#1F4E79", fontWeight: 700 }}
          />
        </Stack>

        {/* Filter & Search Bar */}
        <Stack direction={{ xs: "column", md: "row" }} justifyContent="space-between" spacing={2} mb={2}>
          <Stack direction="row" spacing={0.5} flexWrap="wrap" gap={0.5}>
            {typeOptions.map((t) => {
              const count = t === "all" ? iocs.length : iocData.by_type?.[t] || 0;
              return (
                <Chip
                  key={t}
                  label={`${t.toUpperCase()} (${count})`}
                  size="small"
                  onClick={() => setSelectedType(t)}
                  color={selectedType === t ? "primary" : "default"}
                  variant={selectedType === t ? "filled" : "outlined"}
                  sx={{ fontSize: "0.72rem", cursor: "pointer" }}
                />
              );
            })}
          </Stack>

          <TextField
            size="small"
            placeholder="Search indicator or source..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            InputProps={{
              startAdornment: (
                <InputAdornment position="start">
                  <Search size={14} color="#52606D" />
                </InputAdornment>
              ),
              sx: { fontSize: "0.8rem", width: { xs: "100%", md: 240 } },
            }}
          />
        </Stack>

        {/* IOC Table */}
        {filteredIocs.length === 0 ? (
          <Box p={4} textAlign="center">
            <Typography variant="body2" color="text.secondary">
              No matching indicators found.
            </Typography>
          </Box>
        ) : (
          <TableContainer sx={{ maxHeight: 380 }}>
            <Table size="small" stickyHeader>
              <TableHead>
                <TableRow>
                  <TableCell sx={{ bgcolor: "background.paper", fontWeight: 700 }}>Type</TableCell>
                  <TableCell sx={{ bgcolor: "background.paper", fontWeight: 700 }}>Indicator Value</TableCell>
                  <TableCell sx={{ bgcolor: "background.paper", fontWeight: 700 }}>Source Provenance</TableCell>
                  <TableCell sx={{ bgcolor: "background.paper", fontWeight: 700, textAlign: "right" }}>Confidence</TableCell>
                  <TableCell sx={{ bgcolor: "background.paper", fontWeight: 700, textAlign: "center", width: 50 }}>Copy</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {filteredIocs.map((row, idx) => {
                  const rType = row.ioc_type || row.type || "unknown";
                  return (
                    <TableRow key={idx} hover sx={{ "&:last-child td, &:last-child th": { border: 0 } }}>
                      <TableCell>
                        <Chip
                          icon={getTypeIcon(rType)}
                          label={rType.toUpperCase()}
                          size="small"
                          sx={{ fontSize: "0.65rem", height: 20 }}
                        />
                      </TableCell>
                      <TableCell sx={{ fontFamily: "monospace", fontSize: "0.8rem", color: "cyan.300", wordBreak: "break-all" }}>
                        {row.value}
                      </TableCell>
                      <TableCell sx={{ fontSize: "0.75rem", color: "text.secondary", fontFamily: "monospace" }}>
                        {row.source}
                      </TableCell>
                      <TableCell sx={{ textAlign: "right", fontSize: "0.75rem", fontWeight: 600 }}>
                        {Math.round(row.confidence * 100)}%
                      </TableCell>
                      <TableCell sx={{ textAlign: "center" }}>
                        <Tooltip title={copiedValue === row.value ? "Copied!" : "Copy indicator"}>
                          <IconButton size="small" onClick={() => handleCopy(row.value)}>
                            {copiedValue === row.value ? (
                              <Check size={14} color="#237A57" />
                            ) : (
                              <Copy size={14} color="#52606D" />
                            )}
                          </IconButton>
                        </Tooltip>
                      </TableCell>
                    </TableRow>
                  );
                })}
              </TableBody>
            </Table>
          </TableContainer>
        )}
      </CardContent>
    </Card>
  );
};
