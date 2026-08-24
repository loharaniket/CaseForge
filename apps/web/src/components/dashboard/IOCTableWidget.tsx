"use client";

import React, { useState } from "react";
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
import { Card, CardContent, Badge, Table, Thead, Tbody, Tr, Th, Td, Input } from "@/components/ui";

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
        return <Radio className="w-3.5 h-3.5" />;
      case "domain":
        return <Globe className="w-3.5 h-3.5" />;
      case "url":
        return <ExternalLink className="w-3.5 h-3.5" />;
      case "email":
        return <Mail className="w-3.5 h-3.5" />;
      case "sha256":
        return <Hash className="w-3.5 h-3.5" />;
      default:
        return <Fingerprint className="w-3.5 h-3.5" />;
    }
  };

  const typeOptions = ["all", "ipv4", "ipv6", "domain", "url", "email", "sha256"];

  return (
    <Card>
      <CardContent className="p-6">
        {/* Header */}
        <div className="flex flex-col sm:flex-row justify-between sm:items-center gap-2 mb-4">
          <div className="flex items-center gap-3">
            <Fingerprint className="w-5 h-5 text-primary" />
            <h3 className="text-[16px] font-[700] text-text-primary">
              Extracted Indicators of Compromise (IOCs)
            </h3>
          </div>

          <Badge variant="neutral" className="bg-primary-soft text-primary font-[700] border-transparent px-2 py-0.5">
            {iocs.length} Total IOCs
          </Badge>
        </div>

        {/* Filter & Search Bar */}
        <div className="flex flex-col md:flex-row justify-between md:items-center gap-4 mb-4">
          <div className="flex flex-wrap items-center gap-1.5">
            {typeOptions.map((t) => {
              const count = t === "all" ? iocs.length : iocData.by_type?.[t] || 0;
              const isSelected = selectedType === t;
              return (
                <button
                  key={t}
                  onClick={() => setSelectedType(t)}
                  className={`text-[11px] font-[600] px-2 py-1 rounded-[6px] transition-colors border ${
                    isSelected 
                      ? "bg-primary text-white border-primary" 
                      : "bg-bg-page text-text-secondary border-border hover:bg-bg-panel-subtle hover:text-text-primary"
                  }`}
                >
                  {t.toUpperCase()} ({count})
                </button>
              );
            })}
          </div>

          <div className="relative w-full md:w-64">
            <Search className="w-4 h-4 text-text-secondary absolute left-3 top-1/2 -translate-y-1/2" />
            <Input
              placeholder="Search indicator or source..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="pl-9 h-8 text-[13px]"
            />
          </div>
        </div>

        {/* IOC Table */}
        <div className="border border-border rounded-[8px] overflow-hidden">
          <Table className="border-none rounded-none">
            <Thead>
              <Tr className="bg-bg-panel-subtle border-b border-border">
                <Th className="text-[10px]">INDICATOR VALUE</Th>
                <Th className="text-[10px]">TYPE</Th>
                <Th className="text-[10px]">EXTRACTION SOURCE</Th>
                <Th className="text-[10px] text-center">CONFIDENCE</Th>
              </Tr>
            </Thead>
            <Tbody>
              {filteredIocs.length === 0 ? (
                <Tr>
                  <Td colSpan={4} className="py-8 text-center text-sm text-text-muted">
                    No matching indicators found.
                  </Td>
                </Tr>
              ) : (
                filteredIocs.map((ioc, idx) => (
                  <Tr key={idx}>
                    <Td>
                      <div className="flex items-center gap-2">
                        <span className="font-mono text-[13px] font-[600] text-primary break-all">
                          {ioc.value}
                        </span>
                        <button
                          onClick={() => handleCopy(ioc.value)}
                          className="p-1 hover:bg-bg-panel-subtle rounded text-text-secondary hover:text-text-primary transition-colors shrink-0"
                          title="Copy IOC"
                        >
                          {copiedValue === ioc.value ? (
                            <Check className="w-3.5 h-3.5 text-success" />
                          ) : (
                            <Copy className="w-3.5 h-3.5" />
                          )}
                        </button>
                      </div>
                    </Td>
                    <Td>
                      <Badge variant="neutral" className="gap-1 bg-bg-panel-subtle text-text-secondary text-[10px] uppercase font-[700] px-1.5 py-0.5">
                        {getTypeIcon(ioc.ioc_type || ioc.type || "")}
                        {ioc.ioc_type || ioc.type}
                      </Badge>
                    </Td>
                    <Td className="text-[12px] text-text-secondary truncate max-w-[200px]" title={ioc.source}>
                      {ioc.source}
                    </Td>
                    <Td className="text-center">
                      <Badge 
                        variant={
                          (ioc.confidence || 0) >= 0.8 ? "danger" : 
                          (ioc.confidence || 0) >= 0.5 ? "warning" : "neutral"
                        }
                        className="text-[10px]"
                      >
                        {Math.round((ioc.confidence || 1) * 100)}%
                      </Badge>
                    </Td>
                  </Tr>
                ))
              )}
            </Tbody>
          </Table>
        </div>
      </CardContent>
    </Card>
  );
};
