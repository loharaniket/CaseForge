"use client";

import React, { useState, useMemo } from "react";
import {
  Mail,
  User,
  Globe,
  Radio,
  MapPin,
  Paperclip,
  Share2,
  Link,
  Briefcase,
  Server,
  FileSearch,
  RefreshCw,
  Info,
  AlertCircle,
} from "lucide-react";
import { CaseThreatGraphResponse } from "@/types";
import { Card, CardContent, Badge, Button, LoadingState } from "@/components/ui";

interface ThreatGraphWidgetProps {
  graph?: CaseThreatGraphResponse;
  isLoading?: boolean;
  onRefresh?: () => void;
}

const NODE_COLORS: Record<string, { bg: string; border: string; text: string; iconColor: string }> = {
  Email: { bg: "#EAF2F8", border: "#1F4E79", text: "#17212B", iconColor: "#1F4E79" },
  EmailAddress: { bg: "#EAF2F8", border: "#2B6CB0", text: "#17212B", iconColor: "#2B6CB0" },
  Domain: { bg: "#F3E8FF", border: "#7E22CE", text: "#17212B", iconColor: "#7E22CE" },
  IP: { bg: "#FFF7E6", border: "#B7791F", text: "#17212B", iconColor: "#B7791F" },
  Country: { bg: "#E8F5EF", border: "#237A57", text: "#17212B", iconColor: "#237A57" },
  AttachmentHash: { bg: "#FDECEC", border: "#C53030", text: "#17212B", iconColor: "#C53030" },
  URL: { bg: "#FFF4E5", border: "#DD6B20", text: "#17212B", iconColor: "#DD6B20" },
  ASN: { bg: "#E2E8F0", border: "#4A5568", text: "#17212B", iconColor: "#4A5568" },
  Organization: { bg: "#EDF2F7", border: "#2D3748", text: "#17212B", iconColor: "#2D3748" },
  IOC: { bg: "#FEEBC8", border: "#C05621", text: "#17212B", iconColor: "#C05621" },
  Case: { bg: "#E6FFFA", border: "#319795", text: "#17212B", iconColor: "#319795" },
};

function getNodeIcon(type: string) {
  switch (type) {
    case "Email":
      return <Mail className="w-4 h-4" />;
    case "EmailAddress":
      return <User className="w-4 h-4" />;
    case "Domain":
      return <Globe className="w-4 h-4" />;
    case "IP":
      return <Radio className="w-4 h-4" />;
    case "Country":
      return <MapPin className="w-4 h-4" />;
    case "AttachmentHash":
      return <Paperclip className="w-4 h-4" />;
    case "URL":
      return <Link className="w-4 h-4" />;
    case "ASN":
      return <Server className="w-4 h-4" />;
    case "Organization":
      return <Briefcase className="w-4 h-4" />;
    case "IOC":
      return <FileSearch className="w-4 h-4" />;
    case "Case":
      return <Share2 className="w-4 h-4" />;
    default:
      return <Info className="w-4 h-4" />;
  }
}

export const ThreatGraphWidget: React.FC<ThreatGraphWidgetProps> = ({
  graph,
  isLoading = false,
  onRefresh,
}) => {
  const [selectedNodeId, setSelectedNodeId] = useState<string | null>(null);

  const nodes = useMemo(() => graph?.nodes || [], [graph]);
  const relationships = useMemo(() => graph?.relationships || [], [graph]);

  // Compute 2D node coordinates deterministically
  const nodePositions = useMemo(() => {
    const positions: Record<string, { x: number; y: number }> = {};
    if (nodes.length === 0) return positions;

    const width = 800;
    const height = 480;
    const cx = width / 2;
    const cy = height / 2;

    // Find root email node
    const emailNode = nodes.find((n) => n.type === "Email") || nodes[0];
    positions[emailNode.id] = { x: cx, y: cy };

    // Group other nodes by type
    const senders = nodes.filter((n) => n.type === "EmailAddress" && n.id !== emailNode.id);
    const domains = nodes.filter((n) => n.type === "Domain");
    const ips = nodes.filter((n) => n.type === "IP");
    const countries = nodes.filter((n) => n.type === "Country");
    const hashes = nodes.filter((n) => n.type === "AttachmentHash");

    // Tier 1: Direct connections from Email (Senders left, Domains top/right, Hashes bottom)
    senders.forEach((s, idx) => {
      const step = 60;
      positions[s.id] = { x: cx - 240, y: cy - 60 + idx * step };
    });

    hashes.forEach((h, idx) => {
      positions[h.id] = { x: cx - 180 + idx * 160, y: cy + 160 };
    });

    domains.forEach((d, idx) => {
      const angle = -Math.PI / 4 + (idx * Math.PI) / 3;
      const radius = 180;
      positions[d.id] = {
        x: cx + radius * Math.cos(angle),
        y: cy + radius * Math.sin(angle),
      };
    });

    // Tier 2: IPs connected from Domains
    ips.forEach((ip, idx) => {
      const angle = (idx * Math.PI) / 4;
      const radius = 280;
      positions[ip.id] = {
        x: cx + radius * Math.cos(angle),
        y: cy + radius * Math.sin(angle),
      };
    });

    // Tier 3: Countries connected from IPs
    countries.forEach((c, idx) => {
      positions[c.id] = {
        x: cx + 330,
        y: cy - 100 + idx * 80,
      };
    });

    // Fallback for any unpositioned node
    nodes.forEach((n, idx) => {
      if (!positions[n.id]) {
        const angle = (idx / nodes.length) * 2 * Math.PI;
        positions[n.id] = {
          x: cx + 220 * Math.cos(angle),
          y: cy + 220 * Math.sin(angle),
        };
      }
    });

    return positions;
  }, [nodes]);

  const selectedNode = useMemo(
    () => nodes.find((n) => n.id === selectedNodeId) || null,
    [nodes, selectedNodeId]
  );

  const connectedRelationships = useMemo(() => {
    if (!selectedNodeId) return [];
    return relationships.filter(
      (r) => r.source === selectedNodeId || r.target === selectedNodeId
    );
  }, [relationships, selectedNodeId]);

  return (
    <Card className="overflow-hidden">
      {isLoading && (
        <div className="w-full h-1 bg-border overflow-hidden">
          <div className="h-full bg-primary animate-pulse w-1/3 rounded"></div>
        </div>
      )}

      <CardContent className="p-6">
        {/* Header */}
        <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 mb-6">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-[8px] bg-indigo-50 border border-indigo-100 flex items-center justify-center text-indigo-700">
              <Share2 className="w-5 h-5" />
            </div>
            <div className="flex flex-col">
              <h3 className="text-[16px] font-[700] text-text-primary">
                Investigation Threat Relationship Graph
              </h3>
              <span className="text-[12px] text-text-secondary">
                Case-scoped graph of email origin, infrastructure indicators, domain resolutions, and attachment hashes
              </span>
            </div>
          </div>

          <div className="flex items-center gap-2">
            <Badge variant="neutral" className="bg-bg-panel-subtle text-text-secondary border-border font-[600] px-2 py-0.5">
              {graph?.total_nodes || 0} Nodes
            </Badge>
            <Badge variant="neutral" className="bg-bg-panel-subtle text-text-secondary border-border font-[600] px-2 py-0.5">
              {graph?.total_relationships || 0} Relationships
            </Badge>
            {onRefresh && (
              <button 
                onClick={onRefresh} 
                className="p-1.5 rounded-[6px] text-text-secondary hover:bg-bg-panel-subtle hover:text-text-primary transition-colors border border-transparent hover:border-border"
                title="Refresh Graph"
              >
                <RefreshCw className="w-4 h-4" />
              </button>
            )}
          </div>
        </div>

        {/* Legend */}
        <div className="flex flex-wrap gap-2 p-3 mb-6 bg-bg-panel border border-border rounded-[8px]">
          {Object.entries(NODE_COLORS).map(([type, colors]) => (
            <div
              key={type}
              className="flex items-center gap-1.5 px-2 py-1 rounded-[6px] text-[11px] font-[600] border"
              style={{
                backgroundColor: colors.bg,
                borderColor: colors.border,
                color: colors.text,
              }}
            >
              <div style={{ color: colors.iconColor }} className="flex items-center">
                {getNodeIcon(type)}
              </div>
              <span>{type} ({graph?.node_counts?.[type] || 0})</span>
            </div>
          ))}
        </div>

        {/* Fallback Notice if unavailable */}
        {graph?.status === "unavailable" && (
          <div className="flex items-start gap-2 p-3 bg-warning-bg border border-warning rounded-[6px] mb-4 text-warning-dark text-xs">
            <AlertCircle className="w-4 h-4 shrink-0 mt-0.5" />
            <span>
              {graph.error_message || "Graph database is currently unavailable. Displaying local telemetry fallback."}
            </span>
          </div>
        )}

        <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
          {/* Main 2D SVG Graph Canvas */}
          <div className={`col-span-1 ${selectedNode ? "lg:col-span-8" : "lg:col-span-12"}`}>
            <div className="w-full h-[480px] bg-slate-50 rounded-[8px] border border-border relative overflow-hidden">
              {nodes.length === 0 ? (
                <div className="flex flex-col items-center justify-center h-full gap-3 text-text-secondary">
                  <Share2 className="w-10 h-10 text-text-muted" />
                  <span className="text-sm font-[500]">
                    No graph relationships recorded for this investigation case.
                  </span>
                </div>
              ) : (
                <svg
                  width="100%"
                  height="100%"
                  viewBox="0 0 800 480"
                  className="block"
                >
                  <defs>
                    <marker
                      id="arrow"
                      viewBox="0 0 10 10"
                      refX="24"
                      refY="5"
                      markerWidth="6"
                      markerHeight="6"
                      orient="auto-start-reverse"
                    >
                      <path d="M 0 1 L 10 5 L 0 9 z" fill="#94a3b8" />
                    </marker>
                    <marker
                      id="arrow-active"
                      viewBox="0 0 10 10"
                      refX="24"
                      refY="5"
                      markerWidth="6"
                      markerHeight="6"
                      orient="auto-start-reverse"
                    >
                      <path d="M 0 1 L 10 5 L 0 9 z" fill="#1F4E79" />
                    </marker>
                  </defs>

                  {/* Relationship Lines */}
                  {relationships.map((rel) => {
                    const src = nodePositions[rel.source];
                    const tgt = nodePositions[rel.target];
                    if (!src || !tgt) return null;

                    const isConnected =
                      selectedNodeId &&
                      (rel.source === selectedNodeId || rel.target === selectedNodeId);

                    const midX = (src.x + tgt.x) / 2;
                    const midY = (src.y + tgt.y) / 2;

                    return (
                      <g key={rel.id}>
                        <line
                          x1={src.x}
                          y1={src.y}
                          x2={tgt.x}
                          y2={tgt.y}
                          stroke={isConnected ? "#1F4E79" : "#e2e8f0"}
                          strokeWidth={isConnected ? 2.5 : 1.5}
                          strokeDasharray={rel.type === "RESOLVES_TO" ? "4 4" : undefined}
                          markerEnd={isConnected ? "url(#arrow-active)" : "url(#arrow)"}
                        />
                        {/* Relationship Label Pill */}
                        <rect
                          x={midX - 38}
                          y={midY - 9}
                          width={76}
                          height={18}
                          rx={9}
                          fill="#f8fafc"
                          stroke={isConnected ? "#1F4E79" : "#f1f5f9"}
                          strokeWidth={1}
                        />
                        <text
                          x={midX}
                          y={midY + 3.5}
                          textAnchor="middle"
                          fontSize="9"
                          fill={isConnected ? "#0f172a" : "#64748b"}
                          fontFamily="monospace"
                          fontWeight={600}
                        >
                          {rel.type}
                        </text>
                      </g>
                    );
                  })}

                  {/* Nodes */}
                  {nodes.map((node) => {
                    const pos = nodePositions[node.id];
                    if (!pos) return null;

                    const colors = NODE_COLORS[node.type] || NODE_COLORS.Email;
                    const isSelected = selectedNodeId === node.id;

                    return (
                      <g
                        key={node.id}
                        transform={`translate(${pos.x}, ${pos.y})`}
                        onClick={() => setSelectedNodeId(node.id === selectedNodeId ? null : node.id)}
                        className="cursor-pointer"
                      >
                        {/* Glow / Selection Ring */}
                        {isSelected && (
                          <circle
                            r={26}
                            fill="none"
                            stroke="#1F4E79"
                            strokeWidth={2}
                            strokeDasharray="3 3"
                          />
                        )}

                        {/* Node Body */}
                        <circle
                          r={20}
                          fill={colors.bg}
                          stroke={isSelected ? "#1F4E79" : colors.border}
                          strokeWidth={isSelected ? 2.5 : 1.5}
                        />

                        {/* Node Label Below */}
                        <text
                          y={34}
                          textAnchor="middle"
                          fontSize="10"
                          fill={isSelected ? "#000" : colors.text}
                          fontWeight={isSelected ? 700 : 500}
                          fontFamily="sans-serif"
                        >
                          {node.label.length > 20 ? `${node.label.slice(0, 18)}...` : node.label}
                        </text>

                        {/* Node Type Pill */}
                        <text
                          y={46}
                          textAnchor="middle"
                          fontSize="8"
                          fill="#64748b"
                          fontFamily="monospace"
                        >
                          {node.type}
                        </text>
                      </g>
                    );
                  })}
                </svg>
              )}
            </div>
          </div>

          {/* Node Details Panel */}
          {selectedNode && (
            <div className="col-span-1 lg:col-span-4">
              <div className="h-full bg-slate-900 border border-slate-800 rounded-[8px] p-5">
                <div className="flex items-center justify-between mb-4 pb-3 border-b border-slate-800">
                  <h4 className="text-[13px] font-[700] text-slate-100 uppercase tracking-wider">
                    Node Telemetry
                  </h4>
                  <div
                    className="px-2 py-0.5 rounded-[4px] text-[10px] font-[700] border"
                    style={{
                      backgroundColor: NODE_COLORS[selectedNode.type]?.bg,
                      color: NODE_COLORS[selectedNode.type]?.text,
                      borderColor: NODE_COLORS[selectedNode.type]?.border,
                    }}
                  >
                    {selectedNode.type}
                  </div>
                </div>

                <div className="flex flex-col gap-4">
                  <div className="flex flex-col gap-1">
                    <span className="text-[11px] text-slate-400 uppercase font-[600]">Identifier</span>
                    <span className="text-[12px] font-mono text-cyan-300 break-all bg-slate-950 p-1.5 rounded border border-slate-800">
                      {selectedNode.id}
                    </span>
                  </div>

                  <div className="flex flex-col gap-1">
                    <span className="text-[11px] text-slate-400 uppercase font-[600]">Label / Value</span>
                    <span className="text-[13px] font-[600] text-slate-200 break-all">
                      {selectedNode.label}
                    </span>
                  </div>

                  {selectedNode.properties && Object.keys(selectedNode.properties).length > 0 && (
                    <div className="flex flex-col gap-1">
                      <span className="text-[11px] text-slate-400 uppercase font-[600]">Properties</span>
                      <div className="bg-slate-950 p-2 rounded-[6px] border border-slate-800 flex flex-col gap-1">
                        {Object.entries(selectedNode.properties).map(([k, v]) => (
                          <div key={k} className="flex gap-2">
                            <span className="text-[11px] text-slate-500 font-mono shrink-0">{k}:</span>
                            <span className="text-[11px] text-slate-300 font-mono break-all">{String(v)}</span>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}

                  <div className="mt-2 pt-4 border-t border-slate-800 flex flex-col gap-2">
                    <span className="text-[12px] font-[700] text-slate-300">
                      Connected Relationships ({connectedRelationships.length})
                    </span>

                    <div className="flex flex-col gap-2 max-h-[160px] overflow-y-auto pr-1 custom-scrollbar">
                      {connectedRelationships.map((r) => (
                        <div
                          key={r.id}
                          className="p-2 bg-slate-800/50 border border-slate-700 rounded-[6px]"
                        >
                          <span className="text-[11px] font-[700] text-indigo-300 block mb-1">
                            {r.type}
                          </span>
                          <span className="text-[11px] text-slate-400 font-mono break-all">
                            {r.source === selectedNode.id ? `→ ${r.target}` : `← ${r.source}`}
                          </span>
                        </div>
                      ))}
                    </div>
                  </div>
                </div>
              </div>
            </div>
          )}
        </div>
      </CardContent>
    </Card>
  );
};
