"use client";

import React, { useState, useMemo } from "react";
import {
  Box,
  Card,
  CardContent,
  Chip,
  Divider,
  Grid,
  IconButton,
  LinearProgress,
  Stack,
  Tooltip,
  Typography,
  Alert,
} from "@mui/material";
import {
  Mail,
  User,
  Globe,
  Radio,
  MapPin,
  Paperclip,
  Share2,
  RefreshCw,
  Info,
  AlertCircle,
} from "lucide-react";
import { CaseThreatGraphResponse } from "@/types";

interface ThreatGraphWidgetProps {
  graph?: CaseThreatGraphResponse;
  isLoading?: boolean;
  onRefresh?: () => void;
}

const NODE_COLORS: Record<string, { bg: string; border: string; text: string; iconColor: string }> = {
  Email: { bg: "rgba(59, 130, 246, 0.15)", border: "#3b82f6", text: "#93c5fd", iconColor: "#60a5fa" },
  EmailAddress: { bg: "rgba(14, 165, 233, 0.15)", border: "#0ea5e9", text: "#7dd3fc", iconColor: "#38bdf8" },
  Domain: { bg: "rgba(168, 85, 247, 0.15)", border: "#a855f7", text: "#d8b4fe", iconColor: "#c084fc" },
  IP: { bg: "rgba(245, 158, 11, 0.15)", border: "#f59e0b", text: "#fcd34d", iconColor: "#fbbf24" },
  Country: { bg: "rgba(16, 185, 129, 0.15)", border: "#10b981", text: "#6ee7b7", iconColor: "#34d399" },
  AttachmentHash: { bg: "rgba(244, 63, 94, 0.15)", border: "#f43f5e", text: "#fda4af", iconColor: "#fb7185" },
};

function getNodeIcon(type: string) {
  switch (type) {
    case "Email":
      return <Mail size={16} />;
    case "EmailAddress":
      return <User size={16} />;
    case "Domain":
      return <Globe size={16} />;
    case "IP":
      return <Radio size={16} />;
    case "Country":
      return <MapPin size={16} />;
    case "AttachmentHash":
      return <Paperclip size={16} />;
    default:
      return <Info size={16} />;
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
    <Card sx={{ bgcolor: "background.paper", border: "1px solid", borderColor: "divider", borderRadius: 2 }}>
      {isLoading && <LinearProgress sx={{ height: 2 }} />}

      <CardContent sx={{ p: 3 }}>
        {/* Header */}
        <Stack direction="row" alignItems="center" justifyContent="space-between" mb={2.5}>
          <Box display="flex" alignItems="center" gap={1.5}>
            <Box
              sx={{
                width: 36,
                height: 36,
                borderRadius: 1.5,
                bgcolor: "rgba(168, 85, 247, 0.15)",
                display: "flex",
                alignItems: "center",
                justifyContent: "center",
                color: "#c084fc",
              }}
            >
              <Share2 size={20} />
            </Box>
            <Box>
              <Typography variant="h6" fontWeight={700} color="text.primary">
                Investigation Threat Relationship Graph
              </Typography>
              <Typography variant="caption" color="text.secondary">
                Case-scoped graph of email origin, infrastructure indicators, domain resolutions, and attachment hashes
              </Typography>
            </Box>
          </Box>

          <Stack direction="row" alignItems="center" spacing={1}>
            <Chip
              size="small"
              label={`${graph?.total_nodes || 0} Nodes`}
              sx={{ bgcolor: "rgba(255,255,255,0.06)", fontWeight: 600, fontSize: "0.75rem" }}
            />
            <Chip
              size="small"
              label={`${graph?.total_relationships || 0} Relationships`}
              sx={{ bgcolor: "rgba(255,255,255,0.06)", fontWeight: 600, fontSize: "0.75rem" }}
            />
            {onRefresh && (
              <Tooltip title="Refresh Graph">
                <IconButton size="small" onClick={onRefresh} sx={{ color: "text.secondary" }}>
                  <RefreshCw size={16} />
                </IconButton>
              </Tooltip>
            )}
          </Stack>
        </Stack>

        {/* Legend */}
        <Box
          sx={{
            display: "flex",
            flexWrap: "wrap",
            gap: 1,
            p: 1.5,
            mb: 2.5,
            bgcolor: "rgba(0, 0, 0, 0.2)",
            borderRadius: 1.5,
            border: "1px solid",
            borderColor: "divider",
          }}
        >
          {Object.entries(NODE_COLORS).map(([type, colors]) => (
            <Chip
              key={type}
              size="small"
              icon={<Box sx={{ color: colors.iconColor, display: "flex", ml: 0.5 }}>{getNodeIcon(type)}</Box>}
              label={`${type} (${graph?.node_counts?.[type] || 0})`}
              sx={{
                bgcolor: colors.bg,
                borderColor: colors.border,
                border: "1px solid",
                color: colors.text,
                fontWeight: 600,
                fontSize: "0.72rem",
              }}
            />
          ))}
        </Box>

        {/* Fallback Notice if unavailable */}
        {graph?.status === "unavailable" && (
          <Alert severity="warning" icon={<AlertCircle size={16} />} sx={{ mb: 2 }}>
            {graph.error_message || "Graph database is currently unavailable. Displaying local telemetry fallback."}
          </Alert>
        )}

        <Grid container spacing={2.5}>
          {/* Main 2D SVG Graph Canvas */}
          <Grid item xs={12} lg={selectedNode ? 8 : 12}>
            <Box
              sx={{
                width: "100%",
                height: 480,
                bgcolor: "#0b0f19",
                borderRadius: 2,
                border: "1px solid",
                borderColor: "divider",
                position: "relative",
                overflow: "hidden",
              }}
            >
              {nodes.length === 0 ? (
                <Box
                  display="flex"
                  flexDirection="column"
                  alignItems="center"
                  justifyContent="center"
                  height="100%"
                  gap={1}
                >
                  <Share2 size={36} color="#6b7280" />
                  <Typography variant="body2" color="text.secondary">
                    No graph relationships recorded for this investigation case.
                  </Typography>
                </Box>
              ) : (
                <svg
                  width="100%"
                  height="100%"
                  viewBox="0 0 800 480"
                  style={{ display: "block" }}
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
                      <path d="M 0 1 L 10 5 L 0 9 z" fill="#64748b" />
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
                      <path d="M 0 1 L 10 5 L 0 9 z" fill="#c084fc" />
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
                          stroke={isConnected ? "#c084fc" : "#334155"}
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
                          fill="#0f172a"
                          stroke={isConnected ? "#a855f7" : "#1e293b"}
                          strokeWidth={1}
                        />
                        <text
                          x={midX}
                          y={midY + 3.5}
                          textAnchor="middle"
                          fontSize="9"
                          fill={isConnected ? "#e2e8f0" : "#94a3b8"}
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
                        style={{ cursor: "pointer" }}
                      >
                        {/* Glow / Selection Ring */}
                        {isSelected && (
                          <circle
                            r={26}
                            fill="none"
                            stroke="#c084fc"
                            strokeWidth={2}
                            strokeDasharray="3 3"
                          />
                        )}

                        {/* Node Body */}
                        <circle
                          r={20}
                          fill={colors.bg}
                          stroke={isSelected ? "#c084fc" : colors.border}
                          strokeWidth={isSelected ? 2.5 : 1.5}
                        />

                        {/* Node Label Below */}
                        <text
                          y={34}
                          textAnchor="middle"
                          fontSize="10"
                          fill={isSelected ? "#ffffff" : colors.text}
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
            </Box>
          </Grid>

          {/* Node Details Panel */}
          {selectedNode && (
            <Grid item xs={12} lg={4}>
              <Card
                sx={{
                  bgcolor: "rgba(15, 23, 42, 0.6)",
                  border: "1px solid",
                  borderColor: "divider",
                  borderRadius: 2,
                  height: "100%",
                }}
              >
                <CardContent sx={{ p: 2.5 }}>
                  <Stack direction="row" alignItems="center" justifyContent="space-between" mb={2}>
                    <Typography variant="subtitle2" fontWeight={700} color="text.primary">
                      Node Telemetry
                    </Typography>
                    <Chip
                      size="small"
                      label={selectedNode.type}
                      sx={{
                        bgcolor: NODE_COLORS[selectedNode.type]?.bg,
                        color: NODE_COLORS[selectedNode.type]?.text,
                        borderColor: NODE_COLORS[selectedNode.type]?.border,
                        border: "1px solid",
                        fontWeight: 700,
                        fontSize: "0.7rem",
                      }}
                    />
                  </Stack>

                  <Stack spacing={1.5}>
                    <Box>
                      <Typography variant="caption" color="text.secondary">Identifier</Typography>
                      <Typography variant="body2" sx={{ fontFamily: "monospace", color: "cyan.300", wordBreak: "break-all" }}>
                        {selectedNode.id}
                      </Typography>
                    </Box>

                    <Box>
                      <Typography variant="caption" color="text.secondary">Label / Value</Typography>
                      <Typography variant="body2" fontWeight={600} color="text.primary" sx={{ wordBreak: "break-all" }}>
                        {selectedNode.label}
                      </Typography>
                    </Box>

                    {selectedNode.properties && Object.keys(selectedNode.properties).length > 0 && (
                      <Box>
                        <Typography variant="caption" color="text.secondary">Properties</Typography>
                        <Box sx={{ p: 1, bgcolor: "rgba(0,0,0,0.3)", borderRadius: 1, mt: 0.5 }}>
                          {Object.entries(selectedNode.properties).map(([k, v]) => (
                            <Typography key={k} variant="caption" display="block" sx={{ fontFamily: "monospace", color: "#94a3b8" }}>
                              {k}: {String(v)}
                            </Typography>
                          ))}
                        </Box>
                      </Box>
                    )}

                    <Divider sx={{ my: 1 }} />

                    <Typography variant="caption" fontWeight={700} color="text.secondary">
                      Connected Relationships ({connectedRelationships.length})
                    </Typography>

                    <Stack spacing={1}>
                      {connectedRelationships.map((r) => (
                        <Box
                          key={r.id}
                          sx={{
                            p: 1,
                            bgcolor: "rgba(255,255,255,0.03)",
                            border: "1px solid",
                            borderColor: "divider",
                            borderRadius: 1,
                          }}
                        >
                          <Typography variant="caption" fontWeight={700} color="secondary.light" display="block">
                            {r.type}
                          </Typography>
                          <Typography variant="caption" color="text.secondary" sx={{ fontFamily: "monospace" }}>
                            {r.source === selectedNode.id ? `→ ${r.target}` : `← ${r.source}`}
                          </Typography>
                        </Box>
                      ))}
                    </Stack>
                  </Stack>
                </CardContent>
              </Card>
            </Grid>
          )}
        </Grid>
      </CardContent>
    </Card>
  );
};
