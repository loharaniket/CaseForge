import React from "react";
import { useQuery } from "@tanstack/react-query";
import { Link2 } from "lucide-react";
import { Card, CardContent, CardHeader, Badge } from "@/components/ui";
import { getCaseCampaigns } from "@/lib/api/email";

export function CampaignWidget({ caseId }: { caseId: string }) {
  const { data: campaigns, isLoading, error } = useQuery({
    queryKey: ["case", caseId, "campaigns"],
    queryFn: () => getCaseCampaigns(caseId),
    retry: 1,
  });

  if (isLoading) {
    return (
      <Card>
        <CardHeader className="pb-2">
          <h3 className="text-[14px] font-[600] flex items-center gap-2">
            <Link2 className="w-4 h-4 text-text-secondary" />
            Related Investigations
          </h3>
        </CardHeader>
        <CardContent className="pt-2">
          <p className="text-xs text-text-secondary animate-pulse">Correlating campaigns...</p>
        </CardContent>
      </Card>
    );
  }

  if (error || !campaigns) return null;

  if (campaigns.length === 0) {
    return (
      <Card>
        <CardHeader className="pb-2">
          <h3 className="text-[14px] font-[600] flex items-center gap-2">
            <Link2 className="w-4 h-4 text-text-secondary" />
            Related Investigations
          </h3>
        </CardHeader>
        <CardContent className="pt-2">
          <p className="text-xs text-text-secondary">No high-confidence related investigations detected.</p>
        </CardContent>
      </Card>
    );
  }

  return (
    <Card>
      <CardHeader className="pb-2">
        <h3 className="text-[14px] font-[600] flex items-center gap-2 text-text-primary">
          <Link2 className="w-4 h-4 text-warning" />
          Related Investigations (Campaigns)
        </h3>
      </CardHeader>
      <CardContent className="pt-2 flex flex-col gap-4">
        {campaigns.map((c) => {
          
          

          return (
            <div key={c.campaign_id} className="p-3 bg-surface border border-border rounded-md text-sm">
              <div className="flex justify-between items-start mb-2">
                <div>
                  <div className="font-bold text-text-primary mb-0.5">Related campaign:</div>
                  <Badge variant="neutral" className="font-mono text-[10px] bg-background">
                    {c.campaign_id}
                  </Badge>
                </div>
                <div className="text-right">
                  <div className="text-xs text-text-secondary mb-0.5">Confidence</div>
                  <Badge variant="warning" className="text-[10px] bg-warning/10 text-warning border-warning/20">
                    {Math.round(c.confidence)}%
                  </Badge>
                </div>
              </div>

              <div className="text-text-primary mb-2 text-[13px] font-medium">
                {c.related_investigations?.length || 0} related investigations
              </div>

              <div className="text-xs text-text-secondary mb-1">
                Common infrastructure & indicators:
              </div>
              <div className="flex flex-wrap gap-1 text-[11px] text-text-secondary">
                {Object.entries(c.shared_indicators || {}).map(([key, vals]: [string, string[]]) => (
                  <span key={key}>{vals.length} {key}s</span>
                ))}
                {Object.entries(c.shared_infrastructure || {}).map(([key, vals]: [string, string[]]) => (
                  <span key={key}>{vals.length} {key.toUpperCase()}</span>
                ))}
              </div>
            </div>
          );
        })}
      </CardContent>
    </Card>
  );
}
