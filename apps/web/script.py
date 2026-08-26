import re

file_path = r'src\components\dashboard\InvestigationDashboard.tsx'
with open(file_path, 'r', encoding='utf-8') as f:
    content = f.read()

# 1. Remove activeTab state
content = re.sub(
    r'  const \[activeTab, setActiveTab\] = useState<number>\(0\);\n',
    '',
    content
)

# 2. Fix enabled logic in hooks
content = re.sub(
    r'enabled: !!caseId && isAnalysisComplete && \(activeTab === 0 \|\| activeTab === \d\),',
    'enabled: !!caseId && isAnalysisComplete,',
    content
)

# 3. Remove tabs array
content = re.sub(
    r'  const tabs = \[\n(?:    \"[^\"]+\",?\n)+  \];\n\n',
    '',
    content
)

# 4. Remove Section Jump Tabs
content = re.sub(
    r'          \{\/\* Section Jump Tabs \*\/\}\n          <div className=\"mt-6 border-t border-border pt-1 overflow-x-auto custom-scrollbar\">\n(?:.|\n)*?          <\/div>\n',
    '',
    content
)
# Fix pb-0 on CardContent
content = content.replace('<CardContent className="p-4 sm:p-6 pb-0">', '<CardContent className="p-4 sm:p-6">')

# 5. Extract the email summary card from activeTab blocks and rewrite the whole SIH flow
sih_flow = '''      {/* SIH WORKFLOW */}
      {/* 1. Verdict & 2. Risk & 3. Why Flagged */}
      <section id="section-verdict-why">
        <InvestigationConclusionWidget caseId={parsed.case_id} />
        <ThreatScoreWidget
          risk={risk}
          threat={threat}
          forensics={forensics}
          caseId={parsed.case_id}
          isLoading={isRiskLoading || isThreatLoading}
        />
      </section>

      {/* 4. Authentication */}
      <section id="section-auth">
        <AuthenticationForensicsWidget forensics={forensics} isLoading={isForensicsLoading} />
      </section>

      {/* 5. Sender Identity */}
      <section id="section-email-summary">
        <Card className="shadow-md overflow-hidden">
          <CardContent className="p-6">
            <div className="flex items-center gap-3 mb-6">
              <Mail className="w-5 h-5 text-primary" />
              <h2 className="text-[16px] font-[700] text-text-primary">
                Email Envelope & Identity Summary
              </h2>
            </div>
            
            <div className="p-5 bg-bg-page border border-border rounded-[8px] mb-6">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-5">
                <div className="flex flex-col gap-1">
                  <span className="text-[11px] font-[600] text-text-secondary uppercase tracking-wider">
                    From (Sender)
                  </span>
                  <span className="text-[13px] font-[600] text-text-primary break-all">
                    {parsed.from_name ? `${parsed.from_name} <${parsed.from_address || parsed.sender}>` : parsed.sender || "N/A"}
                  </span>
                </div>
                <div className="flex flex-col gap-1">
                  <span className="text-[11px] font-[600] text-text-secondary uppercase tracking-wider">
                    To (Recipients)
                  </span>
                  <span className="text-[13px] font-[600] text-text-primary break-all">
                    {parsed.recipients && parsed.recipients.length > 0 ? parsed.recipients.join(", ") : "None declared"}
                  </span>
                </div>
                <div className="flex flex-col gap-1">
                  <span className="text-[11px] font-[600] text-text-secondary uppercase tracking-wider">
                    Subject
                  </span>
                  <span className="text-[14px] font-[700] text-primary">
                    {parsed.subject || "(No Subject Declared)"}
                  </span>
                </div>
                <div className="flex flex-col gap-1">
                  <span className="text-[11px] font-[600] text-text-secondary uppercase tracking-wider">
                    Date Declared
                  </span>
                  <span className="text-[13px] text-text-primary">
                    {parsed.date_parsed ? new Date(parsed.date_parsed).toUTCString() : parsed.date_raw || "Not available"}
                  </span>
                </div>
                <div className="flex flex-col gap-1">
                  <span className="text-[11px] font-[600] text-text-secondary uppercase tracking-wider">
                    Message-ID
                  </span>
                  <span className="text-[11px] font-mono text-text-muted break-all">
                    {parsed.message_id || "None declared"}
                  </span>
                </div>
                <div className="flex flex-col gap-1">
                  <span className="text-[11px] font-[600] text-text-secondary uppercase tracking-wider">
                    Reply-To / CC
                  </span>
                  <span className="text-[13px] text-text-muted">
                    {parsed.reply_to && parsed.reply_to.length > 0 ? `Reply-To: ${parsed.reply_to.join(", ")}` : "No Reply-To mismatch"}
                  </span>
                </div>
              </div>
            </div>

            <div className="mb-0">
              <div className="flex flex-col sm:flex-row sm:justify-between sm:items-center gap-3 mb-4">
                <h3 className="text-[14px] font-[700] text-text-primary">
                  Email Body Content Preview
                </h3>
                <div className="flex items-center bg-bg-panel-subtle p-1 rounded-[6px] border border-border">
                  <button
                    onClick={() => setBodyFormat("plain")}
                    className={`px-3 py-1 text-[11px] font-[600] rounded-[4px] transition-colors ${
                      bodyFormat === "plain" ? "bg-white shadow text-text-primary" : "text-text-secondary hover:text-text-primary"
                    }`}
                  >
                    Plain Text
                  </button>
                  <button
                    onClick={() => setBodyFormat("html")}
                    className={`px-3 py-1 text-[11px] font-[600] rounded-[4px] transition-colors ${
                      bodyFormat === "html" ? "bg-white shadow text-text-primary" : "text-text-secondary hover:text-text-primary"
                    }`}
                  >
                    Safe HTML
                  </button>
                </div>
              </div>

              {bodyFormat === "plain" ? (
                <div className="p-4 bg-slate-900 rounded-[8px] border border-slate-700 max-h-[220px] overflow-y-auto custom-scrollbar font-mono text-[12px] text-slate-300 whitespace-pre-wrap">
                  {parsed.body_plain || "No plain text content available."}
                </div>
              ) : (
                <div 
                  className="p-4 bg-white rounded-[8px] border border-border max-h-[220px] overflow-y-auto custom-scrollbar text-[13px] text-slate-800"
                  dangerouslySetInnerHTML={{
                    __html: parsed.body_html || "<p>No HTML body content available.</p>",
                  }}
                />
              )}
            </div>
          </CardContent>
        </Card>
      </section>

      {/* 6. Relay/origin */}
      <section id="section-relay-origin">
        <RelayHopsTimelineWidget forensics={forensics} isLoading={isForensicsLoading} />
      </section>

      {/* 7. Infrastructure intelligence */}
      <section id="section-threat-intel-geo" className="flex flex-col gap-6">
        <ThreatIntelGeoWidget intel={intel} geo={geo} isLoading={isIntelLoading || isGeoLoading} />
        <IPIntelligenceWidget caseId={caseId} />
        <DomainIntelligenceWidget caseId={caseId} />
        <URLIntelligenceWidget caseId={caseId} />
      </section>

      {/* 8. IOCs */}
      <section id="section-iocs">
        <IOCTableWidget iocData={iocs} isLoading={isIocsLoading} />
      </section>

      {/* 9. Related campaign */}
      <section id="section-campaign">
        <CampaignWidget caseId={parsed.case_id} />
      </section>

      {/* 10. Evidence integrity */}
      <section id="section-evidence">
        <EvidenceIntegrityWidget caseId={caseId} />
        {parsed.attachments_metadata && parsed.attachments_metadata.length > 0 && (
          <Card className="mt-6">
            <CardContent className="p-6">
              <h3 className="text-[14px] font-[700] text-text-primary mb-3 flex items-center gap-2">
                <Paperclip className="w-4 h-4" /> Attached Evidence Files ({parsed.attachments_metadata.length})
              </h3>
              <div className="flex flex-col gap-2">
                {parsed.attachments_metadata.map((att, idx) => (
                  <div
                    key={idx}
                    className="p-3 bg-bg-page border border-border rounded-[8px] flex flex-col sm:flex-row sm:items-center justify-between gap-3"
                  >
                    <div className="flex flex-col gap-1">
                      <span className="text-[13px] font-[600] text-text-primary">
                        {att.filename}
                      </span>
                      <span className="text-[11px] text-text-secondary font-mono">
                        Size: {(att.file_size_bytes / 1024).toFixed(1)} KB • SHA-256: {att.sha256}
                      </span>
                    </div>
                    <Badge variant="neutral" className="bg-border/50 text-text-muted text-[10px] uppercase w-fit">
                      {att.extension}
                    </Badge>
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>
        )}
      </section>

      {/* 11. Graph */}
      <section id="section-graph">
        <ThreatGraphWidget graph={graph} isLoading={isGraphLoading} onRefresh={refetchGraph} />
      </section>

      {/* 12. Timeline */}
      <section id="section-timeline">
        <ForensicTimelineWidget timelineData={timeline} isLoading={isTimelineLoading} />
      </section>
'''

# Find the block from CONTINUOUS VERTICAL INVESTIGATION WORKFLOW to the bottom toolbar
start_str = '      {/* ========================================================================= */}'
end_str = '      {/* SECTION L: BOTTOM ACTIONS TOOLBAR */}'

start_idx = content.find(start_str)
end_idx = content.find(end_str)

if start_idx != -1 and end_idx != -1:
    content = content[:start_idx] + sih_flow + '\n' + content[end_idx:]
else:
    print('Failed to find replace block')

# Remove the 'onClick={() => { setActiveTab(6); ...' logic from the View Graph button since tabs are gone
# We can just change it to scroll to section-graph
content = content.replace(
    '                setActiveTab(6);\n',
    ''
)

with open(file_path, 'w', encoding='utf-8') as f:
    f.write(content)
