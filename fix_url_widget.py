import sys
f = 'apps/web/src/components/dashboard/URLIntelligenceWidget.tsx'
with open(f, 'r') as file:
    content = file.read()

if 'redirect_chain' not in content:
    # 1. Add redirect_chain to interface
    content = content.replace(
        'risk_score: number | null;',
        'risk_score: number | null;\n  redirect_chain?: any[] | null;'
    )
    
    # 2. Add header
    content = content.replace(
        '<Th>Reputation</Th>',
        '<Th>Reputation</Th>\n                <Th>Redirect Chain</Th>'
    )
    
    # 3. Add column rendering
    col_str = '''
                  <Td>
                    {urlData.redirect_chain && urlData.redirect_chain.length > 0 ? (
                      <div className="flex flex-col gap-1 text-xs">
                        {urlData.redirect_chain.map((node, i) => (
                          <div key={i} className="flex items-center gap-1">
                            <span className="text-slate-400">?</span>
                            <span className="truncate max-w-[200px]" title={node.redirect_url || node.final_url || node.status}>
                              {node.status === "BLOCKED_SECURITY_POLICY" ? (
                                <span className="text-red-500 font-semibold flex items-center gap-1">
                                  <ShieldAlert className="h-3 w-3"/>
                                  BLOCKED ({node.error})
                                </span>
                              ) : node.redirect_url ? (
                                node.redirect_url
                              ) : node.final_url ? (
                                <span className="text-green-600">Final: {node.final_url}</span>
                              ) : (
                                <span className="text-orange-500">{node.status}</span>
                              )}
                            </span>
                          </div>
                        ))}
                      </div>
                    ) : (
                      <span className="text-xs text-slate-400">No redirects</span>
                    )}
                  </Td>
'''
    
    content = content.replace(
        '</Tr>\n              ))}',
        col_str.strip('\n') + '\n                </Tr>\n              ))}'
    )
    
    with open(f, 'w') as file:
        file.write(content)
