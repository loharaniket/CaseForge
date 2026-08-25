import sys
f = 'apps/web/src/components/dashboard/InvestigationDashboard.tsx'
with open(f, 'r') as file:
    content = file.read()

if 'URLIntelligenceWidget' not in content:
    content = content.replace(
        'import { DomainIntelligenceWidget } from "./DomainIntelligenceWidget";',
        'import { DomainIntelligenceWidget } from "./DomainIntelligenceWidget";\nimport { URLIntelligenceWidget } from "./URLIntelligenceWidget";'
    )
    
    idx = content.find('<DomainIntelligenceWidget')
    if idx != -1:
        end_idx = content.find('/>', idx) + 2
        content = content[:end_idx] + '\n            <URLIntelligenceWidget caseId={caseId} />' + content[end_idx:]
        
with open(f, 'w') as file:
    file.write(content)
