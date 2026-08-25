import sys
f = 'apps/web/src/components/dashboard/URLIntelligenceWidget.tsx'
with open(f, 'r') as file:
    content = file.read()

content = content.replace(
    'redirect_chain?: any[] | null;',
    'redirect_chain?: Record<string, unknown>[] | null;'
)
with open(f, 'w') as file:
    file.write(content)
