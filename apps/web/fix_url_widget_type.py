import sys
f = 'src/components/dashboard/URLIntelligenceWidget.tsx'
with open(f, 'r') as file:
    content = file.read()

# Replace the type definition
interface_code = """interface RedirectNode {
  original_url: string;
  status: number | string;
  error?: string;
  hostname?: string;
  resolved_ip?: string;
  order?: number;
  timestamp?: string;
  redirect_url?: string;
  final_url?: string;
}

interface URLIntelligenceRecord {"""

content = content.replace('interface URLIntelligenceRecord {', interface_code)
content = content.replace('redirect_chain?: Record<string, unknown>[] | null;', 'redirect_chain?: RedirectNode[] | null;')

# Add typecasting inside the map just in case if typescript complains about truthiness
content = content.replace(
    'title={node.redirect_url || node.final_url || node.status}',
    'title={(node.redirect_url || node.final_url || node.status) as string}'
)

with open(f, 'w') as file:
    file.write(content)
