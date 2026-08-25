import sys
f = 'apps/api/src/services/intelligence/__init__.py'
with open(f, 'r') as file:
    content = file.read()
if 'AggregatedURLIntelligenceService' not in content:
    content += '\nfrom .url_service import AggregatedURLIntelligenceService, get_url_intel_service\n'

content = content.replace(
    'from .dto import IPIntelligenceData, DomainIntelligenceData',
    'from .dto import IPIntelligenceData, DomainIntelligenceData, URLIntelligenceData'
)
with open(f, 'w') as file:
    file.write(content)
