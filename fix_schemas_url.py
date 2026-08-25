import sys
f = 'apps/api/src/schemas/__init__.py'
with open(f, 'a') as file:
    file.write('\nfrom .url_intel import CaseURLIntelligenceResponse, URLIntelligenceRecordSchema\n')
