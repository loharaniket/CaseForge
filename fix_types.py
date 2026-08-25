import sys
f = 'apps/api/src/services/intelligence/types.py'
with open(f, 'r') as file:
    content = file.read()
content = content.replace('PROVIDER_ERROR = "PROVIDER_ERROR"', 'PROVIDER_ERROR = "PROVIDER_ERROR"\n    UNAVAILABLE = "UNAVAILABLE"')
with open(f, 'w') as file:
    file.write(content)
