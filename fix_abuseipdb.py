import sys
f = 'apps/api/src/services/intel/providers/abuseipdb.py'
with open(f, 'r') as file:
    content = file.read()
content = content.replace('params = {', 'params: dict[str, str | int | bool] = {')
with open(f, 'w') as file:
    file.write(content)
