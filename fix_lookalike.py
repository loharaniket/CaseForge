import sys
f = 'apps/api/src/services/intelligence/lookalike_detector.py'
with open(f, 'r') as file:
    content = file.read()
content = content.replace(r'\"\"\"', '"""')
with open(f, 'w') as file:
    file.write(content)
