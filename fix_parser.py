import sys
f = 'apps/api/src/services/parser/eml_parser.py'
with open(f, 'r') as file:
    content = file.read()
content = content.replace('import hashlib', 'import hashlib\nimport typing')
with open(f, 'w') as file:
    file.write(content)
