import sys
f = 'apps/api/src/services/parser/eml_parser.py'
with open(f, 'r') as file:
    content = file.read()
content = content.replace('payload = part.get_payload(decode=True) or b\"\"', 'payload = part.get_payload(decode=True)\n                    if not isinstance(payload, bytes):\n                        payload = b\"\"')
content = content.replace('payload_bytes = part.get_payload(decode=True)', 'payload_bytes = part.get_payload(decode=True)\n                    if not isinstance(payload_bytes, bytes):\n                        payload_bytes = None')
with open(f, 'w') as file:
    file.write(content)
