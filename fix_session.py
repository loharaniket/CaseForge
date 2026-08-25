import sys
f = 'apps/api/src/db/session.py'
with open(f, 'r') as file:
    content = file.read()
content = content.replace('connect_args = {}', 'connect_args: dict[str, Any] = {}')
with open(f, 'w') as file:
    file.write(content)
