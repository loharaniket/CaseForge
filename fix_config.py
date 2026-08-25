import sys
f = 'apps/api/src/core/config.py'
with open(f, 'r') as file:
    content = file.read()
content = content.replace('POSTGRES_CONNECT_TIMEOUT: int = 2\n', 'POSTGRES_CONNECT_TIMEOUT: int = 2\n\n    # Providers\n    PROVIDER_TIMEOUT_SECONDS: float = 10.0\n')
with open(f, 'w') as file:
    file.write(content)
