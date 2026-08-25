import sys
f = 'apps/api/src/schemas/url_intel.py'
with open(f, 'r') as file:
    content = file.read()

if 'redirect_chain' not in content:
    content = content.replace(
        'provider_status: str | None = None',
        'provider_status: str | None = None\n    redirect_chain: list[dict] | None = None'
    )
    with open(f, 'w') as file:
        file.write(content)
