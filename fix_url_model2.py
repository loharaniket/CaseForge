import sys
f = 'apps/api/src/models/url_intel.py'
with open(f, 'r') as file:
    content = file.read()

if 'redirect_chain' not in content:
    content = content.replace(
        'last_updated: Mapped[datetime]',
        'redirect_chain: Mapped[list[dict] | None] = mapped_column(JSON, nullable=True)\n    last_updated: Mapped[datetime]'
    )
    with open(f, 'w') as file:
        file.write(content)
