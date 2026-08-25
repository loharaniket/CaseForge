import sys

f = 'apps/api/src/models/case.py'
with open(f, 'r') as file:
    content = file.read()
if 'url_intelligence' not in content:
    content = content.replace(
        'ip_intelligence_records = relationship(',
        'url_intelligence: Mapped[list["URLIntelligenceRecord"]] = relationship(\n        "URLIntelligenceRecord", back_populates="case", cascade="all, delete-orphan"\n    )\n    ip_intelligence_records = relationship('
    )
    with open(f, 'w') as file:
        file.write(content)

f2 = 'apps/api/src/models/__init__.py'
with open(f2, 'r') as file:
    content2 = file.read()
if 'URLIntelligenceRecord' not in content2:
    content2 = content2.replace(
        'from src.models.domain_intel import DomainIntelligenceRecord',
        'from src.models.domain_intel import DomainIntelligenceRecord\nfrom src.models.url_intel import URLIntelligenceRecord'
    )
    content2 = content2.replace(
        '"DomainIntelligenceRecord",',
        '"DomainIntelligenceRecord",\n    "URLIntelligenceRecord",'
    )
    with open(f2, 'w') as file:
        file.write(content2)
