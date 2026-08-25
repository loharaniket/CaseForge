import sys
f = 'apps/api/src/services/intelligence/url_service.py'
with open(f, 'r') as file:
    content = file.read()

imports = '''
from src.services.intelligence.redirect_analyzer import SafeRedirectAnalyzer
'''
if 'SafeRedirectAnalyzer' not in content:
    content = content.replace(
        'from src.services.intelligence.dto import URLIntelligenceData',
        imports.strip() + '\nfrom src.services.intelligence.dto import URLIntelligenceData'
    )
    
    # We will enrich redirect_chain when processing unique URLs
    # Since analyze_case_url_intelligence is async, we can await SafeRedirectAnalyzer.analyze
    
    call_str = '''
            data = await self.get_url_intelligence(url)
            try:
                redirects = await SafeRedirectAnalyzer.analyze(url)
                data.redirect_chain = redirects
            except Exception as e:
                data.redirect_chain = [{"original_url": url, "status": "ERROR", "error": str(e)}]
'''
    content = content.replace('data = await self.get_url_intelligence(url)', call_str.strip())
    
    record_str = '''
                lookalike_target=data.lookalike_target,
                explanation=data.explanation,
                reputation=data.reputation,
                risk_score=data.risk_score,
                provider_status=data.provider_status,
                redirect_chain=data.redirect_chain
'''
    content = content.replace(
        'lookalike_target=data.lookalike_target,\n                explanation=data.explanation,\n                reputation=data.reputation,\n                risk_score=data.risk_score,\n                provider_status=data.provider_status',
        record_str.strip()
    )
    with open(f, 'w') as file:
        file.write(content)
