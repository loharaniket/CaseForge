import sys
f = 'apps/api/src/services/detection_service.py'
with open(f, 'r') as file:
    content = file.read()

# Replace the default detector with extended
content = content.replace(
    'from src.services.detector.rule_based import default_rule_detector',
    'from src.services.detector.rule_based import default_rule_detector\nfrom src.services.detector.extended import extended_detector\nfrom src.models.forensics import HeaderForensics\nfrom src.models.url_intel import URLIntelligenceRecord\n\nclass CompositeContext:\n    def __init__(self, parsed, auth_details, url_intel):\n        self._parsed = parsed\n        self.auth_details = auth_details\n        self.url_intel = url_intel\n    def __getattr__(self, name):\n        return getattr(self._parsed, name)\n'
)

content = content.replace(
    'self.detector = detector or default_rule_detector',
    'self.detector = detector or extended_detector'
)

# Fetch URL intel and Auth details before calling detect
old_detect_call = 'result = self.detector.detect(parsed_email)'
new_detect_call = '''
        # Fetch URL intelligence
        url_intel = db.execute(
            select(URLIntelligenceRecord).where(URLIntelligenceRecord.case_id == case_id)
        ).scalars().all()
        
        # Fetch Header Forensics (authentication results)
        hf = db.execute(select(HeaderForensics).where(HeaderForensics.case_id == case_id)).scalar_one_or_none()
        auth_details = {}
        if hf:
            # We don't have authentication directly on the DB model, but we can look for raw_headers in parsed_email
            # Wait, the prompt says "authentication results". If it's not on HF model, we can parse from raw_headers
            auth_res = parsed_email.raw_headers.get("Authentication-Results", "") if parsed_email.raw_headers else ""
            if isinstance(auth_res, list): auth_res = " ".join(auth_res)
            auth_details["spf_status"] = "fail" if "spf=fail" in auth_res.lower() else ("pass" if "spf=pass" in auth_res.lower() else "neutral")
            auth_details["dkim_status"] = "fail" if "dkim=fail" in auth_res.lower() else ("pass" if "dkim=pass" in auth_res.lower() else "neutral")

        context = CompositeContext(parsed_email, auth_details, url_intel)
        result = self.detector.detect(context)
'''
content = content.replace(old_detect_call, new_detect_call.strip())

with open(f, 'w') as file:
    file.write(content)
