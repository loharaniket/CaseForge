import re
import difflib
from typing import Tuple

TARGET_BRANDS = {
    "microsoft", "apple", "google", "amazon", "facebook", "meta",
    "paypal", "chase", "bankofamerica", "wellsfargo", "netflix",
    "linkedin", "instagram", "twitter", "dhl", "fedex", "ups", "usps"
}

def remove_tld(hostname: str) -> str:
    parts = hostname.split('.')
    if len(parts) > 1:
        # Simplistic TLD removal for basic brand matching
        return parts[-2]
    return hostname

def detect_lookalike(hostname: str) -> Tuple[bool, str | None, str | None]:
    """
    Returns (is_lookalike, matched_target, explanation).
    """
    if not hostname:
        return False, None, None
        
    lower_host = hostname.lower()
    
    # Punycode check
    if 'xn--' in lower_host:
        return True, None, "Domain uses Punycode (xn--) which is often used for homoglyph attacks."

    # Extract primary label for distance checking
    base_name = remove_tld(lower_host)
    
    # Exact match in target brands is NOT a lookalike, it's either legit or spoofing the actual domain
    if base_name in TARGET_BRANDS:
        # e.g., microsoft.login.com -> base_name=login, not microsoft. 
        # But if hostname is microsoft.com -> base_name=microsoft
        return False, None, None

    # Check for homoglyphs using simple string normalization mapping or difflib
    for brand in TARGET_BRANDS:
        # If the brand is a substring, it might be a lookalike (e.g., microsoft-login-secure.com)
        if brand in base_name and brand != base_name:
            return True, brand, f"Observed domain resembles {brand} with high lexical similarity (substring match)."

        # Sequence matcher for typo-squatting
        ratio = difflib.SequenceMatcher(None, brand, base_name).ratio()
        if ratio > 0.85:
            return True, brand, f"Observed domain resembles {brand} with high lexical similarity (typo-squatting)."

    return False, None, None
