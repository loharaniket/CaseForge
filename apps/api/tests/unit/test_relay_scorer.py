import pytest
from src.services.forensics.scorer import OriginCandidateScorer
from src.services.forensics.service import HeaderForensicsService
from src.services.forensics.types import AuthenticationResult

@pytest.fixture
def scorer():
    return OriginCandidateScorer()

def test_normal_gmail_like_chain(scorer):
    raw_headers = {
        "Received": [
            "from mail-wm1-f41.google.com (mail-wm1-f41.google.com. [209.85.128.41]) by mx.google.com with ESMTPS id 123 for <test@test.com>; Wed, 23 Aug 2026 10:00:00 -0700",
            "from [192.168.1.100] (client.corp.com [198.51.100.10]) by mail-wm1-f41.google.com with ESMTPSA id 456; Wed, 23 Aug 2026 09:59:58 -0700"
        ]
    }
    hops = HeaderForensicsService.parse_relay_chain(raw_headers)
    assert len(hops) == 2
    auth = AuthenticationResult(spf_status="pass")
    score = scorer.score_origin_candidates(hops, auth)
    assert score.candidate_ip == "198.51.100.10"
    assert score.candidate_score > 70.0
    assert any("trusted" in r.lower() for r in score.reasons)

def test_exchange_like_chain(scorer):
    raw_headers = {
        "Received": [
            "from EXCH01.corp.local (10.0.1.5) by edge.corp.com (198.51.100.50) with Microsoft SMTP Server id 15.0; Wed, 23 Aug 2026 10:00:00 +0000",
            "from client-pc.corp.local (10.0.1.20) by EXCH01.corp.local (10.0.1.5) with MAPI id 15.0; Wed, 23 Aug 2026 09:59:00 +0000"
        ]
    }
    hops = HeaderForensicsService.parse_relay_chain(raw_headers)
    score = scorer.score_origin_candidates(hops)
    # The first public hop is 198.51.100.50 or it might fallback to 10.0.1.20. Let's verify IP parsing:
    # the regex captures the IP in parens or brackets. 10.0.1.5 and 10.0.1.20 are private.
    assert "10.0.1.20" in [h.ip_address for h in hops]

def test_forged_received_header_and_private_ip(scorer):
    raw_headers = {
        "Received": [
            "from fake.host.com (fake.host.com [198.51.100.99]) by genuine.com; Wed, 23 Aug 2026 10:00:00 +0000",
            "from [10.10.10.10] (unknown [10.10.10.10]) by fake.host.com; Wed, 23 Aug 2026 09:59:00 +0000"
        ]
    }
    hops = HeaderForensicsService.parse_relay_chain(raw_headers)
    auth = AuthenticationResult(spf_status="fail")
    score = scorer.score_origin_candidates(hops, auth)
    assert score.candidate_ip == "198.51.100.99"
    assert score.candidate_score < 100.0
    assert any("private" in r.lower() for r in score.reasons) or any("fail" in r.lower() for r in score.reasons)

def test_malformed_header(scorer):
    raw_headers = {
        "Received": ["from garbage data without proper format by nothing"]
    }
    hops = HeaderForensicsService.parse_relay_chain(raw_headers)
    score = scorer.score_origin_candidates(hops)
    assert any(h.parser_confidence < 1.0 for h in hops)
    assert any("Malformed" in issue for h in hops for issue in h.validation_issues)

def test_multiple_public_candidates(scorer):
    raw_headers = {
        "Received": [
            "from mta1.public.com (mta1.public.com [203.0.113.10]) by mta2.public.com with ESMTP; Wed, 23 Aug 2026 10:05:00 +0000",
            "from origin.public.com (origin.public.com [198.51.100.55]) by mta1.public.com with ESMTP; Wed, 23 Aug 2026 10:00:00 +0000"
        ]
    }
    hops = HeaderForensicsService.parse_relay_chain(raw_headers)
    score = scorer.score_origin_candidates(hops)
    # the earliest public hop is favored due to our tie breaker +5
    assert score.candidate_ip == "198.51.100.55"

def test_inconsistent_timestamps(scorer):
    raw_headers = {
        "Received": [
            "from a (a [1.1.1.1]) by b; Wed, 23 Aug 2026 09:00:00 +0000",
            "from c (c [2.2.2.2]) by d; Wed, 23 Aug 2026 10:00:00 +0000"
        ]
    }
    # This means the earliest hop in chronological order is at 10:00, but the next hop is at 09:00 -> backwards!
    hops = HeaderForensicsService.parse_relay_chain(raw_headers)
    score = scorer.score_origin_candidates(hops)
    print(score.reasons)
    assert any("impossible timestamp ordering" in r.lower() for r in score.reasons)

def test_missing_received_headers(scorer):
    raw_headers = {}
    hops = HeaderForensicsService.parse_relay_chain(raw_headers)
    score = scorer.score_origin_candidates(hops)
    assert score.candidate_score == 0.0
    assert score.candidate_ip == "Unknown"
