"""Sanity tests for the secret-scanner regex catalogue."""
from bubblepwn.bubble.secrets import scan


def test_stripe_sk_live_detected():
    hits = scan("const k = 'sk_live_abcDEF1234567890abcDEF';")
    rules = {h.rule for h in hits}
    assert "stripe-sk-live" in rules


def test_stripe_pk_live_is_info_only():
    # Publishable keys are fine to leak but still reported as `info`.
    hits = scan("window.STRIPE_PK='pk_live_abcDEF1234567890abcDEF';")
    rules = {h.rule: h.severity for h in hits}
    assert rules.get("stripe-pk-live") == "info"


def test_google_api_key_detected():
    # Google API keys are `AIza` + 35 chars of [A-Za-z0-9_-].
    key = "AIza" + "A" * 35
    hits = scan(f"apiKey:'{key}'")
    rules = {h.rule for h in hits}
    assert any("google" in r.lower() for r in rules)


def test_deduplicates_identical_matches():
    # Same key appearing twice should produce at most one finding per rule.
    body = "sk_live_AAABBBCCCDDDEEEFFFGGG, sk_live_AAABBBCCCDDDEEEFFFGGG"
    hits = scan(body)
    matches = [h for h in hits if h.rule == "stripe-sk-live"]
    assert len(matches) <= 1


def test_no_hit_on_clean_html():
    body = "<html><head><title>Hello</title></head><body>Nothing to see.</body></html>"
    assert scan(body) == []
