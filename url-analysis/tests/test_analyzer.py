"""
Unit tests.   Run:  pytest -q

These pin the behaviour documented in the report, so that anyone changing a
rule or a list sees immediately which documented result moved.
"""
import json
from pathlib import Path

import pytest

from url_analyzer import analyze_url, extract_features, ALL_FEATURES, MODEL_FEATURES, RULES
from url_analyzer.features import split_domain, find_keywords

CASES = json.loads((Path(__file__).parent / "validation_urls.json").read_text())


# --- the 18 hand-built real-world URLs (report p.11) -------------------------
@pytest.mark.parametrize("case", CASES, ids=[c["category"] for c in CASES])
def test_validation_scores_match_report(case):
    assert analyze_url(case["url"])["score"] == case["report_score"]


def test_rule_engine_passes_15_of_18():
    passed = sum((analyze_url(c["url"])["classification"] != "Safe") == (c["expected"] == "Phishing") for c in CASES)
    assert passed == 15


# --- robustness: the pipeline must never crash ------------------------------
@pytest.mark.parametrize("bad", [None, "", "   ", 42, "http://", "http://site.com:99999/x", "://nohost"])
def test_bad_input_never_raises(bad):
    r = analyze_url(bad)
    assert r["classification"] == "Unknown" and r["features"]["parse_ok"] == 0


def test_every_result_has_37_features():
    assert len(ALL_FEATURES) == 37 and len(MODEL_FEATURES) == 33
    assert set(extract_features("https://example.com/a?b=c")) == set(ALL_FEATURES)


# --- normalisation ------------------------------------------------------------
def test_missing_scheme_is_repaired_and_flagged():
    f = extract_features("example.com/verify")
    assert f["parse_ok"] == 1 and f["no_scheme"] == 1


def test_unicode_hostname_becomes_punycode():
    f = extract_features("https://аpple.com/login")          # Cyrillic "а"
    assert f["is_punycode"] == 1


def test_fragment_is_dropped():
    assert extract_features("https://a.com/x#frag")["url_length"] == len("https://a.com/x")


# --- individual features ------------------------------------------------------
def test_multi_part_suffix():
    assert split_domain("www.bbc.co.uk") == (["www"], "bbc", "co.uk")
    assert split_domain("paypal.com.evil.tk") == (["paypal", "com"], "evil", "tk")


def test_nested_keywords_are_not_double_counted():
    assert find_keywords("netbanking") == ["banking"]


def test_brand_on_its_own_domain_is_not_impersonation():
    assert extract_features("https://www.google.com/search")["brand_impersonation"] == 0
    assert extract_features("http://google.com@evil.tk/")["brand_impersonation"] == 1


def test_trusted_tld_lowers_score():
    r = analyze_url("https://login.example.gov/")
    assert "R04" in r["indicators"] and r["score"] == 0       # clamped at 0


def test_score_is_clamped_to_100():
    r = analyze_url("http://paypal.login.verify.secure.account.a1b2c3x9z8q7qq.tk:8080//x/%41%42%43@y?a=1&b=2&c=3&d=4&e=5&f=6" + "x" * 80)
    assert r["score"] == 100


def test_weights_sum_to_200():
    assert sum(r.weight for r in RULES if r.weight > 0) == 200
