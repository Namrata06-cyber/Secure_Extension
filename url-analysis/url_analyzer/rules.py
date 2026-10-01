"""
rules.py — pipeline stage 05: 18 transparent, weighted risk rules.

Each rule is (id, condition on the feature dict, weight, finding text).
Weights are INITIAL HEURISTICS informed by measured class separation
(report p.6); they have not been numerically optimised.
Negative weights are allowed (R04 trusted TLD lowers the score).
"""
from dataclasses import dataclass
from typing import Callable


@dataclass(frozen=True)
class Rule:
    id: str
    condition: str                      # human-readable, shown in the report
    weight: int
    finding: str                        # sentence shown to the user when it fires
    test: Callable[[dict], bool]


RULES: list[Rule] = [
    Rule("R01", "has_ip == 1", 25,
         "URL uses a raw IP address instead of a domain name.",
         lambda f: f["has_ip"] == 1),
    Rule("R02", "suspicious_tld_tier == 1", 20,
         "Domain uses a top-level domain offered for free and heavily abused (.tk/.ml/.ga/.cf/.gq).",
         lambda f: f["suspicious_tld_tier"] == 1),
    Rule("R03", "suspicious_tld_tier == 2", 12,
         "Domain uses a low-cost new TLD with a high observed phishing rate.",
         lambda f: f["suspicious_tld_tier"] == 2),
    Rule("R04", "trusted_tld == 1", -20,
         "Domain uses a restricted-registration TLD (.gov/.edu/.mil).",
         lambda f: f["trusted_tld"] == 1),
    Rule("R05", "num_subdomains >= 3", 12,
         "URL contains an unusually large number of subdomains.",
         lambda f: f["num_subdomains"] >= 3),
    Rule("R06", "has_at_symbol == 1", 20,
         "URL contains an \"@\" symbol, which can hide the real destination.",
         lambda f: f["has_at_symbol"] == 1),
    Rule("R07", "is_punycode == 1", 15,
         "Domain uses punycode/IDN encoding, which can imitate Latin letters.",
         lambda f: f["is_punycode"] == 1),
    Rule("R08", "url_length > 75", 10,
         "URL is unusually long.",
         lambda f: f["url_length"] > 75),
    Rule("R09a", "suspicious_keyword_count >= 2", 10,
         "URL contains multiple authentication or payment related keywords.",
         lambda f: f["suspicious_keyword_count"] >= 2),
    Rule("R09b", "suspicious_keyword_count == 1", 5,
         "URL contains an authentication or payment related keyword.",
         lambda f: f["suspicious_keyword_count"] == 1),
    Rule("R10", "brand_impersonation == 1", 18,
         "A well-known brand name appears in the URL but is not the registered domain.",
         lambda f: f["brand_impersonation"] == 1),
    Rule("R11", "num_percent_encodings >= 3", 10,
         "URL contains heavy percent-encoding, which can obscure its real content.",
         lambda f: f["num_percent_encodings"] >= 3),
    Rule("R12", "is_https == 0", 8,
         "URL uses HTTP instead of HTTPS, so traffic is not encrypted.",
         lambda f: f["is_https"] == 0),
    Rule("R13", "num_hyphens_domain >= 3", 8,
         "Domain contains an unusually high number of hyphens.",
         lambda f: f["num_hyphens_domain"] >= 3),
    Rule("R14", "domain_entropy > 3.6", 8,
         "Registered domain name looks randomly generated.",
         lambda f: f["domain_entropy"] > 3.6),
    Rule("R15", "has_port == 1", 6,
         "URL specifies a non-standard network port.",
         lambda f: f["has_port"] == 1),
    Rule("R16", "double_slash_in_path == 1", 8,
         "URL path contains an unusual double slash.",
         lambda f: f["double_slash_in_path"] == 1),
    Rule("R17", "num_query_params >= 5", 5,
         "URL carries an unusually large number of query parameters.",
         lambda f: f["num_query_params"] >= 5),
]

assert len(RULES) == 18
assert sum(r.weight for r in RULES if r.weight > 0) == 200


def fired_rules(features: dict) -> list[Rule]:
    """Return every rule whose condition is true for this feature dict."""
    if not features.get("parse_ok"):
        return []
    return [r for r in RULES if r.test(features)]
