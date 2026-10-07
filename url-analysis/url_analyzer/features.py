"""
features.py — pipeline stage 04: extract 37 features from a URL string.

    33 numeric model features  (MODEL_FEATURES — these go into the ML models)
  +  4 descriptive fields      (tld, suspicious_keywords, brands_found, parse_ok)
  = 37 features

Every feature uses only plain string operations, so the same logic ports
line-for-line to JavaScript (see js/url-analyzer.js). No network requests,
no page loading, no Python-only libraries inside the feature functions.
"""
import math
import re
from collections import Counter
from urllib.parse import parse_qs

from . import config
from .normalize import normalize

_IPV4_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
_PCT_RE = re.compile(r"%[0-9a-fA-F]{2}")
_SAFE_PUNCT = set(":/.?=&-_")

# Column order used by every model, script and the JS port.
MODEL_FEATURES = [
    # size
    "url_length", "domain_length", "path_length", "query_length", "longest_path_segment",
    # structure
    "num_subdomains", "num_dots", "num_hyphens_domain", "num_underscores",
    "num_path_segments", "num_query_params",
    # composition
    "num_digits", "digit_ratio", "num_special_chars", "special_char_ratio",
    "domain_entropy", "domain_has_digits",
    # domain
    "has_ip", "has_port", "is_punycode", "tld_length", "suspicious_tld_tier", "trusted_tld",
    # lexical
    "suspicious_keyword_count", "brand_impersonation",
    # obfuscation
    "num_percent_encodings", "encoding_ratio", "has_at_symbol", "double_slash_in_path",
    "num_ampersands", "num_equals",
    # protocol
    "is_https", "no_scheme",
]
DESCRIPTIVE_FIELDS = ["tld", "suspicious_keywords", "brands_found", "parse_ok"]
ALL_FEATURES = MODEL_FEATURES + DESCRIPTIVE_FIELDS
assert len(MODEL_FEATURES) == 33 and len(ALL_FEATURES) == 37

# Feature groups used by the ablation study (report p.10).
SCHEME_GROUP = ["is_https", "no_scheme"]
PATH_QUERY_GROUP = [
    "path_length", "query_length", "longest_path_segment", "num_path_segments",
    "num_query_params", "num_percent_encodings", "encoding_ratio",
    "double_slash_in_path", "num_ampersands", "num_equals",
]


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------
def split_domain(hostname: str):
    """Return (subdomain_labels, registered_label, suffix).

    'mail.paypal.com.evil.co.uk' -> (['mail','paypal','com'], 'evil', 'co.uk')
    """
    if _IPV4_RE.match(hostname):
        return [], hostname, ""
    labels = [l for l in hostname.split(".") if l]
    if len(labels) == 0:
        return [], "", ""
    if len(labels) == 1:
        return [], labels[0], ""
    two = ".".join(labels[-2:])
    if two in config.MULTI_PART_SUFFIXES and len(labels) >= 3:
        return labels[:-3], labels[-3], two
    return labels[:-2], labels[-2], labels[-1]


def registered_domain(hostname: str) -> str:
    _, label, suffix = split_domain(hostname)
    return f"{label}.{suffix}" if suffix else label


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in Counter(s).values())


def find_keywords(text: str) -> list[str]:
    """Keywords present in text, with nested matches removed
    ('banking' found -> 'bank' is not counted a second time)."""
    hits = [k for k in config.SUSPICIOUS_KEYWORDS if k in text]
    return [k for k in hits if not any(k != o and k in o for o in hits)]


# ---------------------------------------------------------------------------
# main entry point
# ---------------------------------------------------------------------------
def _empty() -> dict:
    f = {name: 0 for name in MODEL_FEATURES}
    f.update(tld="", suspicious_keywords="", brands_found="", parse_ok=0)
    return f


def extract_features(raw_url) -> dict:
    """Stage 04. Always returns a dict with all 37 keys; never raises."""
    p = normalize(raw_url)
    if not p.parse_ok:
        f = _empty()
        f["no_scheme"] = int(p.no_scheme)
        return f

    url, parts, host = p.url, p.parts, p.hostname
    lower = url.lower()
    path, query = parts.path or "", parts.query or ""
    segments = [s for s in path.split("/") if s]

    is_ip = bool(_IPV4_RE.match(host))
    subdomains, reg_label, suffix = split_domain(host)
    reg_domain = f"{reg_label}.{suffix}" if suffix else reg_label
    last_label = "" if is_ip else host.rsplit(".", 1)[-1]

    url_len = len(url)
    digits = sum(ch.isdigit() for ch in url)
    specials = sum(1 for ch in url if not ch.isalnum() and ch not in _SAFE_PUNCT)
    pct = len(_PCT_RE.findall(url))

    if last_label in config.SUSPICIOUS_TLDS_TIER1:
        tier = 1
    elif last_label in config.SUSPICIOUS_TLDS_TIER2:
        tier = 2
    else:
        tier = 0

    keywords = find_keywords(lower)
    # brand impersonation: brand appears in URL but is not the registered name itself
    brands = [b for b in config.KNOWN_BRANDS if b in lower and b != reg_label]

    try:
        has_port = parts.port is not None
    except ValueError:
        has_port = False

    return {
        # size
        "url_length": url_len,
        "domain_length": len(host),
        "path_length": len(path),
        "query_length": len(query),
        "longest_path_segment": max((len(s) for s in segments), default=0),
        # structure
        "num_subdomains": len(subdomains),
        "num_dots": url.count("."),
        "num_hyphens_domain": host.count("-"),
        "num_underscores": url.count("_"),
        "num_path_segments": len(segments),
        "num_query_params": len(parse_qs(query)),
        # composition
        "num_digits": digits,
        "digit_ratio": round(digits / url_len, 4),
        "num_special_chars": specials,
        "special_char_ratio": round(specials / url_len, 4),
        "domain_entropy": round(shannon_entropy(reg_label), 4),   # for an IP, reg_label is the IP itself
        "domain_has_digits": int(any(ch.isdigit() for ch in reg_domain)),
        # domain
        "has_ip": int(is_ip),
        "has_port": int(has_port),
        "is_punycode": int("xn--" in host),
        "tld": suffix,
        "tld_length": len(suffix),
        "suspicious_tld_tier": tier,
        "trusted_tld": int(last_label in config.TRUSTED_TLDS),
        # lexical
        "suspicious_keyword_count": len(keywords),
        "suspicious_keywords": ";".join(keywords),
        "brand_impersonation": int(bool(brands)),
        "brands_found": ";".join(brands),
        # obfuscation
        "num_percent_encodings": pct,
        "encoding_ratio": round(3 * pct / url_len, 4),
        "has_at_symbol": int("@" in url),
        "double_slash_in_path": int("//" in path),
        "num_ampersands": url.count("&"),
        "num_equals": url.count("="),
        # protocol
        "is_https": int(parts.scheme.lower() == "https"),
        "no_scheme": int(p.no_scheme),
        # meta
        "parse_ok": 1,
    }
