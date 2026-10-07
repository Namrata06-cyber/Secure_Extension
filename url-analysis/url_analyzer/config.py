"""
config.py — every tunable list and number in the URL Analysis module lives here.

Nothing in this file is magic: each list is either derived from the PhiUSIIL
dataset (see evaluation/04_tld_evidence.py) or is a documented judgement call.
If you change a value here, re-run the evaluation scripts and update the report.
"""

# ---------------------------------------------------------------------------
# Public-suffix approximation
# ---------------------------------------------------------------------------
# A real browser uses the full Public Suffix List (thousands of entries).
# We hand-code the common two-part suffixes so that "bbc.co.uk" is treated as
# registered domain "bbc.co.uk", not "co.uk".  Known limitation (report p.12):
# rarer suffixes such as "ind.in" or "lg.jp" are missing, so num_subdomains can
# be off by one on those.  Future work: replace with tldextract / psl.
MULTI_PART_SUFFIXES = {
    "co.uk", "org.uk", "ac.uk", "gov.uk", "net.uk",
    "com.au", "net.au", "org.au", "edu.au", "gov.au",
    "co.in", "net.in", "org.in", "ac.in", "gov.in",
    "co.jp", "ne.jp", "or.jp", "ac.jp",
    "com.br", "com.mx", "com.ar", "com.tr", "com.cn",
    "co.za", "co.nz", "co.kr", "co.il",
}

# ---------------------------------------------------------------------------
# TLD lists — derived from the dataset (report p.9, "TLD evidence")
# Lookups use the LAST label of the hostname (".tk", ".xyz", ".gov").
# ---------------------------------------------------------------------------
# Tier 1 (+20): historically free to register (Freenom), phishing rate 98–100 %.
SUSPICIOUS_TLDS_TIER1 = {"cf", "gq", "ml", "ga", "tk"}

# Tier 2 (+12): low-cost new TLDs with measured phishing rate 90–99.9 %.
SUSPICIOUS_TLDS_TIER2 = {
    "top", "site", "link", "gd", "fun", "xyz", "ly", "cloud", "work",
    "shop", "club", "live", "online", "ws", "page",
}
# Deliberately EXCLUDED despite high measured rates: dev, app, co, io.
# They are used heavily by legitimate developers/startups that the dataset
# under-samples, so including them would bake a collection bias into the rules.

# Trusted (−20): restricted registration. Measured 0.0 % (.gov/.mil), 0.3 % (.edu).
TRUSTED_TLDS = {"gov", "mil", "edu"}

# ---------------------------------------------------------------------------
# Lexical lists
# ---------------------------------------------------------------------------
# 30 keywords that credential-harvesting pages tend to put in the URL.
# Nested matches are removed: "netbanking" matches "banking", not also "bank".
SUSPICIOUS_KEYWORDS = [
    "login", "signin", "logon", "verify", "verification", "account",
    "update", "secure", "security", "banking", "bank", "confirm",
    "password", "credential", "auth", "authenticate", "wallet", "billing",
    "invoice", "payment", "pay", "webscr", "suspend", "unlock", "recover",
    "validate", "ebayisapi", "token", "session", "reset",
]

# Brands that phishers impersonate. A brand counts as impersonation when it
# appears anywhere in the URL but is NOT the registered domain's own name
# (so google.com is fine, google.com@evil.tk and paypal.com.evil.tk are not).
KNOWN_BRANDS = [
    "paypal", "google", "microsoft", "apple", "amazon", "facebook",
    "netflix", "instagram", "whatsapp", "linkedin", "twitter", "yahoo",
    "dropbox", "wellsfargo", "bankofamerica", "ebay", "adobe", "docusign",
    "fedex", "coinbase", "binance", "hdfc", "icici", "paytm", "flipkart",
]

# ---------------------------------------------------------------------------
# Classification bands — calibrated on all 235,795 URLs (report p.7)
# The original synopsis proposed 0–30 / 31–60 / 61–100. At T = 61 recall was
# 0.005, so those bands were replaced.
# ---------------------------------------------------------------------------
BAND_SAFE_MAX = 5          # 0 – 5    : Safe
BAND_SUSPICIOUS_MAX = 19   # 6 – 19   : Suspicious
                           # 20 – 100 : Dangerous
SCORE_MIN, SCORE_MAX = 0, 100
