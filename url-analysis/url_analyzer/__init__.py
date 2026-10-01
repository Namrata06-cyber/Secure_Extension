"""URL Analysis module — Group SY503 phishing-detection browser extension.

Quick use:
    >>> from url_analyzer import analyze_url
    >>> analyze_url("http://paypal.com.secure-account-verify.tk/signin")["classification"]
    'Dangerous'
"""
from .features import extract_features, MODEL_FEATURES, ALL_FEATURES
from .rules import RULES, fired_rules
from .scorer import analyze_url, classify

__all__ = ["analyze_url", "extract_features", "classify", "RULES", "fired_rules",
           "MODEL_FEATURES", "ALL_FEATURES"]
__version__ = "1.1.0"
