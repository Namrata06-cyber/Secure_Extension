"""
scorer.py — pipeline stages 06–07: risk score, classification, explanation.

    score = clamp( Σ wᵢ · firedᵢ , 0 , 100 )

analyze_url() is the single public entry point of the module.
"""
from . import config
from .features import extract_features
from .rules import fired_rules


def classify(score: int) -> str:
    if score <= config.BAND_SAFE_MAX:
        return "Safe"
    if score <= config.BAND_SUSPICIOUS_MAX:
        return "Suspicious"
    return "Dangerous"


def analyze_url(url) -> dict:
    """Analyse one URL string. Never raises, never touches the network.

    Returns
    -------
    {
      "url": str,
      "score": int (0–100),
      "classification": "Safe" | "Suspicious" | "Dangerous" | "Unknown",
      "indicators": ["R01", ...],
      "findings":   ["URL uses a raw IP address ...", ...],
      "features":   {37 features}
    }
    """
    features = extract_features(url)

    if not features["parse_ok"]:
        return {
            "url": url, "score": 0, "classification": "Unknown",
            "indicators": [], "findings": ["URL could not be parsed."],
            "features": features,
        }

    fired = fired_rules(features)
    raw = sum(r.weight for r in fired)
    score = max(config.SCORE_MIN, min(config.SCORE_MAX, raw))

    return {
        "url": url,
        "score": score,
        "classification": classify(score),
        "indicators": [r.id for r in fired],
        "findings": [r.finding for r in fired],
        "features": features,
    }
