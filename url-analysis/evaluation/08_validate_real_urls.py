"""
08 — Validation against 18 hand-built real-world URLs  (report p.11, Finding 2 part 2)

NOT a benchmark: small and hand-picked, reported qualitatively.
Compares the 18-rule engine with the Random Forest from 06_train_models.py.
A rule-engine result PASSES if a legitimate URL is Safe, or a phishing URL is
Suspicious/Dangerous. The ML result passes if P(phishing) >= 0.5 matches the label.
"""
import json

import pandas as pd

from common import ROOT, save
from url_analyzer import analyze_url


def main():
    cases = json.loads((ROOT / "tests" / "validation_urls.json").read_text())

    rf, feats = None, None
    try:
        import joblib
        bundle = joblib.load(ROOT / "models" / "rf_domain_disjoint.joblib")
        rf, feats = bundle["model"], bundle["features"]
    except (ImportError, FileNotFoundError):
        print("(no trained model found — run 06_train_models.py first to get the ML column)\n")

    rows = []
    for c in cases:
        r = analyze_url(c["url"])
        phishing = c["expected"] == "Phishing"
        rule_pass = (r["classification"] != "Safe") == phishing
        row = {"url": c["url"], "category": c["category"], "expected": c["expected"],
               "score": r["score"], "rule_class": r["classification"],
               "rule": "PASS" if rule_pass else "FAIL", "indicators": ", ".join(r["indicators"]) or "(none)"}
        if rf is not None:
            x = pd.DataFrame([[r["features"][k] for k in feats]], columns=feats).values
            p = float(rf.predict_proba(x)[0, 1])
            row.update(ml_p_phish=round(p, 3), ml="PASS" if (p >= 0.5) == phishing else "FAIL")
        rows.append(row)

    table = pd.DataFrame(rows)
    print(table.drop(columns=["category"]).to_string(index=False))
    print(f"\nRule engine: {(table.rule == 'PASS').sum()}/{len(table)}")
    if rf is not None:
        print(f"Random Forest: {(table.ml == 'PASS').sum()}/{len(table)}")
    save(table, "08_real_url_validation.csv")


if __name__ == "__main__":
    main()
