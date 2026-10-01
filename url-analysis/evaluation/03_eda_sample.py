"""
03 — Exploratory analysis on the 100-URL working sample  (report p.8)

Sample = first 50 phishing + first 50 legitimate rows in file order.
Outputs: numeric feature means per class, binary indicator rates,
rule firing counts, and the rule engine's band confusion table.
"""
import pandas as pd

from common import load_dataset, load_features, working_sample, save
from url_analyzer import RULES

NUMERIC = ["url_length", "domain_length", "path_length", "query_length", "num_subdomains",
           "num_dots", "num_hyphens_domain", "num_digits", "digit_ratio", "num_special_chars",
           "special_char_ratio", "domain_entropy", "suspicious_keyword_count", "num_path_segments"]
BINARY = ["has_ip", "is_https", "has_at_symbol", "is_punycode", "has_port",
          "brand_impersonation", "domain_has_digits", "trusted_tld", "double_slash_in_path"]


def main():
    df = load_dataset()
    f = load_features(df).loc[working_sample(df).index]
    cls = f["is_phishing"].map({1: "phishing", 0: "legitimate"})

    means = f.groupby(cls)[NUMERIC].mean().T.round(3)
    means["difference"] = (means["phishing"] - means["legitimate"]).round(3)
    rates = (f.groupby(cls)[BINARY].mean().T * 100).round(1)

    fired = []
    for r in RULES:
        hit = f["indicators"].str.split(";").apply(lambda ids: r.id in ids)
        fired.append({"rule": r.id, "condition": r.condition, "weight": r.weight,
                      "fired": int(hit.sum()),
                      "phishing": int(hit[f.is_phishing == 1].sum()),
                      "legitimate": int(hit[f.is_phishing == 0].sum())})
    fired = pd.DataFrame(fired)

    bands = pd.crosstab(cls, f["classification"]).reindex(columns=["Safe", "Suspicious", "Dangerous"], fill_value=0)

    flagged = f["classification"] != "Safe"
    tp = int((flagged & (f.is_phishing == 1)).sum()); fp = int((flagged & (f.is_phishing == 0)).sum())
    fn = int((~flagged & (f.is_phishing == 1)).sum()); tn = int((~flagged & (f.is_phishing == 0)).sum())
    p, r = tp / (tp + fp), tp / (tp + fn)
    summary = (f"Suspicious-or-Dangerous = flagged: TP {tp}, FP {fp}, FN {fn}, TN {tn} -> "
               f"precision {p:.3f}, recall {r:.3f}, F1 {2*p*r/(p+r):.3f}, accuracy {(tp+tn)/len(f):.3f}")

    print(means, "\n\n", rates, "\n\n", fired.to_string(index=False), "\n\n", bands, "\n\n", summary)
    save(means, "03_sample_means.csv", index=True)
    save(rates, "03_sample_binary_rates.csv", index=True)
    save(fired, "03_sample_rule_fires.csv")
    save(bands, "03_sample_bands.csv", index=True)
    save(f[["URL", "is_phishing", "url_length", "num_subdomains", "num_digits", "is_https",
            "suspicious_tld_tier", "score", "classification", "indicators"]], "03_sample_rows.csv")


if __name__ == "__main__":
    main()
