"""
04 — TLD evidence  (report p.9)

The suspicious-TLD tiers (R02/R03) and trusted list (R04) in config.py were
DERIVED from this table, not copied from a published list.

Method: group every URL by its last hostname label, count phishing vs legitimate,
compute the phishing rate. Only TLDs with >= 200 samples are used — below that
the rate is noise.
"""
import pandas as pd

from common import load_features, save

MIN_SAMPLES = 200


def main():
    f = load_features()
    tld = f["URL"].str.extract(r"^[a-zA-Z]+://(?:[^/@]*@)?([^/:?#]+)")[0].str.lower().str.rsplit(".", n=1).str[-1]
    g = (pd.DataFrame({"tld": "." + tld, "phishing": f["is_phishing"]})
         .groupby("tld")["phishing"].agg(n="size", phishing="sum"))
    g["legitimate"] = g["n"] - g["phishing"]
    g["phishing_rate_%"] = (100 * g["phishing"] / g["n"]).round(1)
    g = g[["n", "legitimate", "phishing", "phishing_rate_%"]]

    qualified = g[g["n"] >= MIN_SAMPLES].sort_values("phishing_rate_%", ascending=False)
    print(f"{len(g)} distinct TLDs; {len(qualified)} have >= {MIN_SAMPLES} samples\n")
    print("HIGHEST phishing rate\n", qualified.head(25).to_string(), "\n")
    print("LOWEST phishing rate\n", qualified.tail(12).to_string())
    save(qualified, "04_tld_evidence.csv", index=True)


if __name__ == "__main__":
    main()
