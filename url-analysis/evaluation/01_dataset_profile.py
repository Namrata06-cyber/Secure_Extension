"""
01 — Dataset profile + column decisions  (report p.3)

Checks: size, class balance, missing values, duplicates, malformed URLs,
distinct registered domains, and the two columns we exclude:
  * URLSimilarityIndex  — leakage (exactly 100 for every legitimate row)
  * IsHTTPS             — disagrees with the URL text
"""
import pandas as pd

from common import load_dataset, load_features, save, LEGIT, PHISH


def main():
    df = load_dataset()
    feats = load_features(df)
    n = len(df)

    legit = int((df.label == LEGIT).sum())
    phish = int((df.label == PHISH).sum())
    urls = df["URL"].astype(str)

    rows = [
        ("Records", f"{n:,}"),
        ("Columns", df.shape[1]),
        ("Label encoding", f"1 = LEGITIMATE ({legit:,}) · 0 = PHISHING ({phish:,})"),
        ("Class balance", f"{legit / n:.1%} legitimate / {phish / n:.1%} phishing"),
        ("Missing values", int(df.isna().sum().sum())),
        ("Fully duplicated rows", int(df.duplicated().sum())),
        ("Duplicated URL strings", f"{int(urls.duplicated().sum()):,} ({urls.nunique():,} unique of {n:,})"),
        ("Malformed URLs (no http:// or https://)", int((~urls.str.match(r"^https?://")).sum())),
        ("Distinct registered domains", f"{feats['registered_domain'].nunique():,}"),
    ]

    # --- URLSimilarityIndex leakage -------------------------------------
    usi_legit = df.loc[df.label == LEGIT, "URLSimilarityIndex"]
    one_rule_pred = (df["URLSimilarityIndex"] >= 100).map({True: LEGIT, False: PHISH})
    one_rule_acc = (one_rule_pred == df["label"]).mean()
    rows += [
        ("URLSimilarityIndex on legitimate rows (min / max)", f"{usi_legit.min()} / {usi_legit.max()}"),
        ("Accuracy of the single rule 'URLSimilarityIndex >= 100 -> legitimate'", f"{one_rule_acc:.2%}"),
    ]

    # --- IsHTTPS disagrees with the URL string --------------------------
    starts_http = urls.str.lower().str.startswith("http://")
    rows.append(("Rows that start http:// but have IsHTTPS = 1",
                 int((starts_http & (df["IsHTTPS"] == 1)).sum())))

    # --- Bare-IP hostnames (evidence for rule R01) -----------------------
    ip = feats.groupby("is_phishing")["has_ip"].sum()
    rows.append(("Bare-IP hostnames (phishing / legitimate)", f"{int(ip.get(1, 0)):,} / {int(ip.get(0, 0)):,}"))

    out = pd.DataFrame(rows, columns=["attribute", "value"])
    print(out.to_string(index=False))
    save(out, "01_dataset_profile.csv")


if __name__ == "__main__":
    main()
