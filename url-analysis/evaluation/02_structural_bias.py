"""
02 — The structural bias  (report p.4, Finding 1)

Parse every URL and ask: does it have anything after the hostname?
Result: 0 of 134,850 legitimate URLs have a path or a query string,
and 0 of them use plain HTTP. Every legitimate URL is a bare homepage.
"""
import pandas as pd

from common import load_features, save


def crosstab(f, flag, yes, no):
    rows = []
    for name, grp in [("Phishing", f[f.is_phishing == 1]), ("Legitimate", f[f.is_phishing == 0])]:
        k = int(flag[grp.index].sum())
        rows.append({"class": f"{name} ({len(grp):,})", yes: k, no: len(grp) - k,
                     f"% {yes}": round(100 * k / len(grp), 2)})
    return pd.DataFrame(rows)


def main():
    f = load_features()

    has_path = f["num_path_segments"] > 0          # "real" path: more than a bare "/"
    has_query = f["query_length"] > 0
    plain_http = f["is_https"] == 0

    t1 = crosstab(f, has_path, "has real path", "no path")
    t2 = crosstab(f, has_query, "has query string", "no query")
    t3 = crosstab(f, plain_http, "plain HTTP", "HTTPS")
    for t in (t1, t2, t3):
        print(t.to_string(index=False), "\n")

    # raw string length as stored in the dataset (our url_length feature drops #fragments)
    raw_len = f["URL"].str.len()
    lengths = raw_len.groupby(f["is_phishing"]).agg(["mean", "max"]).round(1)
    lengths.index = ["Legitimate", "Phishing"]
    longest_legit = f.loc[raw_len[f.is_phishing == 0].idxmax(), "URL"]
    print(lengths, f"\nLongest legitimate URL: {longest_legit}")

    save(pd.concat([t1, t2, t3], keys=["path", "query", "scheme"]), "02_structural_bias.csv", index=True)
    save(lengths, "02_url_length.csv", index=True)


if __name__ == "__main__":
    main()
