"""
05 — Threshold calibration  (report p.7, Finding 3)

Question: are the synopsis bands (Safe 0–30 / Suspicious 31–60 / Dangerous 61–100)
correct for these 18 rules?
Method: score all 235,795 URLs, sweep the decision threshold T, and record
precision / recall / F1 / accuracy at each T. Positive class = phishing.
"""
import pandas as pd

from common import load_features, save, RESULTS

THRESHOLDS = [1, 5, 8, 10, 12, 15, 18, 20, 25, 30, 35, 40, 50, 61]


def sweep(scores, y, thresholds):
    rows = []
    for t in thresholds:
        pred = scores >= t
        tp = int((pred & (y == 1)).sum()); fp = int((pred & (y == 0)).sum())
        fn = int((~pred & (y == 1)).sum()); tn = int((~pred & (y == 0)).sum())
        p = tp / (tp + fp) if tp + fp else 1.0
        r = tp / (tp + fn)
        rows.append({"T": t, "TP": tp, "FP": fp, "FN": fn, "TN": tn,
                     "precision": round(p, 4), "recall": round(r, 4),
                     "f1": round(2 * p * r / (p + r), 4) if p + r else 0.0,
                     "accuracy": round((tp + tn) / len(y), 4)})
    return pd.DataFrame(rows)


def plot(table, path):
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except ImportError:
        print("  (matplotlib not installed — skipping figure)")
        return
    fig, ax = plt.subplots(figsize=(9, 4))
    ax.plot(table["T"], table["precision"], label="Precision", color="#1f3864")
    ax.plot(table["T"], table["f1"], label="F1", color="#4a7c3a")
    ax.plot(table["T"], table["recall"], label="Recall", color="#c0504d")
    ax.axvline(20, ls="--", color="#4a7c3a", lw=1); ax.text(20.5, 0.6, "T = 20 adopted", color="#4a7c3a")
    ax.axvline(61, ls="--", color="#c0504d", lw=1); ax.text(52, 0.9, "T = 61 · synopsis", color="#c0504d")
    ax.set_xlabel("Decision threshold T"); ax.set_ylim(0, 1.05); ax.legend(loc="center right")
    ax.spines[["top", "right"]].set_visible(False)
    fig.tight_layout(); fig.savefig(path, dpi=150)
    print(f"  -> saved figure {path.name}")


def main():
    f = load_features()
    table = sweep(f["score"], f["is_phishing"], THRESHOLDS)
    print(table.to_string(index=False))

    zero = int(((f.score == 0) & (f.is_phishing == 1)).sum())
    total = int(f.is_phishing.sum())
    print(f"\nPhishing URLs that trigger no rule at all: {zero:,} of {total:,} ({zero / total:.1%})")
    at61 = table[table["T"] == 61].iloc[0]
    print(f"At the synopsis threshold T = 61: recall {at61.recall} "
          f"— catches {at61.TP:,} of {total:,} phishing URLs")

    save(table, "05_threshold_sweep.csv")
    plot(sweep(f["score"], f["is_phishing"], range(1, 62)), RESULTS / "05_threshold_sweep.png")


if __name__ == "__main__":
    main()
