"""
07 — Ablation study  (report p.10)

Remove a feature group, retrain the Random Forest on the domain-disjoint split,
and measure what is lost. If accuracy barely moves when the two artifact groups
(scheme, path+query) are removed, the model was leaning on dataset artifacts.
"""
import pandas as pd
from sklearn.ensemble import RandomForestClassifier

from common import load_features, save
from url_analyzer import MODEL_FEATURES
from url_analyzer.features import PATH_QUERY_GROUP, SCHEME_GROUP

import importlib
train = importlib.import_module("06_train_models")

SCENARIOS = {
    "A. All features": [],
    "B. Remove is_https / scheme": SCHEME_GROUP,
    "C. Remove path + query features": PATH_QUERY_GROUP,
    "D. Remove both artifact groups": SCHEME_GROUP + PATH_QUERY_GROUP,
}


def main():
    f = load_features()
    y = f["is_phishing"].values
    _, tr, te = list(train.splits(f))[1]          # domain-disjoint split

    rows = []
    for name, drop in SCENARIOS.items():
        cols = [c for c in MODEL_FEATURES if c not in drop]
        X = f[cols].values
        rf = RandomForestClassifier(n_estimators=100, random_state=train.SEED, n_jobs=-1).fit(X[tr], y[tr])
        m = train.evaluate(rf, X[te], y[te])
        rows.append({"scenario": name, "features": len(cols), **m})
        print(f"{name:<34} {len(cols):>2} features  acc {m['accuracy']:.4f}  recall {m['recall']:.4f}")

    table = pd.DataFrame(rows).round(4)
    a, d = table.iloc[0], table.iloc[3]
    print(f"\nAccuracy lost removing both artifact groups: {100*(a.accuracy-d.accuracy):.2f} pp "
          f"({a.accuracy:.4f} -> {d.accuracy:.4f}); recall lost {100*(a.recall-d.recall):.2f} pp")
    save(table, "07_ablation.csv")


if __name__ == "__main__":
    main()
