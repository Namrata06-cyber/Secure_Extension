"""
06 — Baseline machine learning  (report p.10, Finding 2 part 1)

Task     : binary classification, positive class = phishing
Features : ONLY the 33 numeric features our extractor computes from URL text.
           The dataset's own columns are NOT used. Excluded on purpose:
           URLSimilarityIndex (leakage), IsHTTPS (disagrees with URL text),
           and all page-content columns (owned by the JavaScript module).
Splits   : A) Random 75/25 stratified — what most projects do
           B) Domain-disjoint 75/25 (GroupShuffleSplit by registered domain)
              so the model cannot memorise "evil.tk" from train and see it in test.
"""
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, confusion_matrix, f1_score, precision_score, recall_score, roc_auc_score
from sklearn.model_selection import GroupShuffleSplit, train_test_split
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.svm import LinearSVC

from common import load_features, save, ROOT
from url_analyzer import MODEL_FEATURES

SEED = 42


def make_models():
    return {
        "Logistic Regression": make_pipeline(StandardScaler(), LogisticRegression(max_iter=2000)),
        "Random Forest": RandomForestClassifier(n_estimators=100, random_state=SEED, n_jobs=-1),
        "Linear SVM": make_pipeline(StandardScaler(), LinearSVC(C=1.0, max_iter=5000, random_state=SEED)),
    }


def splits(f):
    y = f["is_phishing"].values
    idx = np.arange(len(f))
    tr, te = train_test_split(idx, test_size=0.25, stratify=y, random_state=SEED)
    yield "Random", tr, te
    gss = GroupShuffleSplit(n_splits=1, test_size=0.25, random_state=SEED)
    tr, te = next(gss.split(idx, y, groups=f["registered_domain"].values))
    shared = set(f["registered_domain"].values[tr]) & set(f["registered_domain"].values[te])
    assert not shared, "domain leak between train and test"
    yield "Domain-disjoint", tr, te


def evaluate(model, X_te, y_te):
    pred = model.predict(X_te)
    score = model.predict_proba(X_te)[:, 1] if hasattr(model, "predict_proba") else model.decision_function(X_te)
    tn, fp, fn, tp = confusion_matrix(y_te, pred).ravel()
    return {"accuracy": accuracy_score(y_te, pred), "precision": precision_score(y_te, pred),
            "recall": recall_score(y_te, pred), "f1": f1_score(y_te, pred),
            "roc_auc": roc_auc_score(y_te, score), "TN": tn, "FP": fp, "FN": fn, "TP": tp}


def main():
    f = load_features()
    X = f[MODEL_FEATURES].values
    y = f["is_phishing"].values

    rows, rf_dd = [], None
    for split_name, tr, te in splits(f):
        print(f"{split_name}: {len(tr):,} train / {len(te):,} test")
        for name, model in make_models().items():
            model.fit(X[tr], y[tr])
            m = evaluate(model, X[te], y[te])
            rows.append({"split": split_name, "model": name, **m})
            print(f"  {name:<20} acc {m['accuracy']:.4f}  f1 {m['f1']:.4f}")
            if split_name == "Domain-disjoint" and name == "Random Forest":
                rf_dd = model

    table = pd.DataFrame(rows).round(4)
    save(table, "06_model_results.csv")

    imp = (pd.Series(rf_dd.feature_importances_, index=MODEL_FEATURES)
           .sort_values(ascending=False).round(5).rename("gini_importance"))
    print("\nRandom Forest (domain-disjoint) — top features\n", imp.head(15).to_string())
    print(f"Top two features supply {imp.iloc[:2].sum():.1%} of the model's decision.")
    save(imp.to_frame(), "06_feature_importance.csv", index=True)

    try:
        import joblib
        (ROOT / "models").mkdir(exist_ok=True)
        joblib.dump({"model": rf_dd, "features": MODEL_FEATURES}, ROOT / "models" / "rf_domain_disjoint.joblib")
        print("  -> saved models/rf_domain_disjoint.joblib (used by 08_validate_real_urls.py)")
    except ImportError:
        pass


if __name__ == "__main__":
    main()
