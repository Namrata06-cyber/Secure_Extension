"""
Shared helpers for the evaluation scripts.

All scripts read the PhiUSIIL CSV from data/ (not committed to Git — it is 54 MB)
and write their tables to results/.
"""
import os
import sys
from pathlib import Path
from urllib.parse import urlsplit

import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))           # so "import url_analyzer" works without installing

from url_analyzer import analyze_url                      # noqa: E402
from url_analyzer.features import registered_domain       # noqa: E402

DATA_CSV = Path(os.environ.get("PHIUSIIL_CSV", ROOT / "data" / "PhiUSIIL_Phishing_URL_Dataset.csv"))
RESULTS = ROOT / "results"
RESULTS.mkdir(exist_ok=True)
FEATURE_CACHE = ROOT / "data" / "features_cache.pkl"

# Dataset label encoding (verified by inspecting sample URLs):
#   1 = LEGITIMATE, 0 = PHISHING.   Our positive class everywhere is PHISHING.
LEGIT, PHISH = 1, 0


def load_dataset() -> pd.DataFrame:
    if not DATA_CSV.exists():
        sys.exit(f"Dataset not found at {DATA_CSV}\n"
                 "Download PhiUSIIL_Phishing_URL_Dataset.csv (see data/README.md) "
                 "or set PHIUSIIL_CSV=/path/to/file.csv")
    return pd.read_csv(DATA_CSV)


def load_features(df: pd.DataFrame | None = None) -> pd.DataFrame:
    """Run the analyzer over every URL once (~30 s) and cache the result.

    Returns one row per URL with all 37 features plus: label, is_phishing,
    score, classification, indicators, registered_domain.
    """
    if FEATURE_CACHE.exists():
        return pd.read_pickle(FEATURE_CACHE)
    if df is None:
        df = load_dataset()
    print(f"Extracting features for {len(df):,} URLs (cached afterwards) ...")
    results = [analyze_url(u) for u in df["URL"]]
    f = pd.DataFrame([r["features"] for r in results])
    f.insert(0, "URL", df["URL"].values)
    f["label"] = df["label"].values
    f["is_phishing"] = (f["label"] == PHISH).astype(int)
    f["score"] = [r["score"] for r in results]
    f["classification"] = [r["classification"] for r in results]
    f["indicators"] = [";".join(r["indicators"]) for r in results]
    f["registered_domain"] = [registered_domain(urlsplit(u).hostname or "") for u in df["URL"]]
    f.to_pickle(FEATURE_CACHE)
    return f


def working_sample(df: pd.DataFrame) -> pd.DataFrame:
    """First 50 phishing + first 50 legitimate rows, in file order.
    Balanced by design: the literal first 100 rows are 66 legitimate / 34 phishing."""
    return pd.concat([df[df["label"] == PHISH].head(50), df[df["label"] == LEGIT].head(50)])


def save(df: pd.DataFrame, name: str, index=False):
    path = RESULTS / name
    df.to_csv(path, index=index)
    print(f"  -> saved {path.relative_to(ROOT)}")
