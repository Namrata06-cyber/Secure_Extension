# Dataset

The dataset is **not stored in Git** (54 MB). To run the evaluation scripts:

1. Download the **PhiUSIIL Phishing URL Dataset** (Prasad & Chandra, 2024) from the UCI Machine Learning Repository  
   https://archive.ics.uci.edu/dataset/967/phiusiil+phishing+url+dataset
2. Unzip it and put `PhiUSIIL_Phishing_URL_Dataset.csv` in this folder.

Or point the scripts at a copy elsewhere:

```bash
export PHIUSIIL_CSV=/path/to/PhiUSIIL_Phishing_URL_Dataset.csv
```

| Attribute | Value |
|---|---|
| Records | 235,795 |
| Columns | 55 |
| Label | `1` = legitimate (134,850) · `0` = phishing (100,945) |
| Columns we use | `URL` (input) and `label` (evaluation only) — every feature is recomputed from the URL string |

**PhishTank** (named in the project plan) was not supplied. It is a phishing-only feed and cannot train a classifier on its own.
