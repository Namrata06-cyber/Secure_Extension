# URL Analysis Module

**Browser Extension for Phishing Detection — Group SY503**
Department of Computer Science & Engineering · MIT School of Computing, MIT-ADT University, Pune
Guide: Vrushali Kondhalkar · Module owner: Bhakti Deshmukh · Rev 1.1

Takes **one URL string** and returns a **0–100 risk score**, a **Safe / Suspicious / Dangerous** label and **plain-English findings**. It does not load the page or make any network request. It is the first-pass filter of the extension; the JavaScript/DOM module handles page content.

→ Full design: [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md)

```
$ python -m url_analyzer "http://paypal.com.secure-account-verify.tk/signin"
http://paypal.com.secure-account-verify.tk/signin
  score  64  ->  Dangerous
    [R02] Domain uses a top-level domain offered for free and heavily abused (.tk/.ml/.ga/.cf/.gq).
    [R09a] URL contains multiple authentication or payment related keywords.
    [R10] A well-known brand name appears in the URL but is not the registered domain.
    [R12] URL uses HTTP instead of HTTPS, so traffic is not encrypted.
    [R14] Registered domain name looks randomly generated.
```

---

## Quick start

```bash
git clone <team-repo-url>
cd <team-repo>/url-analysis

# 1. the analyzer itself needs nothing but Python 3.10+
python -m url_analyzer "https://www.google.com"

# 2. tests
pip install -r requirements.txt
pytest -q                                   # 36 Python tests
node --test js/test/parity.test.js          # JS port == Python on 2,133 URLs

# 3. reproduce every number in the report (needs the dataset, see data/README.md)
python evaluation/run_all.py                # ~2 minutes; writes results/
```

Use it from code:

```python
from url_analyzer import analyze_url
r = analyze_url("https://secure-paypal.com/")
r["score"], r["classification"], r["indicators"]      # (28, 'Dangerous', ['R09a', 'R10'])
```

```js
// in the extension
importScripts("url-analyzer.js");
const r = URLAnalyzer.analyzeUrl(details.url);        // same object as Python
```

---

## How it works

| # | Stage | File |
|---|---|---|
| 01 | Raw URL (one string) | — |
| 02 | Normalise & repair — missing scheme, fragments, IDN → punycode, bad ports | `normalize.py` |
| 03 | Parse — `urlsplit` → scheme / host / port / path / query | `normalize.py` |
| 04 | Feature extraction — 33 numeric + 4 descriptive = **37 features** | `features.py` |
| 05 | Rule engine — **18 weighted rules**, each emits an indicator ID | `rules.py` |
| 06 | Risk score — `clamp(Σ weights, 0, 100)` | `scorer.py` |
| 07 | Classify & explain — Safe 0–5 · Suspicious 6–19 · Dangerous 20–100 | `scorer.py` |

All lists (suspicious TLDs, keywords, brands, band cut-offs) are in [`url_analyzer/config.py`](url_analyzer/config.py).

## Key results (PhiUSIIL, 235,795 URLs)

| Result | Value | Script |
|---|---|---|
| Legitimate URLs with a path or query string | **0 of 134,850** — every one is a bare homepage | `02_structural_bias.py` |
| Phishing URLs that trigger no rule | **27.7 %** (27,941) | `05_threshold_sweep.py` |
| Recall at the synopsis threshold T = 61 | **0.005** → bands recalibrated to 0–5 / 6–19 / 20+ | `05_threshold_sweep.py` |
| Precision at adopted threshold T = 20 | **0.999** | `05_threshold_sweep.py` |
| Random Forest, domain-disjoint test accuracy | **99.68 %** | `06_train_models.py` |
| Real-world URLs correct: rule engine vs Random Forest | **15/18 vs 10/18** | `08_validate_real_urls.py` |

The 99.68 % does **not** transfer to live traffic: the model learned "has a path ⇒ phishing" because no legitimate URL in the dataset has one. See the report, pages 10–11.

---

## Adding this folder to the team GitHub repository

If the leader has created the repo and added you as a collaborator:

```bash
git clone https://github.com/<leader>/<repo>.git
cd <repo>
git checkout -b url-analysis                 # work on your own branch
# copy this whole url-analysis/ folder into the repo root, then:
git add url-analysis
git commit -m "Add URL analysis module: analyzer, JS port, evaluation, docs"
git push -u origin url-analysis
```

Then open GitHub → **Compare & pull request** → ask the leader to merge. The dataset CSV is ignored by `.gitignore` on purpose (54 MB); teammates download it themselves (see `data/README.md`).

## Status

| Implemented | Proposed, not built |
|---|---|
| 37-feature extractor · 18-rule engine · calibrated thresholds · EDA · TLD evidence · baseline ML (LR, RF, Linear SVM) · ablation · 18-URL real-world validation · **JavaScript port with parity test** | Score fusion with the JavaScript module · live PhishTank/OpenPhish lookup · typosquatting edit-distance check · official Public Suffix List |

Rule weights are initial heuristics informed by measured class separation, not numerically optimised. Thresholds are calibrated on a structurally biased dataset and must be recalibrated on real browsing traffic before release.
