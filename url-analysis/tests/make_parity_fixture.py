"""
Regenerate tests/parity_fixture.json — the Python "answer key" that the
JavaScript port is checked against (js/test/parity.test.js).

    python tests/make_parity_fixture.py            # 2,000 random dataset URLs + fixed cases
    python tests/make_parity_fixture.py 20000      # bigger check

Run this again whenever you change a rule, a list, or a feature in Python,
then make the same change in js/url-analyzer.js until `node --test js/test/parity.test.js` passes.
"""
import json
import random
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from url_analyzer import analyze_url  # noqa: E402

EDGE_CASES = [
    "", "   ", "example.com/verify", "https://аpple.com/login", "http://site.com:99999/x",
    "http://site.com:8080/a//b", "https://a.com/x#frag", "http://[::1]:80/x",
    "https://x.com/?a=1&a=2&b=&c&=z&d+e=1", "http://host:80:90/", "HTTPS://WWW.EXAMPLE.COM/Login",
    "https://login.example.gov/", "http://user:pass@evil.tk/", "https://münchen.de/konto",
    "http://1.2.3.4.evil.com/",
]


def main(n_random: int = 2000):
    urls = [c["url"] for c in json.loads((ROOT / "tests" / "validation_urls.json").read_text())]
    urls += EDGE_CASES
    csv = ROOT / "data" / "PhiUSIIL_Phishing_URL_Dataset.csv"
    if csv.exists():
        import pandas as pd
        df = pd.read_csv(csv)
        urls += list(df[df.label == 0].URL.head(50)) + list(df[df.label == 1].URL.head(50))
        random.seed(0)
        urls += random.sample(list(df.URL), n_random)
    else:
        print("dataset not found — fixture will contain only the validation + edge-case URLs")

    out = [{"url": u, **{k: v for k, v in analyze_url(u).items() if k != "findings"}} for u in urls]
    path = ROOT / "tests" / "parity_fixture.json"
    path.write_text(json.dumps(out, ensure_ascii=False))
    print(f"wrote {len(out):,} cases to {path.relative_to(ROOT)}")


if __name__ == "__main__":
    main(int(sys.argv[1]) if len(sys.argv) > 1 else 2000)
