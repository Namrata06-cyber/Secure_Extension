"""
Command-line entry point.

    python -m url_analyzer "http://paypal.com.secure-account-verify.tk/signin"
    python -m url_analyzer --json "https://www.google.com"
"""
import argparse
import json
import sys

from .scorer import analyze_url

COLOURS = {"Safe": "\033[32m", "Suspicious": "\033[33m", "Dangerous": "\033[31m", "Unknown": "\033[90m"}
RESET = "\033[0m"


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Score a URL for phishing risk (0–100).")
    ap.add_argument("urls", nargs="+", help="one or more URLs")
    ap.add_argument("--json", action="store_true", help="print full JSON result, including all 37 features")
    args = ap.parse_args(argv)

    for url in args.urls:
        r = analyze_url(url)
        if args.json:
            print(json.dumps(r, indent=2))
            continue
        c = COLOURS.get(r["classification"], "") if sys.stdout.isatty() else ""
        print(f"{url}\n  score {r['score']:>3}  ->  {c}{r['classification']}{RESET if c else ''}")
        for rule_id, text in zip(r["indicators"], r["findings"]):
            print(f"    [{rule_id}] {text}")
        if not r["indicators"]:
            print("    (no indicators fired)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
