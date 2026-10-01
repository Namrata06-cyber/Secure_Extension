"""
normalize.py — pipeline stages 01–03: raw URL -> normalised URL -> parsed parts.

The module must never crash on bad input (the extension calls it on every page
load), so every failure path returns parse_ok = False instead of raising.
"""
from dataclasses import dataclass
from urllib.parse import urlsplit, SplitResult
import re

_SCHEME_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.-]*://")


@dataclass
class ParsedURL:
    url: str                 # the normalised URL string every feature is computed on
    parts: SplitResult | None
    hostname: str            # lower-case, no port, no user-info ("" if missing)
    no_scheme: bool          # True if we had to add "http://" ourselves
    parse_ok: bool


def normalize(raw) -> ParsedURL:
    """Stage 02 (normalise and repair) + stage 03 (parse)."""
    if raw is None or not isinstance(raw, str) or not raw.strip():
        return ParsedURL(url="", parts=None, hostname="", no_scheme=False, parse_ok=False)

    url = raw.strip()

    # Missing scheme ("example.com/verify") -> add one, but remember we did it.
    no_scheme = not _SCHEME_RE.match(url)
    if no_scheme:
        url = "http://" + url

    # Fragments (#...) are never sent to the server; drop them.
    if "#" in url:
        url = url.split("#", 1)[0]

    try:
        parts = urlsplit(url)
        hostname = parts.hostname or ""
        _ = parts.port            # raises ValueError on "site.com:99999" or "site.com:abc"
    except ValueError:
        return ParsedURL(url=url, parts=None, hostname="", no_scheme=no_scheme, parse_ok=False)

    if not hostname:
        return ParsedURL(url=url, parts=parts, hostname="", no_scheme=no_scheme, parse_ok=False)

    # IDN: a Unicode hostname ("аpple.com" with Cyrillic а) is converted to the
    # punycode form the browser actually resolves ("xn--pple-43d.com").
    if not hostname.isascii():
        try:
            hostname = hostname.encode("idna").decode("ascii")
        except UnicodeError:
            return ParsedURL(url=url, parts=parts, hostname="", no_scheme=no_scheme, parse_ok=False)

    return ParsedURL(url=url, parts=parts, hostname=hostname, no_scheme=no_scheme, parse_ok=True)
