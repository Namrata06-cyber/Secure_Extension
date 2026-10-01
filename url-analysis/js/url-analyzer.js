/**
 * url-analyzer.js — JavaScript port of the Python url_analyzer package.
 *
 * Drop-in for the browser extension (background service worker or content
 * script). No dependencies, no network requests, no page access.
 *
 *   const r = URLAnalyzer.analyzeUrl("http://paypal.com.secure-account-verify.tk/signin");
 *   // { score: 64, classification: "Dangerous", indicators: [...], findings: [...], features: {...} }
 *
 * Parity with Python is checked by js/test/parity.test.js on thousands of
 * dataset URLs: every feature and every score must match exactly.
 *
 * NOTE: we deliberately do NOT use `new URL()` to split the URL, because it
 * rewrites the string (adds a trailing "/", resolves "..", re-encodes
 * characters), which would change the features. We mirror Python's
 * urllib.parse.urlsplit instead. `new URL()` is used only to convert a
 * Unicode hostname to punycode.
 */
(function (root) {
  "use strict";

  // ─────────────────────────── config (mirror of config.py) ───────────────────────────
  const MULTI_PART_SUFFIXES = new Set([
    "co.uk", "org.uk", "ac.uk", "gov.uk", "net.uk",
    "com.au", "net.au", "org.au", "edu.au", "gov.au",
    "co.in", "net.in", "org.in", "ac.in", "gov.in",
    "co.jp", "ne.jp", "or.jp", "ac.jp",
    "com.br", "com.mx", "com.ar", "com.tr", "com.cn",
    "co.za", "co.nz", "co.kr", "co.il",
  ]);
  const SUSPICIOUS_TLDS_TIER1 = new Set(["cf", "gq", "ml", "ga", "tk"]);
  const SUSPICIOUS_TLDS_TIER2 = new Set([
    "top", "site", "link", "gd", "fun", "xyz", "ly", "cloud", "work",
    "shop", "club", "live", "online", "ws", "page",
  ]);
  const TRUSTED_TLDS = new Set(["gov", "mil", "edu"]);
  const SUSPICIOUS_KEYWORDS = [
    "login", "signin", "logon", "verify", "verification", "account",
    "update", "secure", "security", "banking", "bank", "confirm",
    "password", "credential", "auth", "authenticate", "wallet", "billing",
    "invoice", "payment", "pay", "webscr", "suspend", "unlock", "recover",
    "validate", "ebayisapi", "token", "session", "reset",
  ];
  const KNOWN_BRANDS = [
    "paypal", "google", "microsoft", "apple", "amazon", "facebook",
    "netflix", "instagram", "whatsapp", "linkedin", "twitter", "yahoo",
    "dropbox", "wellsfargo", "bankofamerica", "ebay", "adobe", "docusign",
    "fedex", "coinbase", "binance", "hdfc", "icici", "paytm", "flipkart",
  ];
  const BAND_SAFE_MAX = 5;
  const BAND_SUSPICIOUS_MAX = 19;

  const MODEL_FEATURES = [
    "url_length", "domain_length", "path_length", "query_length", "longest_path_segment",
    "num_subdomains", "num_dots", "num_hyphens_domain", "num_underscores",
    "num_path_segments", "num_query_params",
    "num_digits", "digit_ratio", "num_special_chars", "special_char_ratio",
    "domain_entropy", "domain_has_digits",
    "has_ip", "has_port", "is_punycode", "tld_length", "suspicious_tld_tier", "trusted_tld",
    "suspicious_keyword_count", "brand_impersonation",
    "num_percent_encodings", "encoding_ratio", "has_at_symbol", "double_slash_in_path",
    "num_ampersands", "num_equals",
    "is_https", "no_scheme",
  ];

  const SCHEME_RE = /^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//;
  const IPV4_RE = /^\d{1,3}(\.\d{1,3}){3}$/;
  const PCT_RE = /%[0-9a-fA-F]{2}/g;
  const SAFE_PUNCT = new Set([":", "/", ".", "?", "=", "&", "-", "_"]);
  const DIGIT_RE = /\p{Nd}/u;
  const ALNUM_RE = /[\p{L}\p{N}]/u;

  // ─────────────────────────── helpers ───────────────────────────
  /** Same result as Python round(x, 4): nearest, and exact ties go to the even digit.
   *  At 4 decimals a double is an exact tie only when x·32 is an odd integer. */
  function round4(x) {
    const k = x * 32;
    if (Number.isInteger(k) && k % 2 !== 0) {
      const lo = Math.floor(x * 1e4);
      return (lo % 2 === 0 ? lo : lo + 1) / 1e4;
    }
    return Number(x.toFixed(4));
  }
  const count = (s, sub) => s.split(sub).length - 1;

  /** Mirror of Python urllib.parse.urlsplit for "scheme://..." strings. */
  function urlsplit(url) {
    const i = url.indexOf("://");
    const scheme = url.slice(0, i).toLowerCase();
    let rest = url.slice(i + 3);
    const cut = rest.search(/[/?#]/);
    const netloc = cut === -1 ? rest : rest.slice(0, cut);
    rest = cut === -1 ? "" : rest.slice(cut);
    let path = rest, query = "";
    const q = rest.indexOf("?");
    if (q !== -1) { path = rest.slice(0, q); query = rest.slice(q + 1); }
    const h = query.indexOf("#"); if (h !== -1) query = query.slice(0, h);
    const hp = path.indexOf("#"); if (hp !== -1) path = path.slice(0, hp);

    // hostname / port, as Python computes them from netloc
    const hostport = netloc.slice(netloc.lastIndexOf("@") + 1);
    let host, portStr = null;
    if (hostport.startsWith("[")) {                       // IPv6 literal
      const end = hostport.indexOf("]");
      host = hostport.slice(1, end);
      const after = hostport.slice(end + 1);
      if (after.startsWith(":")) portStr = after.slice(1);
    } else {
      const c = hostport.indexOf(":");                   // Python partitions on the FIRST ':'
      host = c === -1 ? hostport : hostport.slice(0, c);
      if (c !== -1) portStr = hostport.slice(c + 1);
    }
    let port = null;
    if (portStr !== null && portStr !== "") {
      if (!/^\d+$/.test(portStr)) throw new Error("bad port");
      port = parseInt(portStr, 10);
      if (port > 65535) throw new Error("bad port");
    }
    return { scheme, netloc, path, query, hostname: host.toLowerCase(), port };
  }

  function normalize(raw) {
    const fail = (url, noScheme) => ({ url, parts: null, hostname: "", noScheme, parseOk: false });
    if (typeof raw !== "string" || raw.trim() === "") return fail("", false);

    let url = raw.trim();
    const noScheme = !SCHEME_RE.test(url);
    if (noScheme) url = "http://" + url;
    if (url.includes("#")) url = url.split("#")[0];

    let parts;
    try { parts = urlsplit(url); } catch (e) { return fail(url, noScheme); }
    let hostname = parts.hostname;
    if (!hostname) return fail(url, noScheme);

    // Unicode hostname -> punycode (what the browser actually resolves)
    if (!/^[\x00-\x7F]*$/.test(hostname)) {
      try { hostname = new URL("http://" + hostname).hostname; }
      catch (e) { return fail(url, noScheme); }
    }
    return { url, parts, hostname, noScheme, parseOk: true };
  }

  function splitDomain(hostname) {
    if (IPV4_RE.test(hostname)) return [[], hostname, ""];
    const labels = hostname.split(".").filter(Boolean);
    if (labels.length === 0) return [[], "", ""];
    if (labels.length === 1) return [[], labels[0], ""];
    const two = labels.slice(-2).join(".");
    if (MULTI_PART_SUFFIXES.has(two) && labels.length >= 3) {
      return [labels.slice(0, -3), labels[labels.length - 3], two];
    }
    return [labels.slice(0, -2), labels[labels.length - 2], labels[labels.length - 1]];
  }

  function shannonEntropy(s) {
    if (!s) return 0;
    const freq = {};
    for (const ch of s) freq[ch] = (freq[ch] || 0) + 1;
    const n = [...s].length;
    let h = 0;
    for (const k in freq) { const p = freq[k] / n; h -= p * Math.log2(p); }
    return h;
  }

  function findKeywords(text) {
    const hits = SUSPICIOUS_KEYWORDS.filter((k) => text.includes(k));
    return hits.filter((k) => !hits.some((o) => o !== k && o.includes(k)));
  }

  /** Python unquote(): invalid %-sequences are left as they are. */
  function unquote(s) {
    return s.replace(/(%[0-9a-fA-F]{2})+/g, (m) => {
      try { return decodeURIComponent(m); } catch (e) { return m; }
    });
  }

  /** len(parse_qs(query)) — number of distinct keys with a non-empty value. */
  function countQueryParams(query) {
    const keys = new Set();
    for (const piece of query.split("&")) {
      if (!piece) continue;
      const eq = piece.indexOf("=");
      if (eq === -1) continue;
      if (piece.slice(eq + 1) === "") continue;
      keys.add(unquote(piece.slice(0, eq).replace(/\+/g, " ")));
    }
    return keys.size;
  }

  // ─────────────────────────── features (stage 04) ───────────────────────────
  function emptyFeatures(noScheme) {
    const f = {};
    for (const k of MODEL_FEATURES) f[k] = 0;
    Object.assign(f, { tld: "", suspicious_keywords: "", brands_found: "", parse_ok: 0 });
    f.no_scheme = noScheme ? 1 : 0;
    return f;
  }

  function extractFeatures(raw) {
    const p = normalize(raw);
    if (!p.parseOk) return emptyFeatures(p.noScheme);

    const url = p.url, host = p.hostname, parts = p.parts;
    const lower = url.toLowerCase();
    const path = parts.path, query = parts.query;
    const segments = path.split("/").filter(Boolean);

    const isIp = IPV4_RE.test(host);
    const [subdomains, regLabel, suffix] = splitDomain(host);
    const regDomain = suffix ? `${regLabel}.${suffix}` : regLabel;
    const lastLabel = isIp ? "" : host.slice(host.lastIndexOf(".") + 1);

    const chars = [...url];
    const urlLen = chars.length;
    const digits = chars.filter((c) => DIGIT_RE.test(c)).length;
    const specials = chars.filter((c) => !ALNUM_RE.test(c) && !SAFE_PUNCT.has(c)).length;
    const pct = (url.match(PCT_RE) || []).length;

    const tier = SUSPICIOUS_TLDS_TIER1.has(lastLabel) ? 1 : SUSPICIOUS_TLDS_TIER2.has(lastLabel) ? 2 : 0;
    const keywords = findKeywords(lower);
    const brands = KNOWN_BRANDS.filter((b) => lower.includes(b) && b !== regLabel);

    return {
      url_length: urlLen,
      domain_length: [...host].length,
      path_length: [...path].length,
      query_length: [...query].length,
      longest_path_segment: segments.reduce((m, s) => Math.max(m, [...s].length), 0),
      num_subdomains: subdomains.length,
      num_dots: count(url, "."),
      num_hyphens_domain: count(host, "-"),
      num_underscores: count(url, "_"),
      num_path_segments: segments.length,
      num_query_params: countQueryParams(query),
      num_digits: digits,
      digit_ratio: round4(digits / urlLen),
      num_special_chars: specials,
      special_char_ratio: round4(specials / urlLen),
      domain_entropy: round4(shannonEntropy(regLabel)),
      domain_has_digits: /\d/.test(regDomain) ? 1 : 0,
      has_ip: isIp ? 1 : 0,
      has_port: parts.port !== null ? 1 : 0,
      is_punycode: host.includes("xn--") ? 1 : 0,
      tld: suffix,
      tld_length: suffix.length,
      suspicious_tld_tier: tier,
      trusted_tld: TRUSTED_TLDS.has(lastLabel) ? 1 : 0,
      suspicious_keyword_count: keywords.length,
      suspicious_keywords: keywords.join(";"),
      brand_impersonation: brands.length ? 1 : 0,
      brands_found: brands.join(";"),
      num_percent_encodings: pct,
      encoding_ratio: round4((3 * pct) / urlLen),
      has_at_symbol: url.includes("@") ? 1 : 0,
      double_slash_in_path: path.includes("//") ? 1 : 0,
      num_ampersands: count(url, "&"),
      num_equals: count(url, "="),
      is_https: parts.scheme === "https" ? 1 : 0,
      no_scheme: p.noScheme ? 1 : 0,
      parse_ok: 1,
    };
  }

  // ─────────────────────────── rules (stage 05) ───────────────────────────
  const RULES = [
    ["R01", 25, "URL uses a raw IP address instead of a domain name.", (f) => f.has_ip === 1],
    ["R02", 20, "Domain uses a top-level domain offered for free and heavily abused (.tk/.ml/.ga/.cf/.gq).", (f) => f.suspicious_tld_tier === 1],
    ["R03", 12, "Domain uses a low-cost new TLD with a high observed phishing rate.", (f) => f.suspicious_tld_tier === 2],
    ["R04", -20, "Domain uses a restricted-registration TLD (.gov/.edu/.mil).", (f) => f.trusted_tld === 1],
    ["R05", 12, "URL contains an unusually large number of subdomains.", (f) => f.num_subdomains >= 3],
    ["R06", 20, "URL contains an \"@\" symbol, which can hide the real destination.", (f) => f.has_at_symbol === 1],
    ["R07", 15, "Domain uses punycode/IDN encoding, which can imitate Latin letters.", (f) => f.is_punycode === 1],
    ["R08", 10, "URL is unusually long.", (f) => f.url_length > 75],
    ["R09a", 10, "URL contains multiple authentication or payment related keywords.", (f) => f.suspicious_keyword_count >= 2],
    ["R09b", 5, "URL contains an authentication or payment related keyword.", (f) => f.suspicious_keyword_count === 1],
    ["R10", 18, "A well-known brand name appears in the URL but is not the registered domain.", (f) => f.brand_impersonation === 1],
    ["R11", 10, "URL contains heavy percent-encoding, which can obscure its real content.", (f) => f.num_percent_encodings >= 3],
    ["R12", 8, "URL uses HTTP instead of HTTPS, so traffic is not encrypted.", (f) => f.is_https === 0],
    ["R13", 8, "Domain contains an unusually high number of hyphens.", (f) => f.num_hyphens_domain >= 3],
    ["R14", 8, "Registered domain name looks randomly generated.", (f) => f.domain_entropy > 3.6],
    ["R15", 6, "URL specifies a non-standard network port.", (f) => f.has_port === 1],
    ["R16", 8, "URL path contains an unusual double slash.", (f) => f.double_slash_in_path === 1],
    ["R17", 5, "URL carries an unusually large number of query parameters.", (f) => f.num_query_params >= 5],
  ].map(([id, weight, finding, test]) => ({ id, weight, finding, test }));

  // ─────────────────────────── score + classify (stages 06–07) ───────────────────────────
  function classify(score) {
    if (score <= BAND_SAFE_MAX) return "Safe";
    if (score <= BAND_SUSPICIOUS_MAX) return "Suspicious";
    return "Dangerous";
  }

  function analyzeUrl(url) {
    const features = extractFeatures(url);
    if (!features.parse_ok) {
      return { url, score: 0, classification: "Unknown", indicators: [],
               findings: ["URL could not be parsed."], features };
    }
    const fired = RULES.filter((r) => r.test(features));
    const raw = fired.reduce((s, r) => s + r.weight, 0);
    const score = Math.max(0, Math.min(100, raw));
    return {
      url, score, classification: classify(score),
      indicators: fired.map((r) => r.id),
      findings: fired.map((r) => r.finding),
      features,
    };
  }

  const api = { analyzeUrl, extractFeatures, classify, RULES, MODEL_FEATURES, version: "1.1.0" };
  if (typeof module !== "undefined" && module.exports) module.exports = api;
  root.URLAnalyzer = api;
})(typeof globalThis !== "undefined" ? globalThis : this);
