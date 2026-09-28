/**
 * Rule 7: OBFUSCATION
 *
 * Detects heuristic indicators of JavaScript obfuscation:
 *   - dynamic execution directly wrapping string decoding (atob, unescape, decodeURIComponent)
 *   - String character reconstruction (fromCharCode / fromCodePoint)
 *   - Hexadecimal escape sequences (e.g. "\x68\x74\x74\x70")
 *   - Unicode escape sequences (e.g. "\u0068\u0074...")
 *   - Hex-prefixed obfuscator identifiers (e.g. _0x4a2b)
 *
 * Does NOT automatically classify standard minified JavaScript as malicious.
 * Assigned heuristic weight: 15 (HIGH).
 */

import { RULE_WEIGHTS } from "../scoring.js";

function stripCommentsKeepStrings(code) {
  let result = "";
  let i = 0;
  const len = code.length;

  while (i < len) {
    const ch = code[i];
    const next = code[i + 1];

    if (ch === "/" && next === "/") {
      while (i < len && code[i] !== "\n") {
        result += " ";
        i++;
      }
      continue;
    }

    if (ch === "/" && next === "*") {
      result += "  ";
      i += 2;
      while (i < len && !(code[i] === "*" && code[i + 1] === "/")) {
        result += code[i] === "\n" ? "\n" : " ";
        i++;
      }
      if (i < len) {
        result += "  ";
        i += 2;
      }
      continue;
    }

    if (ch === '"' || ch === "'" || ch === "`") {
      const quote = ch;
      result += quote;
      i++;
      while (i < len && code[i] !== quote) {
        if (code[i] === "\\") {
          result += code[i] + (code[i + 1] || "");
          i += 2;
          continue;
        }
        result += code[i];
        i++;
      }
      if (i < len) {
        result += code[i];
        i++;
      }
      continue;
    }

    result += ch;
    i++;
  }

  return result;
}

export function runRule(code) {
  const findings = [];
  const cleanedCode = stripCommentsKeepStrings(code);
  const lines = cleanedCode.split("\n");
  const originalLines = code.split("\n");

  const evalDecodeComboRegex =
    /\beval\s*\(\s*(?:atob|unescape|decodeURIComponent)\s*\(/i;
  const fromCharCodeRegex =
    /\bString\s*\.\s*from(?:CharCode|CodePoint)\s*\(/;
  const multiEscapeRegex =
    /(?:\\x[0-9a-fA-F]{2}\s*){2,}|(?:\\u[0-9a-fA-F]{4}\s*){2,}/;
  const hexIdentifierRegex = /\b_0x[0-9a-fA-F]{3,}\b/;

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];

    if (evalDecodeComboRegex.test(line)) {
      findings.push({
        ruleId: "OBFUSCATION",
        severity: "HIGH",
        score: RULE_WEIGHTS.OBFUSCATION,
        line: i + 1,
        message: "Obfuscation indicator: dynamic execution directly wrapping string decoding.",
        evidence: originalLines[i].trim().slice(0, 120),
        category: "obfuscation",
        occurrences: 1,
      });
      continue;
    }

    if (fromCharCodeRegex.test(line)) {
      findings.push({
        ruleId: "OBFUSCATION",
        severity: "HIGH",
        score: RULE_WEIGHTS.OBFUSCATION,
        line: i + 1,
        message: "Obfuscation indicator: String.fromCharCode/fromCodePoint character reconstruction.",
        evidence: originalLines[i].trim().slice(0, 120),
        category: "obfuscation",
        occurrences: 1,
      });
      continue;
    }

    if (multiEscapeRegex.test(line)) {
      findings.push({
        ruleId: "OBFUSCATION",
        severity: "HIGH",
        score: RULE_WEIGHTS.OBFUSCATION,
        line: i + 1,
        message: "Obfuscation indicator: encoded hex or Unicode escape sequence chain.",
        evidence: originalLines[i].trim().slice(0, 120),
        category: "obfuscation",
        occurrences: 1,
      });
      continue;
    }

    if (hexIdentifierRegex.test(line)) {
      findings.push({
        ruleId: "OBFUSCATION",
        severity: "MEDIUM",
        score: RULE_WEIGHTS.OBFUSCATION,
        line: i + 1,
        message: "Obfuscation indicator: hex-mangled identifier pattern (_0x...) detected.",
        evidence: originalLines[i].trim().slice(0, 120),
        category: "obfuscation",
        occurrences: 1,
      });
    }
  }

  return findings;
}

export default { runRule };
