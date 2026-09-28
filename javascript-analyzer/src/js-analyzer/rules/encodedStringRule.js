/**
 * Rule 8: ENCODED_STRING
 *
 * Detects decoding functions and unusually long encoded string literals:
 *   - the atob decoding function
 *   - the decodeURIComponent decoding function
 *   - the unescape decoding function
 *   - Long Base64 strings (e.g. "SGVsbG8gd29ybGQ...")
 *   - Long hexadecimal strings (e.g. "68656c6c6f...")
 *
 * A long encoded string alone produces a moderate heuristic signal (10, MEDIUM).
 * When combined with dynamic execution (e.g. dynamic execution wrapping decoded
 * content), the correlation
 * layer raises an additional HIGH-severity finding.
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

  const decodeFnRegex = /\b(atob|decodeURIComponent|unescape)\s*\(/;
  const base64LiteralRegex =
    /["'`]([A-Za-z0-9+/]{12,}={0,2})["'`]/;
  const hexLiteralRegex =
    /["'`](?:0x)?([0-9a-fA-F]{16,})["'`]/;

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];

    const decodeMatch = decodeFnRegex.exec(line);
    if (decodeMatch) {
      findings.push({
        ruleId: "ENCODED_STRING",
        severity: "MEDIUM",
        score: RULE_WEIGHTS.ENCODED_STRING,
        line: i + 1,
        message: `String decoding function (${decodeMatch[1]}) detected.`,
        evidence: originalLines[i].trim().slice(0, 120),
        category: "encoded_content",
        occurrences: 1,
      });
      continue;
    }

    const hexMatch = hexLiteralRegex.exec(line);
    if (hexMatch) {
      findings.push({
        ruleId: "ENCODED_STRING",
        severity: "MEDIUM",
        score: RULE_WEIGHTS.ENCODED_STRING,
        line: i + 1,
        message: "Long hexadecimal encoded string detected.",
        evidence: originalLines[i].trim().slice(0, 120),
        category: "encoded_content",
        occurrences: 1,
      });
      continue;
    }

    const b64Match = base64LiteralRegex.exec(line);
    if (b64Match) {
      const candidate = b64Match[1];
      const hasPadding = b64Match[0].includes("=");
      const isLongMixed =
        candidate.length >= 20 &&
        /[A-Z]/.test(candidate) &&
        /[a-z]/.test(candidate) &&
        /[0-9+/]/.test(candidate);

      if (hasPadding || isLongMixed) {
        findings.push({
          ruleId: "ENCODED_STRING",
          severity: "MEDIUM",
          score: RULE_WEIGHTS.ENCODED_STRING,
          line: i + 1,
          message: "Long Base64-like encoded string detected.",
          evidence: originalLines[i].trim().slice(0, 120),
          category: "encoded_content",
          occurrences: 1,
        });
      }
    }
  }

  return findings;
}

export default { runRule };
