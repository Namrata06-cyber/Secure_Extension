/**
 * Rule 4: REDIRECT
 *
 * Detects JavaScript navigation and redirect patterns:
 *   - window.location = ...
 *   - window.location.href = ...
 *   - window.location.replace(...)
 *   - window.location.assign(...)
 *   - location.href = ...
 *   - location.replace(...)
 *   - location.assign(...)
 *
 * Ignores string literals (e.g. `const text = "window.location.href"`) and comments.
 * Redirects are common legitimate behavior; this is a heuristic indicator only.
 * Assigned heuristic weight: 10 (MEDIUM).
 */

import { RULE_WEIGHTS } from "../scoring.js";

function maskCommentsAndStrings(code) {
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
          result += "  ";
          i += 2;
          continue;
        }
        result += code[i] === "\n" ? "\n" : " ";
        i++;
      }
      if (i < len) {
        result += quote;
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
  const maskedCode = maskCommentsAndStrings(code);
  const maskedLines = maskedCode.split("\n");
  const originalLines = code.split("\n");

  // Matches location assignment (excluding == / ===) or location.replace / location.assign
  const redirectAssignRegex =
    /(?:^|[^\w$.])(?:window\s*\.\s*|document\s*\.\s*)?location(?:\s*\.\s*href)?\s*=(?!=)/;
  const redirectMethodRegex =
    /(?:^|[^\w$.])(?:window\s*\.\s*|document\s*\.\s*)?location\s*\.\s*(?:replace|assign)\s*\(/;

  for (let i = 0; i < maskedLines.length; i++) {
    const maskedLine = maskedLines[i];

    if (redirectAssignRegex.test(maskedLine) || redirectMethodRegex.test(maskedLine)) {
      findings.push({
        ruleId: "REDIRECT",
        severity: "MEDIUM",
        score: RULE_WEIGHTS.REDIRECT,
        line: i + 1,
        message: "Suspicious or programmatic redirect pattern detected.",
        evidence: originalLines[i].trim().slice(0, 120),
        category: "redirect",
        occurrences: 1,
      });
    }
  }

  return findings;
}

export default { runRule };
