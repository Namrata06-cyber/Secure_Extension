/**
 * Rule 1: EVAL_USAGE
 *
 * Detects direct or indirect usage of the eval function, which dynamically
 * executes JavaScript represented as a string.
 *
 * Note: use of the eval function is not proof of malicious behavior, as some legacy or template
 * libraries use it legitimately. Assigned heuristic weight: 20 (HIGH).
 */

import { RULE_WEIGHTS } from "../scoring.js";

/**
 * Masks comments and string literal contents with spaces while preserving line breaks
 * so regex checks only inspect executable code tokens.
 */
function maskCommentsAndStrings(code) {
  let result = "";
  let i = 0;
  const len = code.length;

  while (i < len) {
    const ch = code[i];
    const next = code[i + 1];

    // Single-line comment
    if (ch === "/" && next === "/") {
      while (i < len && code[i] !== "\n") {
        result += " ";
        i++;
      }
      continue;
    }

    // Multi-line comment
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

    // String literals (", ', `)
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
  const originalLines = code.split("\n");
  const maskedLines = maskedCode.split("\n");

  // Matches standalone or window-qualified dynamic execution calls
  const evalRegex = /(?:^|[^\w$])(?:window\s*\.\s*)?eval\s*\(/g;

  for (let i = 0; i < maskedLines.length; i++) {
    const maskedLine = maskedLines[i];
    evalRegex.lastIndex = 0;
    let match;

    while ((match = evalRegex.exec(maskedLine)) !== null) {
      const rawEvidence = originalLines[i].trim().slice(0, 120);
      findings.push({
        ruleId: "EVAL_USAGE",
        severity: "HIGH",
        score: RULE_WEIGHTS.EVAL_USAGE,
        line: i + 1,
        message: "Use of the eval function (dynamic execution) detected.",
        evidence: rawEvidence || "dynamic execution call",
        category: "dynamic_execution",
        occurrences: 1,
      });
    }
  }

  return findings;
}

export default { runRule };
