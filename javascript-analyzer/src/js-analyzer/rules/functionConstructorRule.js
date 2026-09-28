/**
 * Rule 2: FUNCTION_CONSTRUCTOR
 *
 * Detects the Function constructor (with or without the "new" keyword), which
 * dynamically constructs
 * executable JavaScript from strings at runtime.
 *
 * Assigned heuristic weight: 20 (HIGH).
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
  const originalLines = code.split("\n");
  const maskedLines = maskedCode.split("\n");

  // Matches the Function constructor with or without the "new" keyword
  // (capital F, not the lowercase "function" declaration keyword)
  const fnConstructorRegex = /(?:^|[^\w$.])(?:new\s+)?Function\s*\(/g;

  for (let i = 0; i < maskedLines.length; i++) {
    const maskedLine = maskedLines[i];
    fnConstructorRegex.lastIndex = 0;
    let match;

    while ((match = fnConstructorRegex.exec(maskedLine)) !== null) {
      const rawEvidence = originalLines[i].trim().slice(0, 120);
      findings.push({
        ruleId: "FUNCTION_CONSTRUCTOR",
        severity: "HIGH",
        score: RULE_WEIGHTS.FUNCTION_CONSTRUCTOR,
        line: i + 1,
        message: "Function constructor detected. Dynamically creates executable code from strings.",
        evidence: rawEvidence || match[0].trim(),
        category: "dynamic_execution",
        occurrences: 1,
      });
    }
  }

  return findings;
}

export default { runRule };
