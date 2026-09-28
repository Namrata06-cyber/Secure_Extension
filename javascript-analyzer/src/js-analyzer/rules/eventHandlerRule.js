/**
 * Rule 6: EVENT_HANDLER
 *
 * Detects inline or programmatic event handler bindings:
 *   - onclick, onload, onerror, onmouseover, onfocus, onkeydown, onkeypress, onkeyup
 *   - element.onclick = ...
 *   - element.setAttribute("onclick", ...)
 *
 * Event handlers are common in legitimate web apps; assigned low base score (5, LOW).
 * Suspicion increases in the correlation layer when combined with redirects,
 * dynamic execution, dynamic script loading, or obfuscation.
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

  const propOrInlineRegex =
    /(?:\.\s*|\b)(on(?:click|load|error|mouseover|focus|keydown|keypress|keyup))\s*=(?!=)/i;
  const setAttrRegex =
    /\bsetAttribute\s*\(\s*["'`](on(?:click|load|error|mouseover|focus|keydown|keypress|keyup))["'`]\s*,/i;

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const match = propOrInlineRegex.exec(line) || setAttrRegex.exec(line);

    if (match) {
      const handlerName = match[1].toLowerCase();
      findings.push({
        ruleId: "EVENT_HANDLER",
        severity: "LOW",
        score: RULE_WEIGHTS.EVENT_HANDLER,
        line: i + 1,
        message: `Suspicious or inline event handler (${handlerName}) detected.`,
        evidence: originalLines[i].trim().slice(0, 120),
        category: "event_handler",
        occurrences: 1,
      });
    }
  }

  return findings;
}

export default { runRule };
