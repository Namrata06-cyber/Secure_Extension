/**
 * Rule 5: HIDDEN_IFRAME
 *
 * Detects hidden iframe patterns in HTML strings or JavaScript DOM manipulation:
 *   - <iframe hidden>
 *   - <iframe style="display:none"> / visibility:hidden / width:0 / height:0
 *   - iframe.style.display = "none"
 *   - iframe.style.visibility = "hidden"
 *   - iframe.style.width = "0px" / "0"
 *   - iframe.style.height = "0px" / "0"
 *
 * Normal visible iframes are NOT flagged.
 * Assigned heuristic weight: 15 (MEDIUM).
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

  const hasIframeContext = /\biframe\b/i.test(cleanedCode);

  // 1. HTML <iframe ... hidden ...> or <iframe ... style="display:none|visibility:hidden|width:0|height:0">
  const htmlHiddenIframeRegex =
    /<iframe\b[^>]*(?:\bhidden\b|style\s*=\s*["'][^"']*(?:display\s*:\s*none|visibility\s*:\s*hidden|(?:width|height)\s*:\s*0(?:px)?)[^"']*["'])[^>]*>/i;

  // 2. JS style properties hiding an iframe or element in iframe context
  const jsHiddenStyleRegex =
    /\.style\s*\.\s*(?:display\s*=\s*["'`]\s*none\s*["'`]|visibility\s*=\s*["'`]\s*hidden\s*["'`]|(?:width|height)\s*=\s*["'`]\s*0(?:px)?\s*["'`])/i;

  const jsDirectIframeStyleRegex =
    /\biframe\w*\.style\s*\.\s*(?:display|visibility|width|height)\s*=/i;

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];

    if (htmlHiddenIframeRegex.test(line)) {
      findings.push({
        ruleId: "HIDDEN_IFRAME",
        severity: "MEDIUM",
        score: RULE_WEIGHTS.HIDDEN_IFRAME,
        line: i + 1,
        message: "Hidden iframe markup detected (hidden attribute or hidden inline style).",
        evidence: originalLines[i].trim().slice(0, 120),
        category: "hidden_content",
        occurrences: 1,
      });
      continue;
    }

    if (
      jsHiddenStyleRegex.test(line) &&
      (hasIframeContext || jsDirectIframeStyleRegex.test(line))
    ) {
      findings.push({
        ruleId: "HIDDEN_IFRAME",
        severity: "MEDIUM",
        score: RULE_WEIGHTS.HIDDEN_IFRAME,
        line: i + 1,
        message: "Hidden iframe DOM style detected (display:none, visibility:hidden, or 0px dimensions).",
        evidence: originalLines[i].trim().slice(0, 120),
        category: "hidden_content",
        occurrences: 1,
      });
    }
  }

  return findings;
}

export default { runRule };
