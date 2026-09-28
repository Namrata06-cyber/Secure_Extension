/**
 * Rule 3: DYNAMIC_SCRIPT
 *
 * Detects dynamic script element creation and injection patterns such as:
 *   - document.createElement("script")
 *   - script.src = ... / setAttribute("src", ...)
 *   - document.head.appendChild(script) / document.body.appendChild(script)
 *
 * Does NOT flag non-script createElement() calls (e.g. "div", "span", "iframe").
 * Assigned heuristic weight: 15 (HIGH).
 */

import { RULE_WEIGHTS } from "../scoring.js";

/**
 * Strips single-line and multi-line comments while keeping string literals intact
 * (so URLs like "https://..." are not broken by `//` comment splitting).
 */
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

  const createScriptRegex = /\bcreateElement\s*\(\s*["'`]script["'`]\s*\)/i;
  const srcAssignRegex = /(?:\.src\s*=|\bsetAttribute\s*\(\s*["'`]src["'`]\s*,)/i;
  const domAppendRegex = /\b(?:appendChild|append|insertBefore)\s*\(/i;
  const remoteUrlRegex = /["'`](?:https?:)?\/\/[^"'`\s]+["'`]/i;

  const hasScriptCreationInFile = createScriptRegex.test(cleanedCode);
  const hasSrcAssignInFile = srcAssignRegex.test(cleanedCode);
  const hasDomAppendInFile = domAppendRegex.test(cleanedCode);
  const hasRemoteSrcInFile = hasSrcAssignInFile && remoteUrlRegex.test(cleanedCode);

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];

    if (createScriptRegex.test(line)) {
      const details = [];
      if (hasSrcAssignInFile) details.push("source assignment");
      if (hasDomAppendInFile) details.push("DOM insertion");
      if (hasRemoteSrcInFile) details.push("remote URL");

      const contextSuffix =
        details.length > 0 ? ` combined with ${details.join(" and ")}` : "";

      findings.push({
        ruleId: "DYNAMIC_SCRIPT",
        severity: "HIGH",
        score: RULE_WEIGHTS.DYNAMIC_SCRIPT,
        line: i + 1,
        message: `Dynamic script creation detected${contextSuffix}.`,
        evidence: originalLines[i].trim().slice(0, 120),
        category: "script_loading",
        occurrences: 1,
        remoteSource: hasRemoteSrcInFile,
      });
    }
  }

  return findings;
}

export default { runRule };
