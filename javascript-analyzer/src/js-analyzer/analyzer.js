import { runRule as evalRule } from "./rules/evalRule.js";
import { runRule as functionConstructorRule } from "./rules/functionConstructorRule.js";
import { runRule as dynamicScriptRule } from "./rules/dynamicScriptRule.js";
import { runRule as redirectRule } from "./rules/redirectRule.js";
import { runRule as iframeRule } from "./rules/iframeRule.js";
import { runRule as eventHandlerRule } from "./rules/eventHandlerRule.js";
import { runRule as obfuscationRule } from "./rules/obfuscationRule.js";
import { runRule as encodedStringRule } from "./rules/encodedStringRule.js";
import { calculateScore, getRiskLevel, RULE_WEIGHTS } from "./scoring.js";

/**
 * Static, rule-based JavaScript Threat Analysis Engine.
 *
 * SECURITY REQUIREMENT:
 * This module performs STATIC ANALYSIS ONLY.
 * Input JavaScript is treated strictly as untrusted text and is NEVER executed
 * (no eval, no new Function, no DOM execution).
 */

const RULE_MODULES = [
  { name: "evalRule", fn: evalRule },
  { name: "functionConstructorRule", fn: functionConstructorRule },
  { name: "dynamicScriptRule", fn: dynamicScriptRule },
  { name: "redirectRule", fn: redirectRule },
  { name: "iframeRule", fn: iframeRule },
  { name: "eventHandlerRule", fn: eventHandlerRule },
  { name: "obfuscationRule", fn: obfuscationRule },
  { name: "encodedStringRule", fn: encodedStringRule },
];

/**
 * Statically analyzes JavaScript source code for suspicious heuristic indicators.
 *
 * @param {string} code - Raw JavaScript source code to analyze
 * @returns {{
 *   score: number,
 *   risk: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL",
 *   findings: Array<{
 *     ruleId: string,
 *     severity: "LOW" | "MEDIUM" | "HIGH",
 *     score: number,
 *     line?: number,
 *     message: string,
 *     evidence?: string,
 *     category?: string,
 *     occurrences?: number
 *   }>
 * }}
 */
export function analyzeJavaScript(code) {
  if (typeof code !== "string" || code.trim().length === 0) {
    return {
      score: 0,
      risk: "LOW",
      findings: [],
    };
  }

  // 1. Run each detection rule independently
  const rawFindings = [];
  for (const mod of RULE_MODULES) {
    try {
      const ruleFindings = mod.fn(code);
      if (Array.isArray(ruleFindings)) {
        rawFindings.push(...ruleFindings);
      }
    } catch {
      // Defensive isolation so a single rule error does not halt analysis
    }
  }

  // 2. Deduplicate and aggregate repeated occurrences of the same rule
  //    so repeated patterns (e.g. 4 identical dynamic-execution calls) record
  //    occurrences: 4 with a controlled score of 20
  const deduplicatedBaseFindings = aggregateFindingsByRule(rawFindings);

  // 3. Run lightweight correlation engine across detected indicators
  const correlationFindings = runCorrelation(deduplicatedBaseFindings, rawFindings);

  // 4. Combine base findings + correlation findings and compute final capped score
  const findings = [...deduplicatedBaseFindings, ...correlationFindings];
  const score = calculateScore(findings);
  const risk = getRiskLevel(score);

  return {
    score,
    risk,
    findings,
  };
}

/**
 * Groups multiple occurrences of the same ruleId into a single controlled finding
 * with an `occurrences` count so repeated patterns do not artificially inflate the score.
 */
function aggregateFindingsByRule(findings) {
  const byRule = new Map();

  for (const f of findings) {
    if (!byRule.has(f.ruleId)) {
      byRule.set(f.ruleId, {
        ruleId: f.ruleId,
        severity: f.severity,
        score: RULE_WEIGHTS[f.ruleId] ?? f.score ?? 0,
        line: f.line,
        message: f.message,
        evidence: f.evidence,
        category: f.category,
        occurrences: f.occurrences ?? 1,
      });
    } else {
      const existing = byRule.get(f.ruleId);
      existing.occurrences += f.occurrences ?? 1;
    }
  }

  return Array.from(byRule.values());
}

/**
 * Lightweight correlation engine.
 * Evaluates combinations of base indicators and emits explainable correlation findings.
 */
function runCorrelation(baseFindings, rawFindings) {
  const correlations = [];
  const ruleIds = new Set(baseFindings.map((f) => f.ruleId));

  // 1. dynamic execution + Base64 / encoded string / obfuscation
  if (
    ruleIds.has("EVAL_USAGE") &&
    (ruleIds.has("ENCODED_STRING") || ruleIds.has("OBFUSCATION"))
  ) {
    correlations.push({
      ruleId: "ENCODED_DYNAMIC_EXECUTION",
      severity: "HIGH",
      score: RULE_WEIGHTS.ENCODED_DYNAMIC_EXECUTION,
      message: "Encoded content is combined with dynamic JavaScript execution.",
      evidence: "dynamic execution + encoded/obfuscated content",
      category: "correlation",
      occurrences: 1,
    });
  }

  // 2. Function() + encoded string / obfuscation
  if (
    ruleIds.has("FUNCTION_CONSTRUCTOR") &&
    (ruleIds.has("ENCODED_STRING") || ruleIds.has("OBFUSCATION"))
  ) {
    correlations.push({
      ruleId: "ENCODED_FUNCTION_CONSTRUCTOR",
      severity: "HIGH",
      score: RULE_WEIGHTS.ENCODED_FUNCTION_CONSTRUCTOR,
      message: "Function constructor is combined with encoded or obfuscated strings.",
      evidence: "Function constructor + encoded/obfuscated content",
      category: "correlation",
      occurrences: 1,
    });
  }

  // 3. Dynamic script + remote or encoded source
  const hasRemoteDynamicScript = rawFindings.some(
    (f) => f.ruleId === "DYNAMIC_SCRIPT" && f.remoteSource === true
  );
  if (
    ruleIds.has("DYNAMIC_SCRIPT") &&
    (hasRemoteDynamicScript || ruleIds.has("ENCODED_STRING") || ruleIds.has("OBFUSCATION"))
  ) {
    correlations.push({
      ruleId: "REMOTE_DYNAMIC_SCRIPT",
      severity: "HIGH",
      score: RULE_WEIGHTS.REMOTE_DYNAMIC_SCRIPT,
      message: "Dynamic script creation is combined with a remote or encoded source.",
      evidence: "createElement('script') + remote/encoded src",
      category: "correlation",
      occurrences: 1,
    });
  }

  // 4. Hidden iframe + dynamic script
  if (ruleIds.has("HIDDEN_IFRAME") && ruleIds.has("DYNAMIC_SCRIPT")) {
    correlations.push({
      ruleId: "DYNAMIC_HIDDEN_IFRAME",
      severity: "HIGH",
      score: RULE_WEIGHTS.DYNAMIC_HIDDEN_IFRAME,
      message: "Hidden iframe is combined with dynamic script loading.",
      evidence: "hidden iframe + createElement('script')",
      category: "correlation",
      occurrences: 1,
    });
  }

  // 5. Event handler + redirect
  if (ruleIds.has("EVENT_HANDLER") && ruleIds.has("REDIRECT")) {
    correlations.push({
      ruleId: "EVENT_REDIRECT",
      severity: "MEDIUM",
      score: RULE_WEIGHTS.EVENT_REDIRECT,
      message: "Event handler is combined with a redirect behavior.",
      evidence: "event handler + location redirect",
      category: "correlation",
      occurrences: 1,
    });
  }

  // 6. Event handler + dynamic execution / dynamic script / obfuscation
  if (
    ruleIds.has("EVENT_HANDLER") &&
    (ruleIds.has("EVAL_USAGE") ||
      ruleIds.has("FUNCTION_CONSTRUCTOR") ||
      ruleIds.has("DYNAMIC_SCRIPT") ||
      ruleIds.has("OBFUSCATION"))
  ) {
    correlations.push({
      ruleId: "EVENT_SUSPICIOUS_EXECUTION",
      severity: "HIGH",
      score: RULE_WEIGHTS.EVENT_SUSPICIOUS_EXECUTION,
      message:
        "Event handler is combined with dynamic execution, dynamic script loading, or obfuscation.",
      evidence: "event handler + dynamic execution/script/obfuscation",
      category: "correlation",
      occurrences: 1,
    });
  }

  // 7. Obfuscation + redirect
  if (ruleIds.has("OBFUSCATION") && ruleIds.has("REDIRECT")) {
    correlations.push({
      ruleId: "OBFUSCATION_REDIRECT",
      severity: "HIGH",
      score: RULE_WEIGHTS.OBFUSCATION_REDIRECT,
      message: "Obfuscated JavaScript is combined with a redirect behavior.",
      evidence: "obfuscation + location redirect",
      category: "correlation",
      occurrences: 1,
    });
  }

  return correlations;
}

export default { analyzeJavaScript };
