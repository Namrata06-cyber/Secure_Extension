/**
 * Scoring engine for the JavaScript Threat Analysis Module.
 *
 * Defines centralized configurable weights, calculates aggregate heuristic scores,
 * enforces a maximum score cap of 100, and maps scores to project-defined risk levels.
 *
 * NOTE: Thresholds and weights are project-defined heuristic indicators for an
 * early-warning browser extension, NOT scientifically validated malware probabilities.
 */

export const MAX_SCORE = 100;

export const RULE_WEIGHTS = Object.freeze({
  // Base Detection Rules
  EVAL_USAGE: 20,
  FUNCTION_CONSTRUCTOR: 20,
  DYNAMIC_SCRIPT: 15,
  REDIRECT: 10,
  HIDDEN_IFRAME: 15,
  EVENT_HANDLER: 5,
  OBFUSCATION: 15,
  ENCODED_STRING: 10,

  // Correlation Rules
  ENCODED_DYNAMIC_EXECUTION: 15,
  ENCODED_FUNCTION_CONSTRUCTOR: 15,
  REMOTE_DYNAMIC_SCRIPT: 10,
  DYNAMIC_HIDDEN_IFRAME: 15,
  EVENT_REDIRECT: 10,
  EVENT_SUSPICIOUS_EXECUTION: 10,
  OBFUSCATION_REDIRECT: 10,
});

export const RISK_LEVELS = Object.freeze({
  LOW: "LOW",           // 0 - 24
  MEDIUM: "MEDIUM",     // 25 - 49
  HIGH: "HIGH",         // 50 - 74
  CRITICAL: "CRITICAL", // 75 - 100
});

/**
 * Maps a numeric heuristic score (0-100) to a project-defined risk level.
 *
 * @param {number} score - Heuristic risk score (0-100)
 * @returns {"LOW" | "MEDIUM" | "HIGH" | "CRITICAL"}
 */
export function getRiskLevel(score) {
  const normalized = Number.isFinite(score) ? score : 0;
  if (normalized >= 75) return RISK_LEVELS.CRITICAL;
  if (normalized >= 50) return RISK_LEVELS.HIGH;
  if (normalized >= 25) return RISK_LEVELS.MEDIUM;
  return RISK_LEVELS.LOW;
}

/**
 * Calculates the total heuristic score from deduplicated findings,
 * capped strictly between 0 and MAX_SCORE (100).
 *
 * @param {Array<{ruleId: string, score?: number}>} findings
 * @returns {number} Final capped score (0 - 100)
 */
export function calculateScore(findings) {
  if (!Array.isArray(findings)) return 0;

  let total = 0;
  for (const finding of findings) {
    const weight =
      typeof finding.score === "number"
        ? finding.score
        : RULE_WEIGHTS[finding.ruleId] ?? 0;
    total += weight;
  }

  return Math.min(MAX_SCORE, Math.max(0, total));
}

export default {
  MAX_SCORE,
  RULE_WEIGHTS,
  RISK_LEVELS,
  getRiskLevel,
  calculateScore,
};
