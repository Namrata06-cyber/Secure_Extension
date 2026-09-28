/**
 * Public API for the JavaScript Threat Analysis Module.
 *
 * Example:
 *   import { analyzeJavaScript } from "./js-analyzer/index.js";
 *   const result = analyzeJavaScript(scriptCode);
 *   console.log(result);
 */

export { analyzeJavaScript } from "./analyzer.js";
export {
  RULE_WEIGHTS,
  RISK_LEVELS,
  MAX_SCORE,
  getRiskLevel,
  calculateScore,
} from "./scoring.js";

