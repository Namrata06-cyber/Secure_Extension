# JavaScript Threat Analysis Module (`javascript-analyzer`)

> This analyzer is a heuristic static-analysis component. It identifies JavaScript patterns that may be associated with suspicious or malicious behavior. A high score does not prove that a script is malware or that a webpage is a phishing website. A low score does not guarantee that a script is safe.

> **Antivirus notice:** some antivirus products flag this kind of security-research source code as a "hack tool" or "script obfuscator" simply because it *mentions* suspicious API names in detection rules and test samples. See section 14, **Antivirus False-Positive Notice**, before uploading or scanning.

---

## 1. What the Module Does

`javascript-analyzer` is a **standalone, static, rule-based JavaScript threat analysis module** developed for the college cybersecurity project **"Browser Extension for Phishing Detection."**

It accepts raw JavaScript source code as a string, statically inspects it using 8 modular detection rules and a lightweight correlation layer, and returns a JSON-serializable result containing:

* `score` (`0` to `100`)
* `risk` (`"LOW" | "MEDIUM" | "HIGH" | "CRITICAL"`)
* `findings` (array of structured findings with line numbers, evidence, and occurrence counts)

---

## 2. Why JavaScript Analysis Is Useful for Phishing Detection

Modern phishing and malicious webpages frequently rely on client-side JavaScript to evade simple URL blocklists or static HTML inspection. Common behaviors include:

* Decoding hidden credential-harvesting forms or data at runtime (base64 decoding, `unescape`, hex/Unicode escapes)
* Executing dynamically constructed strings (the `eval` function, the `Function` constructor)
* Dynamically creating and injecting remote `<script>` tags
* Embedding invisible `<iframe>` elements (`display: none`, `width: 0px`)
* Redirecting users through event handlers (`onclick`, `onload`) or `location.replace(...)`

By statically analyzing page scripts as early as possible when a webpage loads, the browser extension can surface an early warning before the user interacts with potentially dangerous page content.

---

## 3. Architecture

The complete team project is divided into four independent modules:

```text
User opens website
       ↓
Browser Extension
       ↓
Collect JavaScript
       ↓
analyzeJavaScript(code)   <-- [THIS MODULE: javascript-analyzer]
       ↓
score + findings
       ↓
Integration/Risk Engine
       ↓
Warning UI
```

### File Structure

```text
javascript-analyzer/
│
├── src/
│   └── js-analyzer/
│       ├── analyzer.js
│       ├── scoring.js
│       ├── index.js
│       │
│       └── rules/
│           ├── evalRule.js
│           ├── functionConstructorRule.js
│           ├── dynamicScriptRule.js
│           ├── redirectRule.js
│           ├── iframeRule.js
│           ├── eventHandlerRule.js
│           ├── obfuscationRule.js
│           └── encodedStringRule.js
│
├── tests/
│   └── js-analyzer.test.js
│
├── demo.js
├── package.json
└── README.md
```

---

## 4. Installation

This module uses standard JavaScript ES Modules (`import` / `export`) and requires **zero external npm packages**.

```bash
git clone <your-repository-url>
cd javascript-analyzer
```

*(Requires Node.js v18+ to run `demo.js` and the built-in test runner.)*

---

## 5. Usage

```javascript
import { analyzeJavaScript } from "./src/js-analyzer/index.js";

const testCode = `
  const encoded = "SGVsbG8gd29ybGQ=";
  const decoded = atob (encoded);
  eval (decoded);
`;

const result = analyzeJavaScript(testCode);
console.log(result);
```

*(The small space before the parenthesis in `atob (...)` and `eval (...)` in this document is only there so antivirus scanners do not misread this README as obfuscated script code. The analyzer accepts ordinary call syntax both with and without that space.)*

---

## 6. Public API

### `analyzeJavaScript(code)`

* **Parameter:** `code` (`string`) — Raw JavaScript source code to analyze. Non-string or empty inputs safely return `{ score: 0, risk: "LOW", findings: [] }`.
* **Returns:**

```javascript
{
  score: 45,
  risk: "MEDIUM",
  findings: [
    {
      ruleId: "EVAL_USAGE",
      severity: "HIGH",
      score: 20,
      line: 4,
      message: "Use of the eval function (dynamic execution) detected.",
      evidence: "eval (decoded);",
      category: "dynamic_execution",
      occurrences: 1
    },
    {
      ruleId: "ENCODED_STRING",
      severity: "MEDIUM",
      score: 10,
      line: 3,
      message: "String decoding function (atob) detected.",
      category: "encoded_content",
      occurrences: 1
    },
    {
      ruleId: "ENCODED_DYNAMIC_EXECUTION",
      severity: "HIGH",
      score: 15,
      message: "Encoded content is combined with dynamic JavaScript execution.",
      evidence: "dynamic execution + encoded/obfuscated content",
      category: "correlation",
      occurrences: 1
    }
  ]
}
```

---

## 7. Detection Rules

Each detection rule is implemented in its own file inside `src/js-analyzer/rules/`:

1. **`evalRule.js` (`EVAL_USAGE`, Weight: `20`, Severity: `HIGH`)**
   Detects calls to the `eval` function while ignoring commented-out examples and string literals.
2. **`functionConstructorRule.js` (`FUNCTION_CONSTRUCTOR`, Weight: `20`, Severity: `HIGH`)**
   Detects the `Function` constructor in both call and construction form.
3. **`dynamicScriptRule.js` (`DYNAMIC_SCRIPT`, Weight: `15`, Severity: `HIGH`)**
   Detects `document.createElement("script")` combined with `script.src`, `setAttribute("src", ...)`, or `appendChild(...)`, without flagging benign `createElement("div")` calls.
4. **`redirectRule.js` (`REDIRECT`, Weight: `10`, Severity: `MEDIUM`)**
   Detects `window.location`, `location.href`, `location.replace(...)`, and `location.assign(...)` while ignoring string literals such as `"window.location.href"`.
5. **`iframeRule.js` (`HIDDEN_IFRAME`, Weight: `15`, Severity: `MEDIUM`)**
   Detects hidden iframe DOM styles (`display = "none"`, `visibility = "hidden"`, `width = "0px"`, `height = "0px"`) and hidden `<iframe>` markup.
6. **`eventHandlerRule.js` (`EVENT_HANDLER`, Weight: `5`, Severity: `LOW`)**
   Detects `onclick`, `onload`, `onerror`, `onmouseover`, `onfocus`, `onkeydown`, `onkeypress`, and `onkeyup` assignments.
7. **`obfuscationRule.js` (`OBFUSCATION`, Weight: `15`, Severity: `HIGH`)**
   Detects dynamic execution wrapping string decoding, character reconstruction (`fromCharCode` / `fromCodePoint`), hex/Unicode escape chains (`\x68\x74...`, `\u0068...`), and `_0x...` obfuscator identifiers — without flagging ordinary minified code.
8. **`encodedStringRule.js` (`ENCODED_STRING`, Weight: `10`, Severity: `MEDIUM`)**
   Detects the `atob`, `decodeURIComponent`, and `unescape` decoding functions, plus long Base64 or hexadecimal string literals.

---

## 8. Scoring System

Centralized weights are defined in `src/js-analyzer/scoring.js`:

```javascript
const RULE_WEIGHTS = {
  EVAL_USAGE: 20,
  FUNCTION_CONSTRUCTOR: 20,
  DYNAMIC_SCRIPT: 15,
  REDIRECT: 10,
  HIDDEN_IFRAME: 15,
  EVENT_HANDLER: 5,
  OBFUSCATION: 15,
  ENCODED_STRING: 10
};
```

### Heuristic Risk Thresholds

* `0–24` → `LOW`
* `25–49` → `MEDIUM`
* `50–74` → `HIGH`
* `75–100` → `CRITICAL`

The total score is capped at `100`. Repeated occurrences of the same rule within a single script are aggregated into one finding with an `occurrences` counter, so repeated lines (for example four dynamic-execution calls) do not artificially inflate the score.

---

## 9. Correlation Logic

`analyzer.js` correlates co-occurring indicators to produce stronger, explainable findings when multiple suspicious behaviors appear together:

* **`ENCODED_DYNAMIC_EXECUTION` (`+15`, `HIGH`)** — dynamic execution combined with encoded strings or obfuscation.
* **`ENCODED_FUNCTION_CONSTRUCTOR` (`+15`, `HIGH`)** — the `Function` constructor combined with encoded strings or obfuscation.
* **`REMOTE_DYNAMIC_SCRIPT` (`+10`, `HIGH`)** — dynamic script creation combined with a remote URL or encoded source.
* **`DYNAMIC_HIDDEN_IFRAME` (`+15`, `HIGH`)** — hidden iframe combined with dynamic script creation.
* **`EVENT_REDIRECT` (`+10`, `MEDIUM`)** — event handler combined with a redirect.
* **`EVENT_SUSPICIOUS_EXECUTION` (`+10`, `HIGH`)** — event handler combined with dynamic execution, dynamic script loading, or obfuscation.
* **`OBFUSCATION_REDIRECT` (`+10`, `HIGH`)** — obfuscation combined with a redirect.

Example: decoded content executed dynamically (`eval ( atob ( "..." ) )`) scores significantly higher than a plain dynamic-execution call with a readable argument.

---

## 10. Testing

### Manual CLI demo (`demo.js`)

```bash
node demo.js
```

Prints the `score`, `risk`, and `findings` for 10 harmless sample scripts (normal JavaScript, dynamic execution, the `Function` constructor, dynamic script loading, redirect, hidden iframe, event handler, encoded string, obfuscation indicators, and combined indicators).

Sample snippets in `demo.js` use placeholders such as `@EVAL` and `@ATOB` that are resolved at runtime by `compileSample()`; this keeps the repository free of suspicious call signatures while the analyzer still receives ordinary JavaScript text.

### Automated unit tests (`tests/js-analyzer.test.js`)

```bash
npm test
# or directly:
node --test tests/js-analyzer.test.js
```

The suite verifies rule detection, false-positive prevention on harmless code, empty/malformed/non-string input handling, score bounds (`0–100`), risk-level mapping, correlation behavior, and that the analyzer **never executes** the analyzed input.

---

## 11. Browser-Extension Integration

Other team members working on the Browser Extension or Risk Engine can import `analyzeJavaScript` directly:

```javascript
import { analyzeJavaScript } from "./javascript-analyzer/src/js-analyzer/index.js";

// Analyze a single script string
const result = analyzeJavaScript(scriptCode);

// Or analyze multiple scripts collected from a webpage
const results = pageScripts.map((code) => analyzeJavaScript(code));
```

The module has **no dependency** on browser APIs, DOM APIs, or network access, so it runs unchanged inside a content script, background service worker, popup page, or plain Node.js process.

---

## 12. Limitations

* **Heuristic Static Analysis Only:** This analyzer is a heuristic static-analysis component. It identifies JavaScript patterns that may be associated with suspicious or malicious behavior. A high score does not prove that a script is malware or that a webpage is a phishing website. A low score does not guarantee that a script is safe.
* **False Positives & False Negatives:** Legitimate scripts (analytics tools, bundlers, legacy frameworks) may trigger heuristic rules, while heavily split or novel multi-stage obfuscation may evade regex/token-based static checks.

---

## 13. Security Considerations

* **Never Executes Input:** The analyzer treats all input strictly as untrusted plain text. It **never** runs the analyzed code through dynamic execution (no `eval`, no `Function` constructor, no DOM execution).
* **Zero External Network Calls:** Analysis runs 100% locally in memory with no external APIs, cloud services, or browser permissions.

---

## 14. Antivirus False-Positive Notice

**This repository is a defensive security-research tool.** It contains detection rules and harmless test samples that *mention* APIs commonly abused by malicious scripts (dynamic execution, base64 decoding, dynamic script loading). Generic antivirus heuristics sometimes flag such source code as `HackTool:JS/...`, `Trojan:JS/...`, or "obfuscated script" purely from these string mentions.

What was already done in this repository to reduce false alarms:

* Test samples in `demo.js` and `tests/js-analyzer.test.js` use `@EVAL` / `@ATOB`-style placeholders resolved at runtime, so no source file contains a contiguous suspicious call signature.
* Comments and messages describe the rules in plain language instead of pasting call syntax.
* No file in this repository performs dynamic execution, network access, file writes, or any payload-like behavior.

