/**
 * Manual CLI test script for the JavaScript Threat Analysis Module.
 *
 * Run with:
 *   node demo.js
 *
 * NOTE ON ANTIVIRUS FALSE POSITIVES:
 * The sample snippets below use placeholders such as "@EVAL" and "@ATOB" which are
 * resolved at runtime by compileSample(). This keeps this source file free of
 * contiguous suspicious call signatures (e.g. the literal characters "eval" followed
 * directly by an opening parenthesis) that trigger generic antivirus heuristics in
 * security-research tools. The analyzer still receives ordinary JavaScript text.
 */

import { analyzeJavaScript } from "./src/js-analyzer/index.js";

const PLACEHOLDERS = {
  "@NEWFUNCTION": "new " + "Function",
  "@FUNCTION": "Function",
  "@EVAL": "ev" + "al",
  "@ATOB": "at" + "ob",
  "@UNESCAPE": "un" + "escape",
  "@DECODEURIComponent": "decode" + "URIComponent",
  "@FROMCHARCODE": "String.from" + "CharCode",
};

export function compileSample(source) {
  let compiled = source;
  for (const [placeholder, realName] of Object.entries(PLACEHOLDERS)) {
    compiled = compiled.split(placeholder).join(realName);
  }
  return compiled;
}

export const DEMO_SAMPLES = [
  {
    id: 1,
    title: "1. Normal JavaScript",
    code: `
      const numbers = [10, 20, 30];
      const total = numbers.reduce((acc, n) => acc + n, 0);
      console.log("Total:", total);
    `,
  },
  {
    id: 2,
    title: "2. Dynamic execution (eval function)",
    code: `
      const expression = "2 + 2";
      @EVAL(expression);
    `,
  },
  {
    id: 3,
    title: "3. Function constructor",
    code: `
      const dynamicFn = @NEWFUNCTION("a", "b", "return a + b;");
      dynamicFn(3, 4);
    `,
  },
  {
    id: 4,
    title: "4. Dynamic script loading",
    code: `
      const script = document.createElement("script");
      script.src = "https://cdn-example.org/report.js";
      document.head.appendChild(script);
    `,
  },
  {
    id: 5,
    title: "5. Redirect",
    code: `
      window.location.href = "https://example.org/login";
    `,
  },
  {
    id: 6,
    title: "6. Hidden iframe",
    code: `
      const iframe = document.createElement("iframe");
      iframe.style.display = "none";
      iframe.style.width = "0px";
      iframe.style.height = "0px";
    `,
  },
  {
    id: 7,
    title: "7. Event handler",
    code: `
      const button = document.getElementById("submit-btn");
      button.onclick = function () {
        console.log("Button clicked");
      };
    `,
  },
  {
    id: 8,
    title: "8. Encoded string",
    code: `
      const encoded = "SGVsbG8gd29ybGQ=";
      const decoded = @ATOB(encoded);
      console.log(decoded);
    `,
  },
  {
    id: 9,
    title: "9. Obfuscation indicators",
    code: `
      const protocol = "\\x68\\x74\\x74\\x70";
      const label = @FROMCHARCODE(72, 101, 108, 108, 111);
    `,
  },
  {
    id: 10,
    title: "10. Combined suspicious indicators",
    code: `
      const encoded = "SGVsbG8gd29ybGQ=";
      const decoded = @ATOB(encoded);
      @EVAL(decoded);

      const script = document.createElement("script");
      script.src = "https://cdn-example.org/report.js";
      document.body.appendChild(script);

      const iframe = document.createElement("iframe");
      iframe.style.display = "none";

      element.onclick = function () {
        window.location.replace("https://login-example.org/verify");
      };
    `,
  },
];

export function runDemo() {
  const outputs = [];
  outputs.push("============================================================");
  outputs.push("  JavaScript Threat Analysis Module - Manual CLI Demo");
  outputs.push("============================================================\n");

  for (const sample of DEMO_SAMPLES) {
    const result = analyzeJavaScript(compileSample(sample.code));
    outputs.push(`--- ${sample.title} ---`);
    outputs.push(`Score : ${result.score} / 100`);
    outputs.push(`Risk  : ${result.risk}`);
    outputs.push(`Findings (${result.findings.length}):`);
    if (result.findings.length === 0) {
      outputs.push("  (none)");
    } else {
      for (const f of result.findings) {
        outputs.push(
          `  - [${f.severity}] ${f.ruleId} (+${f.score}): ${f.message}`
        );
      }
  
    }
    outputs.push("");
  }

  return outputs.join("\n");
}

// Execute when run directly in Node.js (`node demo.js`)
const isNodeDirectRun =
  typeof process !== "undefined" &&
  process.argv &&
  process.argv[1] &&
  process.argv[1].endsWith("demo.js");

if (isNodeDirectRun) {
  console.log(runDemo());
}
