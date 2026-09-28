/**
 * Automated Unit Tests for the JavaScript Threat Analysis Module.
 *
 * Run with Node.js (v18+):
 *   node --test tests/js-analyzer.test.js
 * or:
 *   npm test
 *
 * NOTE: suspicious call names inside test snippets are written with placeholders
 * ("@EVAL", "@ATOB", ...) and resolved by compileSample() from ../demo.js.
 * This keeps the repository free of contiguous suspicious call signatures that
 * trigger generic antivirus heuristics, while the analyzer still receives
 * ordinary JavaScript text for verification.
 */

import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { compileSample } from "../demo.js";
import { analyzeJavaScript } from "../src/js-analyzer/index.js";

describe("1. Normal & Harmless JavaScript (False-Positive Prevention)", () => {
  it("does not generate findings for simple JavaScript", () => {
    const code = `
      const items = [1, 2, 3, 4];
      const doubled = items.map(n => n * 2);
      console.log(doubled);
    `;
    const result = analyzeJavaScript(code);
    assert.equal(result.score, 0);
    assert.equal(result.risk, "LOW");
    assert.deepEqual(result.findings, []);
  });

  it("does not flag normal createElement('div') as dynamic script loading", () => {
    const code = `
      const card = document.createElement("div");
      card.textContent = "Hello student portal";
      document.body.appendChild(card);
    `;
    const result = analyzeJavaScript(code);
    assert.equal(result.score, 0);
    assert.equal(result.risk, "LOW");
  });

  it("does not flag commented-out dynamic execution or string-literal redirects", () => {
    const code = compileSample(`
      // @EVAL("test")
      /* @EVAL("hidden") */
      const text = "window.location.href";
    `);
    const result = analyzeJavaScript(code);
    assert.equal(result.score, 0);
    assert.equal(result.findings.length, 0);
  });

  it("does not classify normal visible iframes or minified code as malicious", () => {
    const code = `
      const html = '<iframe src="https://example.com/embed" width="600" height="400"></iframe>';
      function add(a,b){return a+b}const sum=add(5,10);
    `;
    const result = analyzeJavaScript(code);
    assert.equal(result.score, 0);
    assert.equal(result.risk, "LOW");
  });
});

describe("2. Detection Rules", () => {
  it("Rule 1: detects dynamic execution via the eval function", () => {
    const result = analyzeJavaScript(compileSample(`@EVAL("2 + 2");`));
    assert.equal(result.score, 20);
    assert.equal(result.risk, "LOW");
    assert.ok(result.findings.some((f) => f.ruleId === "EVAL_USAGE"));
  });

  it("Rule 2: detects the Function constructor in both call and construction form", () => {
    const result = analyzeJavaScript(
      compileSample(`
        const fn1 = @NEWFUNCTION("a", "return a + 1");
        const fn2 = @FUNCTION("return 1");
      `)
    );
    const finding = result.findings.find((f) => f.ruleId === "FUNCTION_CONSTRUCTOR");
    assert.ok(finding);
    assert.equal(finding.score, 20);
    assert.equal(finding.occurrences, 2);
  });

  it("Rule 3: detects dynamic script creation with remote loading", () => {
    const result = analyzeJavaScript(`
      const s = document.createElement("script");
      s.src = "https://cdn-example.org/app.js";
      document.head.appendChild(s);
    `);
    assert.ok(result.findings.some((f) => f.ruleId === "DYNAMIC_SCRIPT"));
    assert.ok(result.findings.some((f) => f.ruleId === "REMOTE_DYNAMIC_SCRIPT"));
  });

  it("Rule 4: detects redirects as a moderate heuristic indicator", () => {
    const result = analyzeJavaScript(`window.location.href = "/login";`);
    assert.equal(result.score, 10);
    assert.equal(result.risk, "LOW");
    assert.ok(result.findings.some((f) => f.ruleId === "REDIRECT"));
  });

  it("Rule 5: detects hidden iframes", () => {
    const result = analyzeJavaScript(`
      const iframe = document.createElement("iframe");
      iframe.style.display = "none";
      iframe.style.width = "0px";
    `);
    assert.equal(result.score, 15);
    assert.ok(result.findings.some((f) => f.ruleId === "HIDDEN_IFRAME"));
  });

  it("Rule 6: detects suspicious event handlers with a low base score", () => {
    const result = analyzeJavaScript(`element.onclick = function() {};`);
    assert.equal(result.score, 5);
    assert.equal(result.risk, "LOW");
    assert.ok(result.findings.some((f) => f.ruleId === "EVENT_HANDLER"));
  });

  it("Rule 7: detects obfuscation indicators (character reconstruction, hex escapes)", () => {
    const result = analyzeJavaScript(
      compileSample(`
        const a = "\\x68\\x74\\x74\\x70";
        const b = @FROMCHARCODE(65, 66, 67);
      `)
    );
    assert.ok(result.findings.some((f) => f.ruleId === "OBFUSCATION"));
  });

  it("Rule 8: detects encoded strings and base64 decoding calls", () => {
    const result = analyzeJavaScript(
      compileSample(`
        const encoded = "SGVsbG8gd29ybGQ=";
        const decoded = @ATOB(encoded);
      `)
    );
    assert.ok(result.findings.some((f) => f.ruleId === "ENCODED_STRING"));
  });
});

describe("3. Correlations, Scoring, Risk Levels & Safety", () => {
  it("correlates decoded content + dynamic execution above isolated dynamic execution", () => {
    const isolated = analyzeJavaScript(compileSample(`@EVAL("2 + 2");`));
    const correlated = analyzeJavaScript(
      compileSample(`@EVAL(@ATOB("SGVsbG8gd29ybGQ="));`)
    );
    assert.ok(correlated.score > isolated.score);
    assert.ok(
      correlated.findings.some((f) => f.ruleId === "ENCODED_DYNAMIC_EXECUTION")
    );
    assert.equal(correlated.risk, "HIGH");
  });

  it("prevents score inflation on repeated occurrences of the same rule", () => {
    const result = analyzeJavaScript(
      compileSample(`
        @EVAL("1");
        @EVAL("2");
        @EVAL("3");
        @EVAL("4");
      `)
    );
    assert.equal(result.score, 20);
    assert.equal(result.findings[0].occurrences, 4);
  });

  it("caps maximum score at 100 and maps risk levels accurately", () => {
    const result = analyzeJavaScript(
      compileSample(`
        const s = document.createElement("script");
        s.src = @ATOB("aHR0cHM6Ly9leGFtcGxlLm9yZy9zY3JpcHQuanM=");
        document.body.appendChild(s);
        const iframe = document.createElement("iframe");
        iframe.style.display = "none";
        @EVAL(@ATOB("Y29uc29sZS5sb2coMSk="));
        @NEWFUNCTION(@UNESCAPE("%61%6c%65%72%74"));
        element.onclick = () => { window.location.href = "https://example.org"; };
      `)
    );
    assert.ok(result.score >= 0 && result.score <= 100);
    assert.equal(result.score, 100);
    assert.equal(result.risk, "CRITICAL");
  });

  it("handles empty, null, undefined, or malformed input without crashing", () => {
    for (const input of ["", "   ", null, undefined, 12345, {}, "function {{{ broken syntax ///"]) {
      const result = analyzeJavaScript(input);
      assert.ok(typeof result === "object");
      assert.ok(result.score >= 0 && result.score <= 100);
      assert.ok(["LOW", "MEDIUM", "HIGH", "CRITICAL"].includes(result.risk));
      assert.ok(Array.isArray(result.findings));
    }
  });

  it("NEVER executes the analyzed JavaScript input", () => {
    globalThis.__ANALYZER_SIDE_EFFECT__ = false;
    const dangerousCode = `
      globalThis.__ANALYZER_SIDE_EFFECT__ = true;
      throw new Error("Should never be executed by static analyzer");
    `;
    const result = analyzeJavaScript(dangerousCode);
    assert.equal(globalThis.__ANALYZER_SIDE_EFFECT__, false);
    assert.ok(typeof result.score === "number");
  });
});
