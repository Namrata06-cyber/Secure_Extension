// Checks the JavaScript port against the Python answer key.
//   node --test js/test/parity.test.js
// Regenerate the answer key with:  python tests/make_parity_fixture.py
const test = require("node:test");
const assert = require("node:assert/strict");
const path = require("node:path");

const A = require("../url-analyzer.js");
const cases = require(path.join(__dirname, "..", "..", "tests", "parity_fixture.json"));
const validation = require(path.join(__dirname, "..", "..", "tests", "validation_urls.json"));

test(`all ${cases.length} fixture URLs: every feature and score matches Python`, () => {
  const failures = [];
  for (const c of cases) {
    const r = A.analyzeUrl(c.url);
    for (const k of Object.keys(c.features)) {
      if (r.features[k] !== c.features[k]) failures.push(`${c.url} :: ${k} py=${c.features[k]} js=${r.features[k]}`);
    }
    if (r.score !== c.score) failures.push(`${c.url} :: score py=${c.score} js=${r.score}`);
    if (r.classification !== c.classification) failures.push(`${c.url} :: class py=${c.classification} js=${r.classification}`);
  }
  assert.deepEqual(failures.slice(0, 20), []);
});

test("18 real-world validation URLs reproduce the report scores", () => {
  for (const v of validation) assert.equal(A.analyzeUrl(v.url).score, v.report_score, v.url);
});

test("rule engine passes 15 of 18 validation URLs", () => {
  const passed = validation.filter((v) => (A.analyzeUrl(v.url).classification !== "Safe") === (v.expected === "Phishing"));
  assert.equal(passed.length, 15);
});

test("bad input never throws", () => {
  for (const bad of [null, undefined, "", 42, "http://", "http://x.com:abc/"]) {
    assert.equal(A.analyzeUrl(bad).classification, "Unknown");
  }
});
