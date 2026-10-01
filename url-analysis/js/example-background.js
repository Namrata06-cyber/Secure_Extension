/**
 * example-background.js — how the extension team can call the URL module.
 * (Manifest V3 service worker. Not part of the module itself; adapt freely.)
 *
 * manifest.json needs:
 *   "background": { "service_worker": "background.js" },
 *   "permissions": ["webNavigation", "storage"]
 *
 * and background.js starts with:
 *   importScripts("url-analyzer.js");     // defines self.URLAnalyzer
 */

chrome.webNavigation.onBeforeNavigate.addListener((details) => {
  if (details.frameId !== 0) return;                 // top-level page only

  // Stage 1 of the extension: URL analysis runs BEFORE the page loads.
  const result = URLAnalyzer.analyzeUrl(details.url);

  // Hand the result to the fusion step / popup. The JavaScript (DOM) module
  // adds its own score after the page loads — see docs/ARCHITECTURE.md §5.
  chrome.storage.session.set({ [`url:${details.tabId}`]: {
    module: "url-analysis",
    version: URLAnalyzer.version,
    score: result.score,                   // 0–100
    classification: result.classification, // Safe | Suspicious | Dangerous | Unknown
    indicators: result.indicators,         // ["R02", "R10", ...]
    findings: result.findings,             // human-readable sentences for the popup
  }});

  if (result.classification === "Dangerous") {
    chrome.action.setBadgeText({ tabId: details.tabId, text: "!" });
    chrome.action.setBadgeBackgroundColor({ tabId: details.tabId, color: "#c0504d" });
  }
});
