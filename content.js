// content.js

console.log("Content script loaded");


// Listen for messages from the background service worker
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  console.log("Content script received:", message);

  if (message.type === "START_EXTRACTION") {
    try {
      const data = extractPageData();

      sendResponse({
        success: true,
        data
      });
    } catch (error) {
      sendResponse({
        success: false,
        error: error.message
      });
    }
  }

  return true;
});


// Extract useful information from the current page
function extractPageData() {
  const title = document.title;

  const url = window.location.href;

  const headings = Array.from(
    document.querySelectorAll("h1, h2, h3")
  ).map((element) => element.innerText.trim())
   .filter(Boolean);

  const paragraphs = Array.from(
    document.querySelectorAll("p")
  ).map((element) => element.innerText.trim())
   .filter(Boolean);

  const links = Array.from(
    document.querySelectorAll("a")
  ).map((element) => ({
    text: element.innerText.trim(),
    url: element.href
  }))
  .filter((link) => link.text || link.url);

  return {
    title,
    url,
    headings,
    paragraphs,
    links,
    extractedAt: new Date().toISOString()
  };
}


// Example page interaction
function highlightElement(selector) {
  const element = document.querySelector(selector);

  if (!element) {
    return false;
  }

  element.style.outline = "3px solid red";
  element.style.backgroundColor = "rgba(255, 0, 0, 0.1)";

  return true;
}


// Example interaction message
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === "HIGHLIGHT_ELEMENT") {
    const success = highlightElement(message.selector);

    sendResponse({
      success
    });
  }

  return true;
});
