// background.js

console.log("Background service worker started");

// Handle messages from content scripts / popup
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  console.log("Background received:", message);

  switch (message.type) {
    case "EXTRACT_DATA":
      handleExtractData(sender.tab?.id)
        .then((data) => {
          sendResponse({
            success: true,
            data
          });
        })
        .catch((error) => {
          sendResponse({
            success: false,
            error: error.message
          });
        });

      return true;

    case "PAGE_DATA":
      console.log("Received page data:", message.data);

      // Store extracted data if needed
      chrome.storage.local.set({
        lastExtractedData: message.data,
        extractedAt: Date.now()
      });

      sendResponse({
        success: true
      });

      break;

    default:
      sendResponse({
        success: false,
        error: "Unknown message type"
      });
  }
});


async function handleExtractData(tabId) {
  if (!tabId) {
    throw new Error("No active tab found");
  }

  const response = await chrome.tabs.sendMessage(tabId, {
    type: "START_EXTRACTION"
  });

  return response;
}


// Extension installation
chrome.runtime.onInstalled.addListener(() => {
  console.log("Extension installed successfully");

  chrome.storage.local.set({
    extensionInitialized: true
  });
});
