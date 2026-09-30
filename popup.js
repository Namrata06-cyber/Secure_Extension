// popup.js

const extractBtn = document.getElementById("extractBtn");
const highlightBtn = document.getElementById("highlightBtn");
const output = document.getElementById("output");


// Get current active tab
async function getActiveTab() {
  const tabs = await chrome.tabs.query({
    active: true,
    currentWindow: true
  });

  return tabs[0];
}


// Extract data
extractBtn.addEventListener("click", async () => {
  try {
    output.textContent = "Extracting...";

    const tab = await getActiveTab();

    const response = await chrome.tabs.sendMessage(tab.id, {
      type: "START_EXTRACTION"
    });

    if (!response?.success) {
      throw new Error(
        response?.error || "Extraction failed"
      );
    }

    output.textContent = JSON.stringify(
      response.data,
      null,
      2
    );

    // Also send extracted data to background
    await chrome.runtime.sendMessage({
      type: "PAGE_DATA",
      data: response.data
    });

  } catch (error) {
    console.error(error);

    output.textContent =
      `Error: ${error.message}`;
  }
});


// Highlight first H1
highlightBtn.addEventListener("click", async () => {
  try {
    const tab = await getActiveTab();

    const response = await chrome.tabs.sendMessage(tab.id, {
      type: "HIGHLIGHT_ELEMENT",
      selector: "h1"
    });

    if (!response?.success) {
      output.textContent = "No H1 element found.";
      return;
    }

    output.textContent = "H1 highlighted.";

  } catch (error) {
    console.error(error);

    output.textContent =
      `Error: ${error.message}`;
  }
});
