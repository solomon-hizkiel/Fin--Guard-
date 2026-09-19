const countEl = document.getElementById("match-count");
const labelEl = document.getElementById("match-label");
const reportBtn = document.getElementById("report-btn");
const DEFAULT_LABEL = "🚨 Report flagged content";
const API_URL = "http://127.0.0.1:5001/api/report";

function render(count) {
  const value = Number.isFinite(count) ? count : 0;
  countEl.textContent = String(value);
  labelEl.textContent =
    value === 1
      ? "indicator found on this page"
      : "indicators found on this page";
}

function collectFlaggedContent() {
  const snippets = Array.from(document.querySelectorAll("span[title]"))
    .map((el) => (el.textContent || "").trim())
    .filter(Boolean);
  return {
    snippets,
    url: window.location.href,
    title: document.title,
  };
}

function flashButton(label) {
  reportBtn.textContent = label;
  reportBtn.disabled = true;
  setTimeout(() => {
    reportBtn.textContent = DEFAULT_LABEL;
    reportBtn.disabled = false;
  }, 2000);
}

async function reportFlaggedContent() {
  reportBtn.disabled = true;
  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (!tab?.id) {
      flashButton("❌ Failed");
      return;
    }

    const results = await chrome.scripting.executeScript({
      target: { tabId: tab.id },
      func: collectFlaggedContent,
    });
    const page = results?.[0]?.result;
    const snippets = page?.snippets || [];
    if (!snippets.length) {
      flashButton("❌ Failed");
      return;
    }

    const response = await fetch(API_URL, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        text: snippets.join("\n"),
        url: page.url || "",
        source_page_title: page.title || "",
      }),
    });
    if (!response.ok) {
      flashButton("❌ Failed");
      return;
    }
    flashButton("✅ Reported");
  } catch (_err) {
    flashButton("❌ Failed");
  }
}

chrome.storage.local.get("finGuardianMatches", (data) => {
  render(data.finGuardianMatches || 0);
});

chrome.storage.onChanged.addListener((changes, area) => {
  if (area === "local" && changes.finGuardianMatches) {
    render(changes.finGuardianMatches.newValue || 0);
  }
});

reportBtn.addEventListener("click", reportFlaggedContent);
