"use strict";
async function scan() {
  const status = document.getElementById("status");
  const findings = document.getElementById("findings");
  findings.replaceChildren();
  try {
    const [tab] = await chrome.tabs.query({active: true, currentWindow: true});
    if (!tab?.id) throw new Error("No active tab.");
    const result = await chrome.tabs.sendMessage(tab.id, {type: "SCAN_PAGE"}, {frameId: 0});
    if (!result.ready) throw new Error(result.failed ? "Settings failed to load. Reload the page." : "Settings are loading. Try again.");
    status.textContent = `${result.total} links; ${result.suspicious} suspicious; ${result.blocked} blocked; ${result.unsupported} unsupported/invalid.`;
    for (const finding of result.findings) {
      const item = document.createElement("li");
      item.textContent = `${finding.status}: ${finding.hostname} - ${finding.reasons.join(" ")}`;
      findings.appendChild(item);
    }
  } catch (error) {
    status.textContent = "Cannot scan this page. Use an HTTP/HTTPS page and refresh it after loading or updating the extension. " + error.message;
  }
}
document.getElementById("scan").addEventListener("click", scan);
document.getElementById("settings").addEventListener("click", () => chrome.runtime.openOptionsPage());
void scan();
