"use strict";

(() => {
  let config = null;
  let failed = false;
  let timer;
  let observer;
  let summary = {total: 0, suspicious: 0, blocked: 0, unsupported: 0, findings: []};
  const originals = new Map();
  const host = document.createElement("div");
  const root = host.attachShadow({mode: "closed"});
  const panel = document.createElement("div");
  panel.style.cssText = "position:fixed;bottom:16px;right:16px;z-index:2147483647;padding:14px;background:#172033;color:white;border-radius:8px;font:14px Arial;max-width:320px;box-shadow:0 2px 10px #0005";
  panel.setAttribute("role", "status");
  root.appendChild(panel);

  function inspect(link) {
    // Visible text first, with a textContent fallback for hidden/layout-free links.
    return LinkDetector.analyzeLink(link.innerText || link.textContent || "",
      link.getAttribute("href"), document.baseURI, config);
  }
  function observe() {
    observer.observe(document.documentElement, {subtree: true, childList: true,
      characterData: true, attributes: true, attributeFilter: ["href", "target"]});
  }
  function restore(link, original) {
    if (original.outline) link.style.setProperty("outline", original.outline, original.priority);
    else link.style.removeProperty("outline");
    if (original.title === null) link.removeAttribute("title");
    else link.setAttribute("title", original.title);
  }
  function scan() {
    if (!config || !document.body) return;
    observer.disconnect();
    for (const [link, original] of originals) restore(link, original);
    originals.clear();
    const next = {total: 0, suspicious: 0, blocked: 0, unsupported: 0, findings: []};
    for (const link of document.querySelectorAll("a[href]")) {
      next.total++;
      const result = inspect(link);
      if (["unsupported", "invalid"].includes(result.status)) next.unsupported++;
      if (!["suspicious", "blocked"].includes(result.status)) continue;
      next[result.status]++;
      originals.set(link, {outline: link.style.getPropertyValue("outline"),
        priority: link.style.getPropertyPriority("outline"), title: link.getAttribute("title")});
      link.style.setProperty("outline", "3px solid " +
        (result.status === "blocked" ? "crimson" : "darkorange"), "important");
      link.title = result.findings.map(f => f.message).join("\n");
      // Popup summary is intentionally bounded; destinations are not stored.
      if (next.findings.length < 50) next.findings.push({hostname: result.hostname,
        status: result.status, reasons: result.findings.map(f => f.message)});
    }
    summary = next;
    if (window === window.top) {
      if (!host.isConnected) document.documentElement.appendChild(host);
      panel.textContent = `Phishing Link Defence: ${next.total} links; ${next.suspicious} suspicious; ${next.blocked} blocked. Unflagged does not mean safe.`;
    }
    observe();
  }
  function scheduleScan() {
    clearTimeout(timer);
    timer = setTimeout(scan, 150);
  }
  observer = new MutationObserver(scheduleScan);

  function intercept(event) {
    if (event.type === "auxclick" && event.button !== 1) return;
    const link = event.composedPath().find(node => node instanceof Element && node.matches("a[href]"));
    if (!link) return;
    // Preserve mailto/tel behaviour. Explicit javascript: anchors are stopped.
    let url;
    try { url = new URL(link.getAttribute("href"), document.baseURI); }
    catch { url = null; }
    const web = url && ["http:", "https:"].includes(url.protocol);
    if (url && !web && url.protocol !== "javascript:") return;
    if (!web) {
      event.preventDefault(); event.stopImmediatePropagation();
      alert("This link is invalid or uses a script URL. Navigation was cancelled.");
      return;
    }
    if (!config) {
      event.preventDefault(); event.stopImmediatePropagation();
      alert(failed ? "Link settings could not load. Reload this page before opening links."
        : "Link settings are loading. Please try again shortly.");
      return;
    }
    const result = inspect(link);
    if (result.status === "no_indicators") return;
    event.preventDefault(); event.stopImmediatePropagation();
    const reasons = result.findings.map(f => "- " + f.message).join("\n");
    if (result.status === "blocked") {
      alert("Navigation blocked by Phishing Link Defence.\n\n" + reasons);
    } else if (result.status === "suspicious") {
      if (confirm("Suspicious link\n\n" + reasons + "\n\nDestination:\n" + result.destination +
        "\n\nOK: open in this tab. Cancel: stay here.")) {
        // Use the URL that was analysed, not a possibly mutated href.
        window.location.assign(result.destination);
      }
    } else alert("This destination could not be analysed. Navigation cancelled.");
  }
  window.addEventListener("click", intercept, true);
  window.addEventListener("auxclick", intercept, true);
  chrome.runtime.onMessage.addListener((message, sender, respond) => {
    if (sender.id !== chrome.runtime.id) return;
    if (message?.type === "SCAN_PAGE") {
      scan(); respond({ready: Boolean(config), failed, ...summary});
    }
  });
  chrome.storage.onChanged.addListener((changes, area) => {
    if (area === "local" && changes.config?.newValue) {
      try { config = ExtensionConfig.validate(changes.config.newValue); failed = false; scheduleScan(); }
      catch { config = null; failed = true; }
    }
  });
  chrome.storage.local.get("config").then(stored => {
    config = ExtensionConfig.validate(stored.config || ExtensionConfig.defaults);
    if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", scan, {once: true});
    else scan();
  }).catch(error => { failed = true; console.error("Phishing Link Defence:", error); });
})();
