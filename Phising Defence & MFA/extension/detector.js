"use strict";

// Pure detection functions: no webpage access, storage, or network requests.
const LinkDetector = (() => {
  const defaultConfig = {
    trustedDomains: ["campus.example"],
    blockedDomains: ["blocked.example"],
    maxEditDistance: 1
  };
  const normalizeHost = host => host.toLowerCase().replace(/\.+$/, "");
  const belongsTo = (host, domain) =>
    host === domain || host.endsWith("." + domain);
  const isIPAddress = host => /^\d{1,3}(?:\.\d{1,3}){3}$/.test(host) ||
    (host.startsWith("[") && host.endsWith("]"));

  function editDistance(first, second) {
    let previous = Array.from({length: second.length + 1}, (_, i) => i);
    for (let i = 1; i <= first.length; i++) {
      const current = [i];
      for (let j = 1; j <= second.length; j++) {
        current[j] = Math.min(current[j - 1] + 1, previous[j] + 1,
          previous[j - 1] + (first[i - 1] === second[j - 1] ? 0 : 1));
      }
      previous = current;
    }
    return previous[second.length];
  }

  function parseDisplayedURL(text) {
    const value = text.trim();
    if (/\s/.test(value)) return null;
    const hasScheme = /^https?:\/\//i.test(value);
    const looksLikeHost = /^(?:www\.)?[a-z0-9-]+(?:\.[a-z0-9-]+)+(?:[/:?#]|$)/i.test(value);
    if (!hasScheme && !looksLikeHost) return null;
    try {
      const url = new URL(hasScheme ? value : "https://" + value);
      return ["http:", "https:"].includes(url.protocol) ? url : null;
    } catch { return null; }
  }

  function analyzeLink(displayedText, href, baseURL, config = defaultConfig) {
    const findings = [];
    const add = (code, message) => findings.push({code, message});
    let destination;
    try { destination = new URL(href, baseURL); }
    catch {
      return {status: "invalid", hostname: null, destination: String(href),
        findings: [{code: "INVALID_URL", message: "The destination cannot be parsed."}]};
    }
    if (!["http:", "https:"].includes(destination.protocol)) {
      return {status: "unsupported", hostname: null, destination: destination.href,
        findings: [{code: "UNSUPPORTED_SCHEME", message: "Only HTTP and HTTPS links are analysed."}]};
    }
    const host = normalizeHost(destination.hostname);
    const trusted = config.trustedDomains.map(normalizeHost);
    const blocked = config.blockedDomains.map(normalizeHost);
    const blockedMatch = blocked.find(domain => belongsTo(host, domain));
    if (blockedMatch) add("BLOCKLIST", "Destination matches blocked domain: " + blockedMatch);
    if (isIPAddress(host)) add("IP_ADDRESS", "The destination uses an IP address.");
    if (destination.username || destination.password) {
      add("USERINFO", "URL has user information before @; the actual host is " + host);
    }
    const displayedURL = parseDisplayedURL(displayedText);
    if (displayedURL && normalizeHost(displayedURL.hostname) !== host) {
      add("DISPLAY_MISMATCH", `Displayed host is ${normalizeHost(displayedURL.hostname)}, but destination host is ${host}.`);
    }
    const matchesTrusted = trusted.some(domain => belongsTo(host, domain));
    if (!matchesTrusted && !isIPAddress(host)) {
      const comparisonHost = host.replace(/^www\./, "");
      for (const domain of trusted) {
        const reference = domain.replace(/^www\./, "");
        // Bound work on long hostnames; distance cannot beat the length difference.
        if (Math.abs(comparisonHost.length - reference.length) > config.maxEditDistance) continue;
        const distance = editDistance(comparisonHost, reference);
        if (distance > 0 && distance <= config.maxEditDistance) {
          add("LOOKALIKE", "Destination resembles trusted domain: " + domain);
          break;
        }
      }
    }
    return {status: blockedMatch ? "blocked" : findings.length ? "suspicious" : "no_indicators",
      hostname: host, destination: destination.href, findings};
  }
  return {analyzeLink, defaultConfig};
})();
if (typeof module !== "undefined") module.exports = LinkDetector;
