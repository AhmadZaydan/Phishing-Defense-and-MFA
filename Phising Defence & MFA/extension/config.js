"use strict";

// Shared by settings, the service worker, and content scripts.
const ExtensionConfig = (() => {
  const defaults = LinkDetector.defaultConfig;
  function parseList(value) {
    const entries = Array.isArray(value) ? value : String(value).split(/\r?\n/);
    const result = [];
    for (const entry of entries) {
      const input = String(entry).trim().toLowerCase().replace(/\.+$/, "");
      if (!input) continue;
      if (input.length > 253 || /[\s/@?#*\\]/.test(input)) {
        throw new Error("Enter hostnames only, one per line. Invalid entry: " + input);
      }
      let url;
      try { url = new URL("https://" + input); }
      catch { throw new Error("Invalid hostname: " + input); }
      // Reject ports, user information, shorthand IP addresses, and URL syntax.
      if (url.hostname !== input || url.port || url.username || url.password || url.pathname !== "/") {
        throw new Error("Use a plain hostname without a scheme, port, or path: " + input);
      }
      if (!input.startsWith("[")) {
        const labels = input.split(".");
        if ((labels.length < 2 && input !== "localhost") || labels.some(label =>
          !/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(label))) {
          throw new Error("Invalid hostname: " + input);
        }
      }
      if (!result.includes(input)) result.push(input);
    }
    if (result.length > 200) throw new Error("Maximum 200 hostnames per list.");
    return result;
  }
  function validate(value) {
    if (!value || typeof value !== "object") throw new Error("Missing configuration.");
    return {trustedDomains: parseList(value.trustedDomains),
      blockedDomains: parseList(value.blockedDomains), maxEditDistance: 1};
  }
  return {defaults, validate, parseList};
})();
if (typeof module !== "undefined") module.exports = ExtensionConfig;
