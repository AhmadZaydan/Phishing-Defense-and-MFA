"use strict";
const trusted = document.getElementById("trusted");
const blocked = document.getElementById("blocked");
const status = document.getElementById("status");
const save = document.getElementById("save");
const defaults = document.getElementById("defaults");
function showConfig(config) {
  trusted.value = config.trustedDomains.join("\n");
  blocked.value = config.blockedDomains.join("\n");
}
function message(text, success = false) {
  status.textContent = text;
  status.className = success ? "success" : "error";
}
async function store(config) {
  save.disabled = defaults.disabled = true;
  try {
    const response = await chrome.runtime.sendMessage({type: "SAVE_CONFIG", config});
    if (!response?.ok) throw new Error(response?.error || "No reply from the background worker.");
    showConfig(response.config);
    message("Saved. Domain-blocking rules applied. Open pages will rescan automatically.", true);
  } catch (error) { message("Could not save: " + error.message); }
  finally { save.disabled = defaults.disabled = false; }
}
document.getElementById("settings").addEventListener("submit", event => {
  event.preventDefault();
  try {
    const config = ExtensionConfig.validate({trustedDomains: trusted.value, blockedDomains: blocked.value});
    void store(config);
  } catch (error) { message(error.message); }
});
defaults.addEventListener("click", () => {
  if (confirm("Replace both lists with campus.example and blocked.example demo defaults?")) {
    void store(ExtensionConfig.defaults);
  }
});
chrome.runtime.sendMessage({type: "GET_CONFIG"}).then(response => {
  if (!response?.ok) throw new Error(response?.error || "No reply from the background worker.");
  showConfig(response.config);
  save.disabled = defaults.disabled = false;
  message("Settings loaded.", true);
}).catch(error => message("Could not load: " + error.message));
