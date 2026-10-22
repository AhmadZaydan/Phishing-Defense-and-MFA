"use strict";
importScripts("detector.js", "config.js");

// Serialize configuration changes, including startup and simultaneous saves.
let pending = Promise.resolve();
function enqueue(task) {
  const operation = pending.then(task);
  pending = operation.catch(error => console.error(error));
  return operation;
}
async function readConfig() {
  const stored = await chrome.storage.local.get("config");
  return ExtensionConfig.validate(stored.config || ExtensionConfig.defaults);
}
function rulesFor(config) {
  return config.blockedDomains.map((domain, index) => ({
    id: index + 1,
    priority: 1,
    action: {type: "block"},
    condition: {requestDomains: [domain], resourceTypes: ["main_frame", "sub_frame"]}
  }));
}
async function applyRules(config) {
  const oldRules = await chrome.declarativeNetRequest.getDynamicRules();
  await chrome.declarativeNetRequest.updateDynamicRules({
    removeRuleIds: oldRules.map(rule => rule.id), addRules: rulesFor(config)
  });
}
async function initialize() {
  const config = await readConfig();
  await applyRules(config);
  await chrome.storage.local.set({config});
}
chrome.runtime.onInstalled.addListener(() => { void enqueue(initialize); });
chrome.runtime.onStartup.addListener(() => { void enqueue(initialize); });

chrome.runtime.onMessage.addListener((message, sender, respond) => {
  // Only packaged extension pages may change policy. Content scripts cannot.
  const extensionPage = sender.id === chrome.runtime.id &&
    sender.url?.startsWith(chrome.runtime.getURL(""));
  if (!extensionPage || !["GET_CONFIG", "SAVE_CONFIG"].includes(message?.type)) return;
  enqueue(async () => {
    if (message.type === "GET_CONFIG") return {ok: true, config: await readConfig()};
    const config = ExtensionConfig.validate(message.config);
    const previous = await readConfig();
    await applyRules(config);
    try { await chrome.storage.local.set({config}); }
    catch (error) { await applyRules(previous); throw error; }
    return {ok: true, config};
  }).then(respond, error => respond({ok: false, error: error.message}));
  return true;
});
