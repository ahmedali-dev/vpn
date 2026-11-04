"use strict";

/**
 * Shared UI state and control API.
 * Owns the control-session token, current connection/editor state, icon rendering and the native/browser API adapter.
 */
"use strict";
const $ = (id) => document.getElementById(id);
const actionIconPaths = {
  play: '<path d="m8 5 11 7-11 7Z"/>',
  stop: '<rect x="6" y="6" width="12" height="12" rx="2"/>',
  edit: '<path d="m16 3 5 5-12 12-6 1 1-6Z"/><path d="m13 6 5 5"/>',
  share:
    '<circle cx="18" cy="5" r="3"/><circle cx="6" cy="12" r="3"/><circle cx="18" cy="19" r="3"/><path d="m8.6 10.5 6.8-4M8.6 13.5l6.8 4"/>',
  trash: '<path d="M3 6h18M9 6V3h6v3M5 6l1 15h12l1-15M10 10v7M14 10v7"/>',
  ssh: '<rect x="3" y="4" width="18" height="16" rx="3"/><path d="m7 9 3 3-3 3M13 15h4"/>',
  network:
    '<circle cx="12" cy="12" r="9"/><ellipse cx="12" cy="12" rx="4" ry="9"/><path d="M3 12h18M5 7h14M5 17h14"/>',
};
function actionIcon(name) {
  return (
    '<svg class="uiIcon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false">' +
    actionIconPaths[name] +
    "</svg>"
  );
}

let token = location.hash.slice(1);
const sessionKey = "tunnelnest-control-token";
// Keep the token in the fragment: some embedded browsers do not retain session storage.
// Fragments stay local to the browser and are not sent in HTTP requests.
try {
  if (token) sessionStorage.setItem(sessionKey, token);
  else token = sessionStorage.getItem(sessionKey) || "";
} catch {}
let editorOriginalArgs = [];
let selectedProfileId = 0,
  quickRoutingOverride = null,
  lastStartedArgs = [],
  latestStatus = null;
let helperAvailable = false;
let busy = false,
  lastLogs = "",
  clearOffset = 0,
  administrator = false,
  importedSni = "",
  importGeneration = 0,
  sniOverride = false,
  importTimer,
  currentProfileId = 0,
  savedProfiles = [],
  activeProfileId = 0,
  connectionState = "disconnected",
  profileFilter = "all",
  lastCardState = "",
  vmessDirty = false;
async function api(path, body) {
  if (typeof window !== "undefined" && window.tunnelDesktop?.request)
    return window.tunnelDesktop.request(path, body);
  if (!token)
    throw new Error(
      "Control session is missing. Open the complete CONTROL_URL printed by tunnel -ui.",
    );
  const response = await fetch("/api/" + path, {
    method: body === undefined ? "GET" : "POST",
    headers: { "X-Tunnel-Token": token, "Content-Type": "application/json" },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  if (response.status === 401) {
    token = "";
    try {
      sessionStorage.removeItem(sessionKey);
    } catch {}
    throw new Error(
      "Control session expired. Open the latest complete CONTROL_URL printed by tunnel -ui.",
    );
  }
  let data;
  try {
    data = await response.json();
  } catch {
    throw new Error(
      response.ok
        ? "Invalid response from the control server."
        : "Control request failed (HTTP " + response.status + ").",
    );
  }
  if (!response.ok)
    throw new Error(
      data?.error || "Control request failed (HTTP " + response.status + ").",
    );
  return data;
}
