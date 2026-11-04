"use strict";

/**
 * Application startup.
 * Runs only after all feature controllers are loaded. Starts status polling and initializes workspace bindings.
 */
// START APPLICATION
setMode();
loadProfiles();
poll();
setInterval(poll, 1500);
$("sshPinMode").dispatchEvent(new Event("change"));
setupWorkspaceControls();

for (const id of ["hostKey", "knownHosts"])
  $(id).addEventListener("input", () => {
    if ($("hostKey").value.trim() || $("knownHosts").value.trim())
      $("sshTOFU").checked = false;
  });

$("vmessNetwork").addEventListener("change", () =>
  refreshTransportFields($("vmessNetwork").value, $("vmessTLS").value),
);
