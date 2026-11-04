"use strict";

/**
 * Connection actions controller.
 * Starts/stops the selected connection and requests elevation for full-device routing through native IPC.
 */
async function startConnection(values) {
  if ($("vaultNotice") && !$("vaultNotice").hidden) {
    $("pageError").textContent = "Unlock the profile vault first.";
    return;
  }
  values = TunnelNestProfileOptions.normalize(values);
  if (busy || isRunning()) return;
  lastStartedArgs = [...values];
  latestStatus = null;
  busy = true;
  connectionState = "connecting";
  lastLogs = "";
  clearOffset = 0;
  $("logs").textContent = "Starting connection…";
  $("error").textContent = "";
  $("pageError").textContent = "";
  showProfiles();
  renderProfiles();
  try {
    if (
      values.includes("-tun") &&
      !administrator &&
      !helperAvailable &&
      window.tunnelDesktop
    ) {
      $("pageError").textContent =
        "Approve the system administrator prompt to start full-device VPN.";
      await window.tunnelDesktop.connectPrivileged(values);
    } else {
      await api("start", { args: values });
    }
  } catch (error) {
    connectionState = "error";
    $("pageError").textContent = error.message;
    $("error").textContent = error.message;
    $("logs").textContent = "Connection failed: " + error.message;
  } finally {
    busy = false;
    renderProfiles();
    await poll();
  }
}
$("connection").onsubmit = async (e) => {
  e.preventDefault();
  try {
    activeProfileId = currentProfileId;
    await startConnection(args());
  } catch (error) {
    $("error").textContent = error.message;
  }
};
async function stopConnection() {
  try {
    await api("stop", {});
    await poll();
  } catch (e) {
    $("pageError").textContent = e.message;
  }
}
$("disconnect").onclick = stopConnection;
$("summaryDisconnect").onclick = stopConnection;
$("closeEditor").onclick = showProfiles;
$("cancelEditor").onclick = showProfiles;
$("saveTop").onclick = () => $("saveProfile").click();
$("addRoute").onclick = () => {
  try {
    const value = $("routeValue").value.trim();
    if (!value || /[\r\n]/.test(value))
      throw new Error("Enter a single domain, IP range, or process name.");
    const line =
      $("routeAction").value + " " + $("routeKind").value + " " + value;
    const text = [$("routingRules").value.trim(), line]
      .filter(Boolean)
      .join("\n");
    TunnelNestProfileOptions.routeRules(text);
    $("routingRules").value = text;
    $("routeValue").value = "";
    $("error").textContent = "";
  } catch (e) {
    $("error").textContent = e.message;
  }
};
$("searchProfiles").oninput = renderProfiles;
document.querySelectorAll("[data-filter]").forEach(
  (b) =>
    (b.onclick = () => {
      profileFilter = b.dataset.filter;
      document
        .querySelectorAll("[data-filter]")
        .forEach((x) => x.classList.toggle("selected", x === b));
      renderProfiles();
    }),
);
$("expandLog").onclick = () => {
  const expanded = $("liveActivity").classList.toggle("expanded");
  $("expandLog").textContent = expanded ? "Collapse" : "Expand";
  $("expandLog").setAttribute("aria-expanded", String(expanded));
};
