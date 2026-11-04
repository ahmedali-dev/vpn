"use strict";

/**
 * Connection dashboard presenter.
 * Displays selected profile details, routing choice, transport failures and live power-button state.
 */
function updateDashboard() {
  refreshTrust();
  $("indicator").classList.toggle(
    "connecting",
    busy ||
      ["connecting", "verifying", "reconnecting"].includes(connectionState),
  );
  const running = isRunning(),
    selected = savedProfiles.find(
      (p) => p.id === (running ? activeProfileId : selectedProfileId),
    );
  $("libraryCount").textContent = String(savedProfiles.length).padStart(2, "0");
  $("selectedProfileName").textContent =
    selected?.name ||
    (running ? latestStatus?.connection?.server : "No profile selected") ||
    "Active connection";
  $("selectedProfileProtocol").textContent = selected
    ? selected.mode === "ssh"
      ? "SSH over TLS"
      : "Xray / V2Ray"
    : "Select or create a connection profile";
  const values = running ? lastStartedArgs : selected?.args || [],
    normalized = TunnelNestProfileOptions.normalize(values);
  const flag = (name) => {
    const index = normalized.indexOf(name);
    return index >= 0 ? normalized[index + 1] : "";
  };
  const tun = running
    ? normalized.includes("-tun")
    : (quickRoutingOverride ?? normalized.includes("-tun"));
  $("quickTun").checked = tun;
  $("quickTun").disabled = running || busy || !selected;
  $("quickRoutingHint").textContent = running
    ? "Disconnect before changing routing"
    : quickRoutingOverride === null
      ? "Applies when you connect"
      : "Override for the next connection only";
  $("summaryRoute").textContent = tun ? "Full-device VPN" : "Proxy mode";
  $("summaryProxy").textContent =
    "127.0.0.1:" + (flag("-socks-port") || "1082");
  $("summaryTLS").textContent =
    { auto: "Automatic", "tls1.2": "TLS 1.2 only", "tls1.3": "TLS 1.3 only" }[
      flag("-tls-version") || "auto"
    ] || flag("-tls-version");
  $("quickConnectText").textContent = running
    ? "Disconnect"
    : selected
      ? "Connect to " + selected.name
      : "Add your first profile";
  $("quickPower").setAttribute(
    "aria-label",
    running ? "Disconnect" : "Connect selected profile",
  );
  $("quickConnect").disabled = $("quickPower").disabled =
    busy || connectionState === "stopping" || (running && !latestStatus);
  const recentStreamFailures =
    latestStatus?.transportErrors?.recentUpstreamFailures || 0;
  $("healthState").textContent = !running
    ? "Awaiting connection"
    : connectionState === "connected" &&
        latestStatus?.health?.state === "healthy"
      ? recentStreamFailures
        ? "Online · " +
          (recentStreamFailures >= 32 ? "32+" : recentStreamFailures) +
          " recent stream failures"
        : "Connection verified"
      : latestStatus?.health?.state === "degraded"
        ? "Needs attention"
        : "Connecting…";
  if (running && !lastStartedArgs.length) {
    $("summaryRoute").textContent = "See activity log";
    $("summaryProxy").textContent = "—";
    $("summaryTLS").textContent = "—";
    $("quickRoutingHint").textContent = "Routing managed by the active session";
  }
  $("healthState").classList.toggle(
    "healthy",
    !recentStreamFailures &&
      latestStatus?.health?.state === "healthy" &&
      connectionState === "connected",
  );
  document.body.classList.toggle(
    "isConnected",
    connectionState === "connected",
  );
}
