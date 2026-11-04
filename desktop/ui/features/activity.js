"use strict";

/**
 * Live connection activity controller.
 * Polls status, renders health/recovery state and appends the running connection activity log.
 */
async function poll() {
  try {
    const s = await api("status");
    latestStatus = s;
    if (typeof s.version === "string" && s.version) {
      $("appVersion").textContent = "v" + s.version;
      $("appVersion").hidden = false;
      $("appVersion").setAttribute(
        "aria-label",
        "Application version " + s.version,
      );
    }
    administrator = s.administrator;
    helperAvailable = !!s.helperAvailable;
    connectionState = s.state;
    lastLogFile = s.logFile || "";
    if (s.logError) $("pageError").textContent = s.logError;
    if ($("logsDialog").open && $("followSavedLogs").checked)
      refreshSavedLogs();
    const active = [
      "connected",
      "degraded",
      "connecting",
      "verifying",
      "reconnecting",
      "stopping",
    ].includes(s.state);
    $("badge").textContent = s.state[0].toUpperCase() + s.state.slice(1);
    $("badge").classList.toggle("active", s.state === "connected");
    $("indicator").classList.toggle("active", s.state === "connected");
    $("connect").disabled = active;
    $("disconnect").disabled = !active;
    $("status").textContent = {
      degraded: "Internet connectivity needs attention.",
      connected: "Connection verified.",
      connecting: "Establishing your connection…",
      verifying: "Verifying internet and VPN routing…",
      reconnecting: "Reconnecting to the server…",
      stopping: "Closing your connection…",
      error: "Connection needs attention.",
      disconnected: "Ready when you are.",
    }[s.state];
    $("statusHint").textContent =
      s.health?.state === "degraded"
        ? s.health.error
        : active
          ? s.connection
            ? "Active profile: " +
              s.connection.server +
              " · SNI " +
              s.connection.sni +
              ". Disconnect and reconnect to apply profile changes."
            : "Check the activity log for upstream connectivity."
          : "Import a profile or configure SSH to begin.";
    $("summaryState").textContent = $("badge").textContent;
    $("summaryDisconnect").hidden = !active;
    const selected = savedProfiles.find((p) => p.id === activeProfileId);
    if (selected) {
      const d = profileDetails(selected);
      $("summaryProxy").textContent =
        "127.0.0.1:" + (d.get("-socks-port") || "1082");
      $("summaryRoute").textContent = TunnelNestProfileOptions.normalize(
        selected.args,
      ).includes("-tun")
        ? "Full-device VPN"
        : "Proxy mode";
      $("summaryTLS").textContent = d.get("-tls-version") || "Automatic";
    }
    const cardState =
      connectionState +
      ":" +
      activeProfileId +
      ":" +
      s.health?.state +
      ":" +
      JSON.stringify([
        s.recovery?.lastFailure || null,
        s.transportErrors?.recentUpstreamFailures > 0
          ? s.transportErrors?.lastReason
          : null,
      ]);
    if (cardState !== lastCardState) {
      lastCardState = cardState;
      renderProfiles();
    }
    $("admin").textContent = s.administrator
      ? "Administrator privileges available for full-device VPN."
      : "Full-device VPN will request system administrator authorization when you connect.";
    if (s.error) {
      $("error").textContent = s.error;
      $("pageError").textContent = s.error;
    }
    if (s.logs !== lastLogs) {
      if (s.logs.length < lastLogs.length) clearOffset = 0;
      lastLogs = s.logs;
      $("logs").textContent =
        s.logs.slice(clearOffset) || "Waiting for core output…";
      if ($("followLogs").checked) $("logs").scrollTop = $("logs").scrollHeight;
    }
    updateDashboard();
  } catch (e) {
    $("badge").textContent = "Control service unavailable";
    $("error").textContent = e.message;
    $("quickConnect").disabled = true;
    $("quickPower").disabled = true;
  }
}
