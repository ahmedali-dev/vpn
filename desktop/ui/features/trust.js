"use strict";

/**
 * SSH trust controller.
 * Displays TLS/SSH trust state and requires independent user verification before filling a persistent fingerprint.
 */
function refreshDropdowns() {
  globalThis.TunnelNestDropdowns?.refresh();
}

function refreshTrust() {
  const c = latestStatus?.connection || {};
  const eligible =
    c.sshAuthenticated === true &&
    $("mode").value === "ssh" &&
    $("host").value.trim() === c.sshHost &&
    Number($("sshPort").value) === Number(c.sshPort) &&
    !!c.sshFingerprint;
  const observed = eligible ? c.sshFingerprint : "";
  if ($("observedKey").value !== observed)
    $("verifiedObservedKey").checked = false;
  $("observedKeyPanel").hidden = !eligible;
  $("observedKey").value = observed;
  $("useObservedKey").disabled = !eligible || !$("verifiedObservedKey").checked;
  const tls = {
    custom_config: "TLS: managed by custom core configuration",
    session_unverified: "TLS: compatibility certificate, first use unverified",
    certificate_verified: "TLS: certificate verification required",
    configured_pin: "TLS: configured certificate pin",
    reality_key: "REALITY: configured server key",
    not_enabled: "TLS: disabled",
  };
  const ssh = {
    session_only: "SSH: session-only first-key trust",
    verified_fingerprint: "SSH: trusted fingerprint matched",
    verified_known_hosts: "SSH: verified against known_hosts",
    pending: "SSH: awaiting host-key check",
  };
  $("trustStatus").hidden = !isRunning() || !c.tlsTrust;
  $("trustStatus").textContent = [tls[c.tlsTrust], ssh[c.sshTrust]]
    .filter(Boolean)
    .join(" · ");
}
$("verifiedObservedKey").onchange = refreshTrust;
$("useObservedKey").onclick = () => {
  refreshTrust();
  if ($("useObservedKey").disabled) return;
  $("hostKey").value = $("observedKey").value;
  $("sshTOFU").checked = false;
  $("sshTrustDetails").open = true;
  $("error").textContent =
    "Verified fingerprint filled. Save this profile to enforce it on future connections.";
};
for (const id of ["host", "sshPort"])
  $(id).addEventListener("input", () => {
    $("verifiedObservedKey").checked = false;
    refreshTrust();
  });
