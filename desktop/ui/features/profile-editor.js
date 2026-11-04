"use strict";

/**
 * Profile editor controller.
 * Reads imported transport details, resets editor state and applies stored arguments to form controls.
 */
function setMode() {
  const ssh = $("mode").value === "ssh";
  $("ray").hidden = ssh;
  $("ssh").hidden = !ssh;
  refreshTrust();
}
$("mode").onchange = setMode;
$("pinMode").onchange = () => {
  $("manualPin").hidden = $("pinMode").value !== "manual";
  $("insecureNotice").hidden = $("pinMode").value !== "insecure";
};
$("sshPinMode").onchange = () => {
  $("sshManualPin").hidden = $("sshPinMode").value !== "manual";
  $("sshInsecureNotice").hidden = $("sshPinMode").value !== "insecure";
};
function refreshTransportFields(network, security) {
  $("wsDetails").hidden = !["ws", "httpupgrade", "xhttp"].includes(network);
  $("transportExtras").hidden =
    !["grpc", "xhttp"].includes(network) && security !== "reality";
  $("grpcOptions").hidden = network !== "grpc";
  $("xhttpModeOptions").hidden = network !== "xhttp";
  $("xhttpExtraOptions").hidden = network !== "xhttp";
  $("realityOptions").hidden = security !== "reality";
}
async function readProfile() {
  const link = $("link").value.trim(),
    generation = ++importGeneration;
  if (!link) return;
  try {
    const p = await api("import", { link });
    if (generation !== importGeneration || $("link").value.trim() !== link)
      return;
    const imported = p.SNI || "";
    $("profile").textContent =
      p.Protocol.toUpperCase() +
      " · " +
      p.Address +
      ":" +
      p.Port +
      " · " +
      p.Network +
      (imported
        ? " · SNI " + imported
        : " · No SNI in link · Automatic TLS name: " +
          (p.EffectiveSNI || p.Address) +
          " (" +
          p.SNISource +
          ")");
    if (!sniOverride) $("sni").value = imported;
    importedSni = imported;
    $("sni").placeholder = imported
      ? "Use the SNI in the link"
      : "Automatic: " + (p.EffectiveSNI || p.Address);
    $("wsDetails").hidden = !["ws", "httpupgrade", "xhttp"].includes(p.Network);
    $("vmessFields").hidden = p.Protocol !== "vmess";
    vmessDirty = false;
    if (p.Protocol === "vmess") {
      for (const [id, key] of [
        ["vmessAddress", "Address"],
        ["vmessPort", "Port"],
        ["vmessUUID", "UUID"],
        ["vmessNetwork", "Network"],
        ["vmessTLS", "Security"],
        ["vmessCipher", "Cipher"],
        ["vmessFingerprint", "Fingerprint"],
      ])
        $(id).value =
          p[key] || { vmessCipher: "auto", vmessFingerprint: "" }[id] || "";
      $("vmessALPN").value = (p.ALPN || []).join(",");
    }
    refreshDropdowns();
    $("wsHost").value = p.Host || "";
    $("wsPath").value = p.Path || "/";
    $("grpcService").value = p.ServiceName || "";
    $("xhttpMode").value = p.XHTTPMode || "auto";
    $("xhttpExtra").value = p.XHTTPExtra ? JSON.stringify(p.XHTTPExtra) : "";
    $("realitySpiderX").value = p.RealitySpiderX || "/";
    refreshTransportFields(p.Network, p.Security);
    refreshDropdowns();
    $("error").textContent = "";
  } catch (e) {
    if (generation === importGeneration && $("link").value.trim() === link)
      $("error").textContent = e.message;
  }
}
$("inspect").onclick = readProfile;
$("sni").addEventListener("input", () => {
  sniOverride = true;
});
$("link").addEventListener("input", () => {
  importGeneration++;
  sniOverride = false;
  vmessDirty = false;
  $("vmessFields").hidden = true;
  clearTimeout(importTimer);
  $("sni").value = "";
  importedSni = "";
  $("profile").textContent = "";
  $("wsDetails").hidden = true;
  $("transportExtras").hidden = true;
  $("wsHost").value = "";
  $("wsPath").value = "";
  importTimer = setTimeout(readProfile, 300);
});

function applyArgs(values) {
  importGeneration++;
  sniOverride = values.includes("-v2ray-sni");
  values = TunnelNestProfileOptions.normalize(values);
  editorOriginalArgs = [...values];
  clearTimeout(importTimer);
  $("connection").reset();
  $("pinMode").value = "auto";
  $("sshPinMode").value = "auto";
  vmessDirty = false;
  $("vmessFields").hidden = true;
  $("profile").textContent = "";
  $("wsDetails").hidden = true;
  $("transportExtras").hidden = true;
  const take = (flag) => {
    const i = values.indexOf(flag);
    return i >= 0 ? values[i + 1] || "" : "";
  };
  const mode = take("-mode");
  if (mode) $("mode").value = mode;
  const link = take("-v2ray-link");
  if (link) $("link").value = link;
  const sni = take("-v2ray-sni");
  $("sni").value = sni;
  importedSni = "";
  const pin = take("-v2ray-cert-sha256");
  if (pin) {
    $("pinMode").value = ["auto", "none", "insecure"].includes(pin)
      ? pin
      : "manual";
    $("pin").value = $("pinMode").value === "manual" ? pin : "";
  }
  $("socks").value = take("-socks-port") || $("socks").value;
  $("pac").value = take("-pac-port") || $("pac").value;
  const sshPin = take("-ssh-cert-sha256");
  if (sshPin) {
    $("sshPinMode").value = ["auto", "none", "insecure"].includes(sshPin)
      ? sshPin
      : "manual";
    $("sshPin").value = $("sshPinMode").value === "manual" ? sshPin : "";
  }
  $("sshPort").value = take("-P") || $("sshPort").value;
  const fields = [
    ["-H", "host"],
    ["-u", "username"],
    ["-p", "password"],
    ["-S", "sshSNI"],
    ["-ssh-host-key", "hostKey"],
    ["-ssh-known-hosts", "knownHosts"],
    ["-tls-ca", "tlsCA"],
    ["-proxy", "proxy"],
    ["-payload-file", "payloadFile"],
  ];
  for (const [flag, id] of fields) {
    const value = take(flag);
    if (value) $(id).value = value;
  }
  $("tun").checked = values.includes("-tun");
  $("sshTOFU").checked = TunnelNestProfileOptions.withSessionTrustDefault(
    values,
  ).includes("-ssh-trust-on-first-use");
  $("sshIPv4Only").checked = values.includes("-ssh-ipv4-only");
  $("corePath").value = take("-v2ray-binary");
  $("tunPath").value = take("-tun-binary");
  const stage = take("-payload-stage");
  if (stage) $("payloadStage").value = stage;
  $("sshTrustDetails").open = !!(
    $("hostKey").value ||
    $("knownHosts").value ||
    $("sshTOFU").checked
  );
  setMode();
  $("pinMode").dispatchEvent(new Event("change"));
  $("sshPinMode").dispatchEvent(new Event("change"));
  if (link) readProfile();
  refreshDropdowns();
}
function showProfiles() {
  if ($("connectionView").open) $("connectionView").close();
  $("profilesNav").classList.add("selected");
  $("newProfileNav").classList.remove("selected");
}
function showEditor() {
  if (savedProfiles.find((p) => p.id === currentProfileId)?.locked) {
    $("vaultNotice").hidden = false;
    $("vaultPassword").focus();
    return;
  }
  $("editorTitle").textContent = currentProfileId
    ? "Edit profile"
    : "Add profile";
  $("profilesNav").classList.remove("selected");
  $("newProfileNav").classList.add("selected");
  refreshDropdowns();
  if (!$("connectionView").open) $("connectionView").showModal();
}
function newProfile() {
  $("tunAddress4").value = "172.30.111.1/30";
  $("tunAddress6").value = "fdfe:dcba:9876::1/126";
  $("tunStack").value = "auto";
  $("tunMTU").value = "1500";
  $("verifiedObservedKey").checked = false;
  importGeneration++;
  sniOverride = false;
  $("routingRules").value = "";
  $("bypassLan").checked = false;
  $("routingDetails").open = false;
  closeProfileActions();
  $("sshTrustDetails").open = false;
  editorOriginalArgs = [];
  clearTimeout(importTimer);
  currentProfileId = 0;
  $("connection").reset();
  $("blockQuic").checked = false;
  $("healthTimeout").value = "20";
  $("sshTOFU").checked = true;
  $("profileName").value = "";
  $("profile").textContent = "";
  $("wsDetails").hidden = true;
  $("transportExtras").hidden = true;
  $("wsHost").value = "";
  $("wsPath").value = "";
  importedSni = "";
  vmessDirty = false;
  $("vmessFields").hidden = true;
  $("error").textContent = "";
  setMode();
  $("pinMode").dispatchEvent(new Event("change"));
  $("sshPinMode").dispatchEvent(new Event("change"));
  showEditor();
}
