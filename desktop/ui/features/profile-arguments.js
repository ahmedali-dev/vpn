"use strict";

/**
 * Profile argument mapping service.
 * Converts form values into canonical connection arguments and rewrites only supported share-link fields.
 */
function exportLink() {
  const link = $("link").value.trim();
  if (!vmessDirty) return link;
  const vmess = link.startsWith("vmess://"),
    url = vmess ? null : new URL(link);
  const network = vmess
    ? $("vmessNetwork").value
    : url.searchParams.get("type") || "tcp";
  const security = vmess
    ? $("vmessTLS").value
    : url.searchParams.get("security") || "";
  const fields = { host: $("wsHost").value.trim(), path: $("wsPath").value };
  if (network === "grpc") fields.serviceName = $("grpcService").value;
  if (network === "xhttp") {
    let extra = null;
    if ($("xhttpExtra").value.trim()) {
      extra = JSON.parse($("xhttpExtra").value);
      if (!extra || Array.isArray(extra) || typeof extra !== "object")
        throw new Error("XHTTP extra must be a JSON object.");
    }
    fields.mode = $("xhttpMode").value || "auto";
    fields.extra = extra;
  }
  if (security === "reality") fields.spx = $("realitySpiderX").value || "/";
  if (link.startsWith("vmess://")) {
    Object.assign(fields, {
      add: $("vmessAddress").value.trim(),
      port: $("vmessPort").value,
      id: $("vmessUUID").value.trim(),
      net: $("vmessNetwork").value,
      scy: $("vmessCipher").value,
      fp: $("vmessFingerprint").value,
      alpn: $("vmessALPN").value,
      sni: $("sni").value.trim(),
      tls: $("vmessTLS").value === "tls" ? "tls" : "",
    });
  }
  return TunnelNestProfileOptions.rewriteLink(link, fields);
}
for (const id of [
  "vmessAddress",
  "vmessPort",
  "vmessUUID",
  "vmessNetwork",
  "vmessCipher",
  "vmessTLS",
  "vmessFingerprint",
  "vmessALPN",
  "wsHost",
  "wsPath",
  "grpcService",
  "xhttpMode",
  "xhttpExtra",
  "realitySpiderX",
])
  for (const event of ["change", "input"])
    $(id).addEventListener(event, () => (vmessDirty = true));
function args() {
  const result = [
    "-mode",
    $("mode").value,
    "-socks-port",
    $("socks").value,
    "-pac-port",
    $("pac").value,
  ];
  const add = (flag, id) => {
    if ($(id).value.trim()) result.push(flag, $(id).value.trim());
  };
  if ($("mode").value === "ssh") {
    add("-H", "host");
    add("-P", "sshPort");
    add("-u", "username");
    result.push("-p", $("password").value);
    add("-S", "sshSNI");
    result.push(
      "-ssh-cert-sha256",
      $("sshPinMode").value === "manual"
        ? $("sshPin").value.trim()
        : $("sshPinMode").value,
    );
    add("-ssh-host-key", "hostKey");
    result.push(
      $("sshTOFU").checked
        ? "-ssh-trust-on-first-use"
        : "-ssh-trust-on-first-use=false",
    );
    if ($("sshIPv4Only").checked) result.push("-ssh-ipv4-only");
    add("-ssh-known-hosts", "knownHosts");
    add("-tls-ca", "tlsCA");
    add("-proxy", "proxy");
    add("-payload-file", "payloadFile");
    result.push("-payload-stage", $("payloadStage").value);
  } else {
    if (exportLink()) result.push("-v2ray-link", exportLink());
    if (sniOverride || $("sni").value.trim() !== importedSni)
      result.push("-v2ray-sni", $("sni").value.trim());
    result.push(
      "-v2ray-cert-sha256",
      $("pinMode").value === "manual"
        ? $("pin").value.trim()
        : $("pinMode").value,
    );
    add("-v2ray-binary", "corePath");
  }
  if ($("tun").checked) {
    result.push("-tun");
    add("-tun-binary", "tunPath");
  }
  return result;
}
const baseArgs = args;
args = () => {
  const result = baseArgs();
  for (const [f, id] of [
    ["-tun-address4", "tunAddress4"],
    ["-tun-address6", "tunAddress6"],
    ["-tun-stack", "tunStack"],
    ["-tun-mtu", "tunMTU"],
  ])
    if ($(id).value) result.push(f, $(id).value.trim());
  const routing = TunnelNestProfileOptions.routeRules(
    $("routingRules").value || "",
  );
  if (routing.length) result.push("-routing-rules", JSON.stringify(routing));
  if ($("bypassLan").checked) result.push("-bypass-lan");
  result.push("-health-timeout", $("healthTimeout").value || "20");
  if ($("blockQuic").checked) result.push("-block-quic");
  result.push("-tls-version", $("tlsVersion").value);
  return TunnelNestProfileOptions.merge(editorOriginalArgs, result);
};
const baseApplyArgs = applyArgs;
applyArgs = (values) => {
  baseApplyArgs(values);
  const take = (f, d) => {
    const i = values.indexOf(f);
    return i < 0 ? d : values[i + 1];
  };
  $("tunAddress4").value = take("-tun-address4", "172.30.111.1/30");
  $("tunAddress6").value = take("-tun-address6", "fdfe:dcba:9876::1/126");
  $("tunStack").value = take("-tun-stack", "auto");
  $("tunMTU").value = take("-tun-mtu", "1500");
  $("verifiedObservedKey").checked = false;
  refreshTrust();
  const routeIndex = values.indexOf("-routing-rules");
  $("routingRules").value =
    routeIndex >= 0
      ? TunnelNestProfileOptions.routesText(JSON.parse(values[routeIndex + 1]))
      : "";
  $("bypassLan").checked = values.includes("-bypass-lan");
  $("routingDetails").open =
    !!$("routingRules").value || $("bypassLan").checked;
  const timeoutIndex = values.indexOf("-health-timeout");
  $("healthTimeout").value =
    timeoutIndex >= 0 ? values[timeoutIndex + 1] : "20";
  $("blockQuic").checked = values.includes("-block-quic");
  const i = values.indexOf("-tls-version");
  $("tlsVersion").value = i >= 0 ? values[i + 1] || "auto" : "auto";
  refreshDropdowns();
};
