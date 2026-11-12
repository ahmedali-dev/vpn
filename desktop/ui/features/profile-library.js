async function confirmProfileDelete(name) {
  const dialog = $("profileDeleteDialog");
  $("profileDeleteText").textContent = `Delete “${name}” from this device?`;
  return new Promise((resolve) => {
    let accepted = false;
    dialog.onclose = () => resolve(accepted);
    $("confirmProfileDelete").onclick = () => { accepted = true; dialog.close(); };
    $("cancelProfileDelete").onclick = () => dialog.close();
    dialog.showModal();
  });
}

"use strict";

/**
 * Connection library controller.
 * Renders saved profile rows and performs profile selection, loading, saving and run requests.
 */
function profileDetails(p) {
  p.args = p.args || [];
  const get = (flag) => {
    const i = p.args.indexOf(flag);
    return i >= 0 ? p.args[i + 1] || "" : "";
  };
  let server = get("-H"),
    port = get("-P") || "443",
    network = "SSH over TLS",
    sni = get("-S");
  if (p.mode !== "ssh") {
    server = "Imported connection";
    network = "Xray";
    sni = get("-v2ray-sni");
    try {
      const link = get("-v2ray-link");
      if (link.startsWith("vmess://")) {
        const encoded = link.slice(8).replace(/-/g, "+").replace(/_/g, "/");
        const bytes = Uint8Array.from(atob(encoded), (c) => c.charCodeAt(0));
        const data = JSON.parse(new TextDecoder().decode(bytes));
        server = data.add;
        port = data.port;
        network = (data.net || "tcp") + (data.tls === "tls" ? " · TLS" : "");
        sni = p.args.includes("-v2ray-sni") ? sni : data.sni || "";
      } else if (link) {
        const url = new URL(link);
        server = url.hostname;
        port = url.port;
        network = url.searchParams.get("type") || "tcp";
        sni = p.args.includes("-v2ray-sni")
          ? sni
          : url.searchParams.get("sni") || "";
      }
    } catch {}
  }
  return { server, port, network, sni, get };
}
function isRunning() {
  return [
    "connected",
    "degraded",
    "connecting",
    "verifying",
    "reconnecting",
    "stopping",
  ].includes(connectionState);
}
function profileFailure(status, state) {
  const stream = status?.transportErrors;
  if (stream?.recentUpstreamFailures > 0 && stream?.lastReason)
    return { category: "transport", reason: stream.lastReason };
  const failure = status?.recovery?.lastFailure;
  if (
    failure?.recoveredAt ||
    (state === "connected" && status?.health?.state !== "degraded")
  )
    return null;
  return failure;
}
function renderProfiles() {
  const cards = $("profileCards"),
    activity = $("liveActivity");
  $("activityHome").append(activity);
  if (!savedProfiles.some((p) => p.id === selectedProfileId)) {
    selectedProfileId = savedProfiles[0]?.id || 0;
    quickRoutingOverride = null;
  }
  cards.replaceChildren();
  $("profileCount").textContent =
    savedProfiles.length +
    " saved connection" +
    (savedProfiles.length === 1 ? "" : "s");
  const query = $("searchProfiles").value.trim().toLowerCase();
  const matches = savedProfiles.filter((p) => {
    const d = profileDetails(p);
    return (
      (profileFilter === "all" ||
        (profileFilter === "ssh" ? p.mode === "ssh" : p.mode !== "ssh")) &&
      (p.name + " " + d.server).toLowerCase().includes(query)
    );
  });
  if (!matches.length) {
    const empty = document.createElement("div");
    empty.className = "emptyProfiles";
    const strong = document.createElement("strong");
    strong.textContent = savedProfiles.length
      ? "No matching profiles"
      : "No saved profiles yet";
    const hint = document.createElement("span");
    hint.textContent = savedProfiles.length
      ? "Try another search or filter."
      : "Add an SSH or V2Ray profile to get started.";
    empty.append(strong, hint);
    cards.append(empty);
  }
  for (const p of matches) {
    const d = profileDetails(p),
      selected = activeProfileId === p.id && isRunning();
    const card = document.createElement("article");
    card.className =
      "profileCard" +
      (selected ? " running" : "") +
      (p.id === selectedProfileId ? " picked" : "");
    card.dataset.profileId = p.id;
    const title = document.createElement("div");
    title.className = "profileCardTitle";
    title.innerHTML =
      '<div class="cardTop"><span class="profileMode"></span><span class="cardStatus"></span></div><h3></h3><p></p>';
    const pick = document.createElement("button");
    pick.type = "button";
    pick.className = "profilePick";
    pick.textContent = p.name;
    pick.setAttribute("aria-pressed", String(p.id === selectedProfileId));
    pick.onclick = () => {
      if (isRunning() || busy) return;
      selectedProfileId = p.id;
      quickRoutingOverride = null;
      renderProfiles();
    };
    title.querySelector("h3").append(pick);
    title.querySelector("p").textContent = d.server + ":" + d.port;
    title.querySelector(".profileMode").innerHTML =
      actionIcon(p.mode === "ssh" ? "ssh" : "network") +
      "<span>" +
      (p.mode === "ssh" ? "SSH / TLS" : "V2RAY") +
      "</span>";
    title.querySelector(".cardStatus").textContent = selected
      ? connectionState.toUpperCase()
      : "READY";
    const meta = document.createElement("div");
    meta.className = "cardMeta";
    for (const [label, value] of [
      ["TRANSPORT", d.network],
      ["TLS SNI", d.sni || "Automatic"],
    ]) {
      const item = document.createElement("span");
      item.textContent = label;
      const valueNode = document.createElement("strong");
      valueNode.textContent = value;
      item.append(valueNode);
      meta.append(item);
    }
    const actions = document.createElement("div");
    actions.className = "profileActions";
    const run = document.createElement("button");
    run.innerHTML =
      actionIcon(selected && isRunning() ? "stop" : "play") +
      "<span>" +
      (selected && isRunning() ? "Disconnect" : "Run profile") +
      "</span>";
    run.type = "button";
    run.disabled =
      busy || (isRunning() && !selected) || connectionState === "stopping";
    run.onclick = () => runProfile(p);
    const edit = document.createElement("button");
    edit.className = "secondary";
    edit.type = "button";
    edit.innerHTML = actionIcon("edit") + "<span>Edit</span>";
    edit.onclick = () => {
      if (p.locked) {
        $("vaultNotice").hidden = false;
        $("vaultPassword").focus();
        return;
      }
      currentProfileId = p.id;
      applyArgs(p.args);
      $("profileName").value = p.name;
      $("rememberCredentials").checked = !p.sessionOnly;
      showEditor();
    };
    const del = document.createElement("button");
    del.className = "textbutton danger";
    del.type = "button";
    del.innerHTML = actionIcon("trash") + "<span>Delete</span>";
    del.disabled = selected && isRunning();
    del.onclick = async () => {
      if (!(await confirmProfileDelete(p.name))) return;
      showOperationMessage(`Deleting “${p.name}” from this device…`);
      try {
        await api("profiles/delete", { id: p.id });
        if (activeProfileId === p.id) activeProfileId = 0;
        await loadProfiles();
        showOperationMessage(`“${p.name}” deleted from this device.`, "success");
      } catch (e) {
        const reason = typeof e === "string" ? e : e?.message || "Unexpected error. Please retry.";
        showOperationMessage(`Could not delete “${p.name}”: ${reason}`, "error");
      }
    };
    const share = document.createElement("button");
    share.className = "secondary";
    share.type = "button";
    share.innerHTML = actionIcon("share") + "<span>Share</span>";
    share.onclick = () => openShare(p);
    for (const [button, label] of [
      [run, selected && isRunning() ? "Disconnect" : "Run profile"],
      [edit, "Edit"],
      [share, "Share"],
      [del, "Delete"],
    ]) {
      button.querySelector("span").remove();
      button.title = label;
      button.setAttribute("aria-label", label + " · " + p.name);
    }
    const diagnose = document.createElement("button");
    diagnose.className = "secondary";
    diagnose.type = "button";
    diagnose.innerHTML = actionIcon("network");
    diagnose.title = "Diagnose profile";
    diagnose.setAttribute("aria-label", "Diagnose profile · " + p.name);
    diagnose.onclick = () => runProfileDiagnostics(p);
    const upload = document.createElement("button");
    upload.className = "secondary";
    upload.type = "button";
    upload.textContent = "↑";
    upload.title = "Add / update in cloud";
    upload.setAttribute("aria-label", "Add / update in cloud · " + p.name);
    upload.onclick = () => uploadCloud(p);
    const cloudDelete = document.createElement("button");
    cloudDelete.className = "textbutton danger";
    cloudDelete.type = "button";
    cloudDelete.textContent = "☁ ×";
    cloudDelete.title = "Delete from cloud";
    cloudDelete.setAttribute("aria-label", "Delete from cloud · " + p.name);
    cloudDelete.onclick = () => deleteCloud(p);
    actions.append(run, edit, share, diagnose, upload, cloudDelete, del);
    card.append(title, meta, actions);
    if (activeProfileId === p.id) {
      const failure = profileFailure(latestStatus, connectionState);
      if (failure?.reason) {
        const notice = document.createElement("p");
        notice.className = "connectionFailure";
        notice.setAttribute("role", "status");
        notice.textContent =
          "Last failure · " +
          (failure.category || "connection").toUpperCase() +
          ": " +
          failure.reason;
        card.append(notice);
      }
    }
    cards.append(card);
  }
  updateDashboard();
}
async function runProfile(p) {
  if (busy || connectionState === "stopping") return;
  if (isRunning() && activeProfileId !== p.id) return;
  const selected = activeProfileId === p.id;
  if (p.locked) {
    $("vaultNotice").hidden = false;
    $("vaultPassword").focus();
    return;
  }
  if (p.needsCredentials) {
    currentProfileId = p.id;
    applyArgs(p.args);
    $("rememberCredentials").checked = false;
    $("profileName").value = p.name;
    showEditor();
    $("error").textContent =
      "Enter SSH credentials or paste the protocol link again; credentials were not saved between sessions.";
    return;
  }
  if (selected && isRunning()) {
    await stopConnection();
    return;
  }
  if (selectedProfileId !== p.id) quickRoutingOverride = null;
  activeProfileId = p.id;
  currentProfileId = p.id;
  applyArgs(p.args);
  $("profileName").value = p.name;
  selectedProfileId = p.id;
  let values = TunnelNestProfileOptions.withSessionTrustDefault(p.args);
  if (quickRoutingOverride !== null) {
    values = TunnelNestProfileOptions.withRouting(values, quickRoutingOverride);
  }
  quickRoutingOverride = null;
  await startConnection(values);
}
async function loadProfiles() {
  try {
    const vault = await api("vault/status");
    $("vaultNotice").hidden = !vault.locked;
    $("vaultPassword").hidden = vault.mode === "keychain";
    $("unlockVault").textContent =
      vault.mode === "keychain" ? "Retry OS vault" : "Unlock vault";
    savedProfiles = (await api("profiles")) || [];
    renderProfiles();
  } catch (e) {
    $("pageError").textContent = "Profiles unavailable: " + e.message;
  }
}
$("profilesNav").onclick = showProfiles;
$("newProfileNav").onclick = () => toggleProfileActions();
$("saveProfile").onclick = async () => {
  const name = $("profileName").value.trim();
  if (!name) {
    $("error").textContent = "Enter a profile name first.";
    return;
  }
  if ($("saveProfile").disabled) return;
  $("saveProfile").disabled = true;
  $("saveTop").disabled = true;
  try {
    const p = await api("profiles/save", {
      id: currentProfileId,
      name,
      sessionOnly: !$("rememberCredentials").checked,
      mode: $("mode").value,
      args: args(),
    });
    currentProfileId = p.id;
    await loadProfiles();
    $("error").textContent = "Profile saved locally.";
    showProfiles();
  } catch (e) {
    $("error").textContent = e.message;
  } finally {
    $("saveProfile").disabled = false;
    $("saveTop").disabled = false;
  }
};
