"use strict";
/** Public API operations with an app dialog (works in native WebViews) and durable feedback. */
let cloudBusy = false;
function showOperationMessage(text, kind = "info") {
  $("operationFeedback").hidden = false;
  $("operationFeedback").dataset.kind = kind;
  $("operationFeedbackText").textContent = text;
  $("cloudStatus").textContent = text;
}
$("dismissOperationFeedback").onclick = () => $("operationFeedback").hidden = true;
function confirmCloud(message, label) {
  return new Promise((resolve) => {
    const dialog = $("cloudConfirmDialog");
    $("cloudConfirmText").textContent = message;
    $("acceptCloudAction").textContent = label;
    let accepted = false;
    dialog.onclose = () => resolve(accepted);
    $("acceptCloudAction").onclick = () => { accepted = true; dialog.close(); };
    $("cancelCloudAction").onclick = () => dialog.close();
    dialog.showModal();
  });
}
async function cloudTask(action) {
  if (cloudBusy) {
    showOperationMessage("A cloud action is already running. Please wait.");
    return;
  }
  cloudBusy = true;
  for (const id of ["cloudConnect", "refreshCloud"]) $(id).disabled = true;
  showOperationMessage("Contacting public cloud…");
  try {
    await action();
  } catch (e) {
    const reason = typeof e === "string" ? e : e?.message || "Unexpected cloud error. Please retry.";
    showOperationMessage("Cloud action failed: " + reason, "error");
  } finally {
    cloudBusy = false;
    for (const id of ["cloudConnect", "refreshCloud"]) $(id).disabled = false;
  }
}
async function ensureCloud() {
  const state = await api("cloud/status", {});
  return state.connected ? state : api("cloud/connect", { url: state.url });
}
async function openCloud() {
  $("cloudDialog").showModal();
  try {
    const state = await api("cloud/status", {});
    $("cloudURL").value = state.url;
  } catch (e) {
    showOperationMessage(e?.message || String(e), "error");
  }
}
$("configureCloud").onclick = openCloud;
$("closeCloud").onclick = () => $("cloudDialog").close();
$("cloudConnect").onclick = () => cloudTask(async () => {
  await api("cloud/connect", { url: $("cloudURL").value.trim() });
  showOperationMessage("Public cloud ready. No sign-in is required.", "success");
});
$("refreshCloud").onclick = () => cloudTask(async () => {
  await ensureCloud();
  showOperationMessage("Refreshing public cloud…");
  const result = await api("cloud/refresh", {});
  await loadProfiles();
  showOperationMessage(`${result.synced} public profiles refreshed. ${result.conflicts} local edits kept. ${result.invalid} unsupported profiles skipped.`, "success");
});
async function uploadCloud(profile) {
  if (profile.locked || profile.needsCredentials || profile.sessionOnly) {
    showOperationMessage("Unlock the local vault and save credentials with Remember credentials before uploading.", "error");
    return;
  }
  await cloudTask(async () => {
    const state = await ensureCloud();
    if (!await confirmCloud(`Publish “${profile.name}” to ${state.url}? Anyone can download its credentials, edit it or delete it.`, "Add / update in cloud")) {
      showOperationMessage("Cloud upload cancelled.");
      return;
    }
    showOperationMessage(`Uploading “${profile.name}”…`);
    await api("cloud/upload", { id: profile.id });
    showOperationMessage(`“${profile.name}” published to the public cloud. Existing cloud copy updated if present.`, "success");
  });
}
async function deleteCloud(profile) {
  await cloudTask(async () => {
    const state = await ensureCloud();
    if (!await confirmCloud(`Delete “${profile.name}” from ${state.url} for everyone? The local copy will be kept.`, "Delete from cloud")) {
      showOperationMessage("Cloud deletion cancelled.");
      return;
    }
    showOperationMessage(`Deleting “${profile.name}” from cloud…`);
    await api("cloud/delete", { id: profile.id });
    showOperationMessage(`“${profile.name}” deleted from public cloud. Local profile kept.`, "success");
  });
}
