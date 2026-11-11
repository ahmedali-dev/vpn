"use strict";
/** Public cloud operations require no account. Database credentials stay on the server. */
let cloudBusy = false;
async function cloudTask(action) {
  if (cloudBusy) return;
  cloudBusy = true;
  for (const id of ["cloudConnect", "refreshCloud"]) $(id).disabled = true;
  try {
    await action();
  } catch (e) {
    $("cloudStatus").textContent = e.message;
    $("pageError").textContent = e.message;
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
    $("cloudStatus").textContent = e.message;
  }
}
$("configureCloud").onclick = openCloud;
$("closeCloud").onclick = () => $("cloudDialog").close();
$("cloudConnect").onclick = () =>
  cloudTask(async () => {
    await api("cloud/connect", { url: $("cloudURL").value.trim() });
    $("cloudStatus").textContent =
      "Public cloud ready. No sign-in is required.";
  });
$("refreshCloud").onclick = () =>
  cloudTask(async () => {
    await ensureCloud();
    $("pageError").textContent = "Refreshing public cloud…";
    const result = await api("cloud/refresh", {});
    await loadProfiles();
    const text = `${result.synced} public profiles refreshed. ${result.conflicts} local edits kept. ${result.invalid} unsupported profiles skipped.`;
    $("pageError").textContent = text;
    $("cloudStatus").textContent = text;
  });
async function uploadCloud(profile) {
  if (profile.locked || profile.needsCredentials) {
    $("pageError").textContent =
      "Unlock the local vault and save credentials before uploading.";
    return;
  }
  await cloudTask(async () => {
    const state = await ensureCloud();
    if (
      !confirm(
        `Publish “${profile.name}” to ${state.url}? Anyone can download its credentials, edit it or delete it. Do not upload private accounts.`,
      )
    )
      return;
    await api("cloud/upload", { id: profile.id });
    $("pageError").textContent = "Profile published to the public cloud.";
  });
}
async function deleteCloud(profile) {
  await cloudTask(async () => {
    const state = await ensureCloud();
    if (
      !confirm(
        `Delete “${profile.name}” from ${state.url} for everyone? The local copy will be kept.`,
      )
    )
      return;
    await api("cloud/delete", { id: profile.id });
    $("pageError").textContent =
      "Deleted from public cloud. Local profile kept.";
  });
}
