"use strict";
/** Manual stable-release checks and an explicit system-browser release link. */
let updateReleaseTag = "";
$("checkUpdates").onclick = async () => {
  $("updatesDialog").showModal();
  await checkAppUpdates();
};
$("closeUpdates").onclick = () => $("updatesDialog").close();
async function checkAppUpdates() {
  $("retryUpdates").disabled = true;
  $("openRelease").hidden = true;
  $("updateNotes").textContent = "";
  $("updateStatus").textContent = "Checking GitHub releases…";
  try {
    const result = await api("updates/check", {});
    updateReleaseTag = result.tag;
    $("updateStatus").textContent =
      `Installed: ${result.currentVersion} · Latest release: ${result.latestVersion}. ` +
      (result.updateAvailable
        ? "A new version is available."
        : result.state === "ahead"
          ? "This build is newer than the latest published release."
          : "You are up to date.");
    $("updateNotes").textContent = result.notes || "No release notes provided.";
    $("openRelease").hidden = !result.updateAvailable;
  } catch (e) {
    $("updateStatus").textContent = e.message;
  } finally {
    $("retryUpdates").disabled = false;
  }
}
$("retryUpdates").onclick = checkAppUpdates;
$("openRelease").onclick = async () => {
  try {
    await api("updates/open", { tag: updateReleaseTag });
  } catch (e) {
    $("updateStatus").textContent = e.message;
  }
};
