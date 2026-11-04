"use strict";

/**
 * Profile sharing and import controller.
 * Handles code/file/QR export, optional share passwords, dropped content and validated shared-profile import.
 */
let sharingProfileId = 0,
  shareGeneration = 0,
  shareFormat = "",
  sharingName = "";
const validSharePrefix = (code) => /^TN(?:1|2|2P)\./.test(code);
const protectedShare = (code) =>
  code.startsWith("TN1.") || code.startsWith("TN2P.");
function clearShareResult() {
  for (const id of [
    "shareCodePanel",
    "shareQRPanel",
    "copyShare",
    "saveShareFile",
    "saveShareQR",
  ])
    $(id).hidden = true;
  $("shareOutput").value = "";
  $("shareSize").textContent = "";
  $("copyShare").disabled = true;
}
function renderShareResult() {
  const code = $("shareOutput").value;
  for (const id of [
    "shareCodePanel",
    "shareQRPanel",
    "copyShare",
    "saveShareFile",
    "saveShareQR",
  ])
    $(id).hidden = true;
  if (!code) return;
  $("shareSize").textContent =
    code.length +
    " characters · " +
    (protectedShare(code) ? "password-protected" : "no password");
  if (shareFormat === "code") {
    $("shareCodePanel").hidden = false;
    $("copyShare").hidden = false;
    $("copyShare").disabled = false;
  } else if (shareFormat === "qr") {
    TunnelNestQR.paint(code, $("shareQR"));
    $("shareQRPanel").hidden = false;
    $("saveShareQR").hidden = false;
  } else if (shareFormat === "file") {
    $("saveShareFile").hidden = false;
  }
}
function chooseShareFormat(format) {
  shareGeneration++;
  shareFormat = format;
  $("createShare").disabled = false;
  $("shareSettings").hidden = false;
  document
    .querySelectorAll("[data-share-format]")
    .forEach((b) =>
      b.setAttribute("aria-pressed", String(b.dataset.shareFormat === format)),
    );
  $("createShare").textContent = {
    qr: "Generate QR code",
    file: "Create profile file",
    code: "Create compact code",
  }[format];
  $("shareStatus").textContent = "";
  try {
    renderShareResult();
  } catch (error) {
    $("shareStatus").className = "notice error";
    $("shareStatus").textContent = error.message;
  }
}
function openShare(profile) {
  sharingProfileId = profile.id;
  sharingName = profile.name;
  shareGeneration++;
  shareFormat = "";
  $("sharingProfileName").textContent = profile.name;
  $("sharePassword").value = "";
  $("shareStatus").textContent = "";
  $("shareSettings").hidden = true;
  $("shareProtection").textContent =
    "Without a password, anyone holding the code, QR, or file can import the credentials.";
  clearShareResult();
  document
    .querySelectorAll("[data-share-format]")
    .forEach((b) => b.setAttribute("aria-pressed", "false"));
  $("shareDialog").showModal();
}
document
  .querySelectorAll("[data-share-format]")
  .forEach(
    (button) =>
      (button.onclick = () => chooseShareFormat(button.dataset.shareFormat)),
  );
$("closeShare").onclick = () => $("shareDialog").close();
$("shareDialog").addEventListener("close", () => {
  shareGeneration++;
  $("sharePassword").value = "";
  clearShareResult();
});
$("sharePassword").addEventListener("input", () => {
  shareGeneration++;
  clearShareResult();
  $("createShare").disabled = false;
  $("shareStatus").textContent = "";
  $("shareProtection").textContent = $("sharePassword").value
    ? "Password protection will be applied. Send the password separately."
    : "Without a password, anyone holding the code, QR, or file can import the credentials.";
});
function downloadShareBlob(blob, filename) {
  const url = URL.createObjectURL(blob),
    link = document.createElement("a");
  link.href = url;
  link.download = filename;
  document.body.append(link);
  link.click();
  link.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}
async function saveShareExport(format) {
  const code = $("shareOutput").value;
  if (!code) return;
  const name =
    sharingName.replace(/[<>:"/\\|?*\x00-\x1f]/g, "-").slice(0, 80) ||
    "profile";
  const request =
    format === "qr"
      ? { format, name, image: $("shareQR").toDataURL("image/png") }
      : { format: "profile", name, code };
  if (window.tunnelDesktop?.saveShareFile) {
    const saved = await window.tunnelDesktop.saveShareFile(request);
    $("shareStatus").textContent = saved.cancelled
      ? "Save cancelled."
      : "Saved " + saved.filename + ".";
  } else {
    if (format === "qr") {
      const blob = await new Promise((resolve) =>
        $("shareQR").toBlob(resolve, "image/png"),
      );
      if (!blob) throw new Error("Could not create QR image");
      downloadShareBlob(blob, "TunnelNest-" + name + "-QR.png");
    } else
      downloadShareBlob(
        new Blob([code + "\n"], { type: "text/plain;charset=utf-8" }),
        "TunnelNest-" + name + ".tnprofile",
      );
    $("shareStatus").textContent = "Download started.";
  }
}
$("shareForm").onsubmit = async (event) => {
  event.preventDefault();
  if (!shareFormat) return;
  const generation = ++shareGeneration;
  $("createShare").disabled = true;
  clearShareResult();
  $("shareStatus").className = "notice";
  $("shareStatus").textContent = "Creating compact share…";
  try {
    const result = await api("profiles/share", {
      id: sharingProfileId,
      password: $("sharePassword").value,
    });
    if (generation !== shareGeneration || !$("shareDialog").open) return;
    $("shareOutput").value = result.code;
    renderShareResult();
    $("shareStatus").textContent = protectedShare(result.code)
      ? "Ready to share. Send the password separately."
      : "Ready to share. This export has no password protection.";
    if (shareFormat === "file") await saveShareExport("profile");
  } catch (error) {
    if (generation === shareGeneration) {
      $("shareStatus").className = "notice error";
      $("shareStatus").textContent = error.message;
    }
  } finally {
    if (generation === shareGeneration) $("createShare").disabled = false;
  }
};
$("copyShare").onclick = async () => {
  try {
    await navigator.clipboard.writeText($("shareOutput").value);
    $("shareStatus").textContent = "Code copied.";
  } catch {
    $("shareOutput").focus();
    $("shareOutput").select();
    $("shareStatus").textContent = "Select and copy the code manually.";
  }
};
for (const [id, format] of [
  ["saveShareFile", "profile"],
  ["saveShareQR", "qr"],
])
  $(id).onclick = async () => {
    try {
      await saveShareExport(format);
    } catch (error) {
      $("shareStatus").className = "notice error";
      $("shareStatus").textContent = error.message;
    }
  };
$("pasteShared").onclick = async () => {
  try {
    $("sharedInput").value = await navigator.clipboard.readText();
    $("importSharedStatus").textContent =
      "Code pasted. Enter its password only if protected.";
  } catch {
    $("sharedInput").focus();
    $("importSharedStatus").textContent =
      "Paste the code into the field using your keyboard.";
  }
};
$("openShareFile").onclick = () => $("sharedFile").click();
function openImportDialog() {
  closeProfileActions();
  if (!$("importDialog").open) $("importDialog").showModal();
}
function showImportError(error) {
  openImportDialog();
  $("importSharedStatus").className = "notice error";
  $("importSharedStatus").textContent = error.message;
}
function stageProfileInput(input, name = "Dropped content") {
  if (input.kind === "link") {
    if ($("importDialog").open) $("importDialog").close();
    closeProfileActions();
    newProfile();
    $("mode").value = "xray";
    setMode();
    $("link").value = input.value;
    $("link").dispatchEvent(new Event("input", { bubbles: true }));
    refreshDropdowns();
    $("error").textContent =
      "Protocol link loaded. Review the details and save the profile to import it.";
    return;
  }
  openImportDialog();
  $("sharedInput").value = input.value;
  $("sharedPassword").value = "";
  $("importSharedStatus").className = "notice";
  $("importSharedStatus").textContent =
    "Loaded " +
    name +
    ". " +
    (protectedShare(input.value)
      ? "Enter its password, then validate and save."
      : "No password needed. Validate and save to import.");
}
async function loadSharedFile(file) {
  if (!file) return;
  $("sharedInput").value = "";
  $("sharedPassword").value = "";
  $("importSharedStatus").textContent = "Reading profile…";
  try {
    stageProfileInput(await TunnelNestProfileInput.readFile(file), file.name);
  } catch (error) {
    showImportError(error);
  }
}
$("sharedFile").onchange = async () => {
  try {
    await loadSharedFile($("sharedFile").files?.[0]);
  } finally {
    $("sharedFile").value = "";
  }
};
async function handleProfileDrop(event) {
  event.preventDefault();
  event.stopPropagation();
  closeProfileActions();
  $("sharedInput").value = "";
  $("sharedPassword").value = "";
  document
    .querySelectorAll(".isDragging")
    .forEach((element) => element.classList.remove("isDragging"));
  try {
    const files = Array.from(event.dataTransfer?.files || []);
    if (files.length > 1)
      throw new Error("Drop one profile file or QR image at a time.");
    if (files.length) {
      await loadSharedFile(files[0]);
      return;
    }
    const text =
      event.dataTransfer?.getData("text/plain") ||
      event.dataTransfer?.getData("text/uri-list") ||
      "";
    stageProfileInput(TunnelNestProfileInput.classify(text));
  } catch (error) {
    showImportError(error);
  }
}
$("importShared").onclick = async () => {
  const code = $("sharedInput").value.trim(),
    password = $("sharedPassword").value;
  $("importSharedStatus").className = "notice";
  if (
    !validSharePrefix(code) ||
    (protectedShare(code) && password.length < 8)
  ) {
    $("importSharedStatus").className = "notice error";
    $("importSharedStatus").textContent = validSharePrefix(code)
      ? "This code needs its password (at least 8 characters)."
      : "Enter a valid TunnelNest share code.";
    return;
  }
  $("importShared").disabled = true;
  $("importSharedStatus").textContent = "Checking shared profile…";
  try {
    const saved = await api("profiles/import-shared", { code, password });
    $("sharedInput").value = "";
    $("sharedPassword").value = "";
    profileFilter = "all";
    $("searchProfiles").value = "";
    document
      .querySelectorAll("[data-filter]")
      .forEach((b) =>
        b.classList.toggle("selected", b.dataset.filter === "all"),
      );
    await loadProfiles();
    $("importSharedStatus").className = "notice success";
    $("importSharedStatus").textContent =
      "Saved new profile: " + saved.name + ". It has not been connected.";
  } catch (error) {
    $("importSharedStatus").className = "notice error";
    $("importSharedStatus").textContent = error.message;
  } finally {
    $("importShared").disabled = false;
  }
};
