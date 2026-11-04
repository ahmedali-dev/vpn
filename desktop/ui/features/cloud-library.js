"use strict";
/** Optional shared-library controller. No database credentials are stored in browser storage. */
let mongoConnected = false,
  mongoCursor = "",
  mongoBusy = false;
function openMongoLibrary() {
  $("mongoDialog").showModal();
}
$("openMongoLibrary").onclick = openMongoLibrary;
$("configureMongo").onclick = openMongoLibrary;
$("closeMongo").onclick = () => $("mongoDialog").close();
function mongoStatus(text) {
  $("mongoStatus").textContent = text;
}
async function mongoAction(action) {
  if (mongoBusy) return;
  mongoBusy = true;
  $("mongoConnect").disabled = true;
  $("mongoLoad").disabled = true;
  try {
    await action();
  } catch (e) {
    mongoStatus(e.message);
  } finally {
    mongoBusy = false;
    $("mongoConnect").disabled = false;
    $("mongoLoad").disabled = false;
  }
}
async function finishMongoConnect(result) {
  mongoConnected = true;
  $("mongoCredentials").hidden = true;
  $("mongoLibraryView").hidden = false;
  mongoStatus(
    result.warning || "Connected. Refresh to browse encrypted shared profiles.",
  );
  await refreshMongoLibrary(false);
}
$("mongoConnect").onclick = () =>
  mongoAction(async () => {
    const settings = {
      uri: $("mongoURI").value.trim(),
      database: $("mongoDatabase").value.trim(),
      collection: $("mongoCollection").value.trim(),
      library: $("mongoName").value.trim(),
      passphrase: $("mongoPassphrase").value,
      remember: $("rememberMongo").checked,
    };
    // Clear secrets even when a connection fails. They never enter localStorage.
    $("mongoURI").value = "";
    $("mongoPassphrase").value = "";
    mongoStatus("Connecting and verifying the library passphrase…");
    await finishMongoConnect(await api("mongo/connect", settings));
  });
$("mongoLoad").onclick = () =>
  mongoAction(async () => finishMongoConnect(await api("mongo/load", {})));
$("mongoDisconnect").onclick = () =>
  mongoAction(async () => {
    await api("mongo/disconnect", {});
    mongoConnected = false;
    mongoCursor = "";
    $("mongoCredentials").hidden = false;
    $("mongoLibraryView").hidden = true;
    $("mongoProfiles").replaceChildren();
    mongoStatus("Disconnected. Local profiles remain available.");
  });
$("mongoForget").onclick = () =>
  mongoAction(async () => {
    await api("mongo/forget", {});
    mongoStatus("Saved settings removed from the OS keychain.");
  });
async function refreshMongoLibrary(more) {
  const result = await api("mongo/list", { after: more ? mongoCursor : "" });
  if (!more) $("mongoProfiles").replaceChildren();
  for (const p of result.profiles) {
    const row = document.createElement("div");
    row.className = "mongoProfile";
    const name = document.createElement("span");
    name.textContent = `${p.name} · ${p.mode.toUpperCase()}`;
    const load = document.createElement("button");
    load.type = "button";
    load.textContent = "Save locally";
    load.className = "secondary";
    load.onclick = () =>
      mongoAction(async () => {
        load.disabled = true;
        try {
          await api("mongo/import", { id: p.id });
          await loadProfiles();
          mongoStatus(`Saved “${p.name}” to the local library.`);
        } finally {
          load.disabled = false;
        }
      });
    const remove = document.createElement("button");
    remove.type = "button";
    remove.textContent = "Delete shared";
    remove.className = "textbutton";
    remove.onclick = () => {
      if (
        confirm(
          `Delete “${p.name}” from the shared library for every device? Local copies remain.`,
        )
      )
        mongoAction(async () => {
          await api("mongo/delete", { id: p.id });
          await refreshMongoLibrary(false);
          mongoStatus("Shared profile deleted. Local copies remain.");
        });
    };
    row.append(name, load, remove);
    $("mongoProfiles").append(row);
  }
  const last = result.profiles.at(-1);
  if (last) mongoCursor = last.id;
  $("mongoMore").hidden = result.profiles.length < 25;
  if (!more && !result.profiles.length)
    mongoStatus(
      "Library is empty. Check Save to MongoDB while saving a profile to add one.",
    );
}
$("mongoRefresh").onclick = () => mongoAction(() => refreshMongoLibrary(false));
$("mongoMore").onclick = () => mongoAction(() => refreshMongoLibrary(true));
async function saveSelectedToMongo(id) {
  if (!mongoConnected)
    throw new Error(
      "Profile saved locally. Connect to a MongoDB library, then save again to upload.",
    );
  try {
    await api("mongo/save", { id });
  } catch (e) {
    throw new Error(
      "Profile saved locally; shared-library save failed: " + e.message,
    );
  }
}
