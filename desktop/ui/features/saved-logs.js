"use strict";

/**
 * Saved-log viewer controller.
 * Loads persisted log files and handles level filtering, search, download and follow-latest behavior.
 */
let savedLogText = "",
  savedLogName = "",
  savedLogsBusy = false,
  lastLogFile = "";
function renderSavedLog() {
  const query = $("searchSavedLogs").value.toLowerCase(),
    level = $("savedLogLevel").value;
  const lines = savedLogText
    .split("\n")
    .filter(
      (line) =>
        (!query || line.toLowerCase().includes(query)) &&
        (level === "all" || line.includes("[" + level + "]")),
    );
  $("savedLogsText").textContent =
    lines.join("\n") || "No matching log messages.";
  if ($("followSavedLogs").checked)
    $("savedLogsText").scrollTop = $("savedLogsText").scrollHeight;
}
async function readSavedLog() {
  const name = $("savedLogFiles").value;
  if (!name) {
    savedLogText = "";
    savedLogName = "";
    $("savedLogsText").textContent =
      "No logs yet. Start a connection to create a log file.";
    $("downloadSavedLog").disabled = true;
    return;
  }
  const file = await api("logs/read", { name });
  savedLogText = file.text;
  savedLogName = file.name;
  $("downloadSavedLog").disabled = false;
  renderSavedLog();
}
async function refreshSavedLogs() {
  if (savedLogsBusy) return;
  savedLogsBusy = true;
  try {
    const data = await api("logs"),
      previous = $("savedLogFiles").value;
    $("logDirectory").value = data.directory;
    const signature = JSON.stringify(
      data.files.map((file) => [file.name, Math.ceil(file.size / 1024)]),
    );
    if ($("savedLogFiles").dataset.signature !== signature) {
      $("savedLogFiles").dataset.signature = signature;
      $("savedLogFiles").replaceChildren();
      for (const file of data.files) {
        const option = document.createElement("option");
        option.value = file.name;
        option.textContent =
          file.name + " · " + Math.ceil(file.size / 1024) + " KiB";
        $("savedLogFiles").append(option);
      }
    }
    const selected =
      $("followSavedLogs").checked &&
      data.files.some((f) => f.name === lastLogFile)
        ? lastLogFile
        : previous;
    if (data.files.some((f) => f.name === selected))
      $("savedLogFiles").value = selected;
    refreshDropdowns();
    await readSavedLog();
    $("savedLogsStatus").textContent =
      data.files.length +
      " saved log file(s). " +
      ($("followSavedLogs").checked
        ? "Following latest connection."
        : "Viewing selected file.");
  } catch (error) {
    $("savedLogsStatus").textContent = "Logs unavailable: " + error.message;
  } finally {
    savedLogsBusy = false;
  }
}
$("logsNav").onclick = () => {
  if (!$("logsDialog").open) $("logsDialog").showModal();
  refreshSavedLogs();
};
$("closeSavedLogs").onclick = () => $("logsDialog").close();
$("refreshSavedLogs").onclick = refreshSavedLogs;
$("savedLogFiles").onchange = async () => {
  $("followSavedLogs").checked = false;
  try {
    await readSavedLog();
  } catch (error) {
    $("savedLogsStatus").textContent = error.message;
  }
};
$("searchSavedLogs").oninput = renderSavedLog;
$("savedLogLevel").onchange = renderSavedLog;
$("downloadSavedLog").onclick = () => {
  if (savedLogName)
    downloadShareBlob(
      new Blob([savedLogText], { type: "text/plain;charset=utf-8" }),
      savedLogName,
    );
};
$("copyLogFolder").onclick = async () => {
  try {
    await navigator.clipboard.writeText($("logDirectory").value);
    $("savedLogsStatus").textContent = "Log folder path copied.";
  } catch {
    $("logDirectory").focus();
    $("logDirectory").select();
    $("savedLogsStatus").textContent =
      "Select and copy the folder path manually.";
  }
};
