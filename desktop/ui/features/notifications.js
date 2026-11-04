"use strict";

/**
 * Notification preferences controller.
 * Loads/saves private desktop notification preferences and sends explicit test notifications.
 */
let notificationSettingsBusy = false;
function renderNotificationSettings(data) {
  const p = data.preferences;
  $("notificationsEnabled").checked = p.enabled;
  $("notificationConnections").checked = p.connectionUpdates;
  $("notificationProblems").checked = p.problems;
  $("notificationBackgroundOnly").checked = p.backgroundOnly;
  $("testNotifications").disabled = !p.enabled;
  $("notificationStatus").textContent =
    data.systemIssue ||
    (data.systemAuthorization === "denied"
      ? "macOS notifications are denied. Enable TunnelNest in System Settings → Notifications."
      : data.systemAuthorization === "not_determined"
        ? "macOS permission has not been requested. Enable notifications and save, or send a test."
        : data.issue ||
          "Preferences apply while the desktop app is running. Closing the app stops the connection and notifications.");
}
async function openNotificationSettings() {
  if (!$("notificationsDialog").open) $("notificationsDialog").showModal();
  if (
    typeof window === "undefined" ||
    !window.tunnelDesktop?.notificationSettings
  ) {
    $("saveNotifications").disabled = true;
    $("testNotifications").disabled = true;
    $("notificationStatus").textContent =
      "Open the native TunnelNest desktop app to configure system notifications.";
    return;
  }
  $("saveNotifications").disabled = true;
  $("testNotifications").disabled = true;
  $("notificationStatus").textContent = "Loading preferences…";
  try {
    renderNotificationSettings(
      await window.tunnelDesktop.notificationSettings(),
    );
  } catch (error) {
    $("notificationStatus").textContent = error.message;
  } finally {
    $("saveNotifications").disabled = false;
  }
}
$("notificationsNav").onclick = openNotificationSettings;
$("closeNotifications").onclick = () => $("notificationsDialog").close();
$("saveNotifications").onclick = async () => {
  if (
    notificationSettingsBusy ||
    typeof window === "undefined" ||
    !window.tunnelDesktop?.notificationSettings
  )
    return;
  notificationSettingsBusy = true;
  $("saveNotifications").disabled = true;
  $("testNotifications").disabled = true;
  try {
    const data = await window.tunnelDesktop.notificationSettings({
      enabled: $("notificationsEnabled").checked,
      connectionUpdates: $("notificationConnections").checked,
      problems: $("notificationProblems").checked,
      backgroundOnly: $("notificationBackgroundOnly").checked,
    });
    renderNotificationSettings(data);
    if (!data.issue)
      $("notificationStatus").textContent =
        "Notification preferences saved. Use Send test notification to check system delivery.";
  } catch (error) {
    $("notificationStatus").textContent = error.message;
  } finally {
    notificationSettingsBusy = false;
    $("saveNotifications").disabled = false;
  }
};
$("testNotifications").onclick = async () => {
  if (
    notificationSettingsBusy ||
    typeof window === "undefined" ||
    !window.tunnelDesktop?.testNotification
  )
    return;
  notificationSettingsBusy = true;
  $("testNotifications").disabled = true;
  try {
    await window.tunnelDesktop.testNotification();
    $("notificationStatus").textContent =
      "Test submitted. If no banner appears, check system notification settings, Do Not Disturb and the Linux notification daemon.";
  } catch (error) {
    $("notificationStatus").textContent = error.message;
  } finally {
    notificationSettingsBusy = false;
    $("testNotifications").disabled = false;
  }
};
$("exportDiagnostics").onclick = async () => {
  try {
    const report = await api("diagnostics");
    downloadShareBlob(
      new Blob([JSON.stringify(report, null, 2)], { type: "application/json" }),
      "TunnelNest-diagnostics.json",
    );
  } catch (error) {
    $("pageError").textContent = error.message;
  }
};
$("clear").onclick = () => {
  clearOffset = lastLogs.length;
  $("logs").textContent = "";
};
