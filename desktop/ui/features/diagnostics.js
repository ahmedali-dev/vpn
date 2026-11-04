"use strict";

/**
 * Profile diagnostics controller.
 * Runs bounded read-only diagnostics and exports the resulting report.
 */
let profileDiagnosticReport = null,
  profileDiagnosticBusy = false;
async function runProfileDiagnostics(profile) {
  if (profileDiagnosticBusy) {
    $("pageError").textContent = "A profile diagnostic is already running.";
    return;
  }
  if (!profile) {
    $("pageError").textContent = "Select a saved profile to diagnose.";
    return;
  }
  if (profile.locked) {
    $("vaultNotice").hidden = false;
    $("vaultPassword").focus();
    return;
  }
  profileDiagnosticBusy = true;
  profileDiagnosticReport = null;
  $("profileDiagnosticsName").textContent = profile.name;
  $("profileDiagnosticsResults").textContent = "";
  $("downloadProfileDiagnostics").disabled = true;
  $("profileDiagnosticsStatus").textContent = "Checking the saved profile…";
  if (!$("profileDiagnosticsDialog").open)
    $("profileDiagnosticsDialog").showModal();
  try {
    const report = await api("profiles/diagnose", { id: profile.id });
    profileDiagnosticReport = report;
    $("profileDiagnosticsResults").textContent =
      report.checks
        .map(
          (check) =>
            check.stage +
            " · " +
            check.state.toUpperCase() +
            " · " +
            check.durationMs +
            " ms\n" +
            check.message +
            (check.nextAction ? "\nNext: " + check.nextAction : ""),
        )
        .join("\n\n") +
      "\n\nCurrent connection snapshot\n" +
      report.currentSession.scope +
      "\n" +
      JSON.stringify(
        {
          state: report.currentSession.state,
          sshAuthenticated: report.currentSession.sshAuthenticated,
          tlsTrust: report.currentSession.tlsTrust,
          sshTrust: report.currentSession.sshTrust,
          checks: report.currentSession.checks,
        },
        null,
        2,
      );
    $("profileDiagnosticsStatus").textContent =
      report.result === "failed"
        ? "Preflight found a problem. Review the failed stage below."
        : report.result === "warning"
          ? "Preflight completed with a certificate trust warning."
          : "Preflight completed. Authentication and VPN routing require a running connection.";
    $("downloadProfileDiagnostics").disabled = false;
  } catch (error) {
    $("profileDiagnosticsStatus").textContent =
      "Diagnostics unavailable: " + error.message;
  } finally {
    profileDiagnosticBusy = false;
  }
}
$("runProfileDiagnostics").onclick = () =>
  runProfileDiagnostics(savedProfiles.find((p) => p.id === selectedProfileId));
$("closeProfileDiagnostics").onclick = () =>
  $("profileDiagnosticsDialog").close();
$("downloadProfileDiagnostics").onclick = () => {
  if (profileDiagnosticReport)
    downloadShareBlob(
      new Blob([JSON.stringify(profileDiagnosticReport, null, 2)], {
        type: "application/json",
      }),
      "TunnelNest-profile-diagnostics.json",
    );
};
