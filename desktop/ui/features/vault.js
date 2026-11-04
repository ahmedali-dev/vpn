"use strict";

/**
 * Profile vault controller.
 * Unlocks the encrypted profile store through the API and refreshes the saved library.
 */
$("unlockVault").onclick = async () => {
  const password = $("vaultPassword").value;
  $("vaultPassword").value = "";
  $("unlockVault").disabled = true;
  try {
    await api("vault/unlock", { password });
    $("vaultError").textContent = "";
    await loadProfiles();
  } catch (error) {
    $("vaultError").textContent = error.message;
  } finally {
    $("unlockVault").disabled = false;
  }
};
