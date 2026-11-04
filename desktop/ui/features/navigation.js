"use strict";

/**
 * Workspace navigation controller.
 * Owns quick-connect actions, add/import menus, drag/drop targets and sidebar navigation.
 */
async function quickConnect() {
  closeProfileActions();
  if (busy) return;
  if (isRunning()) {
    await stopConnection();
    return;
  }
  const profile = savedProfiles.find((p) => p.id === selectedProfileId);
  if (profile) await runProfile(profile);
  else toggleProfileActions(true);
}
$("quickConnect").onclick = quickConnect;
$("quickPower").onclick = quickConnect;
$("quickTun").onchange = () => {
  quickRoutingOverride = $("quickTun").checked;
  updateDashboard();
};
document.querySelectorAll("[data-section]").forEach(
  (button) =>
    (button.onclick = () => {
      if (button.dataset.section === "logs") $("logsNav").click();
      else if (button.dataset.section === "add") {
        toggleProfileActions(true);
        $("newProfileNav").focus();
      } else {
        showProfiles();
        const target =
          button.dataset.section === "profiles"
            ? $("profilesView")
            : $("overview");
        target.scrollIntoView({ behavior: "smooth" });
      }
    }),
);
document.addEventListener("keydown", (event) => {
  if (
    event.key === "/" &&
    !event.ctrlKey &&
    !event.metaKey &&
    !event.altKey &&
    !["INPUT", "TEXTAREA", "SELECT"].includes(document.activeElement.tagName) &&
    !document.querySelector("dialog[open]")
  ) {
    event.preventDefault();
    $("searchProfiles").focus();
  }
});
function closeProfileActions() {
  $("profileActionsMenu").hidden = true;
  $("newProfileNav").setAttribute("aria-expanded", "false");
}
function toggleProfileActions(force) {
  const open = force ?? $("profileActionsMenu").hidden;
  $("profileActionsMenu").hidden = !open;
  $("newProfileNav").setAttribute("aria-expanded", String(open));
}
function setupWorkspaceControls() {
  const actions = $("profileActions"),
    menu = $("profileActionsMenu"),
    trigger = $("newProfileNav");
  trigger.addEventListener("keydown", (event) => {
    if (menu.hidden && ["ArrowDown", "ArrowUp"].includes(event.key)) {
      event.preventDefault();
      event.stopPropagation();
      toggleProfileActions(true);
      const choices = Array.from(menu.querySelectorAll("[role=menuitem]"));
      choices[event.key === "ArrowUp" ? choices.length - 1 : 0]?.focus();
    }
  });
  $("createProfileAction").onclick = () => newProfile();
  $("importProfileAction").onclick = () => {
    openImportDialog();
    $("sharedInput").focus();
  };
  $("closeImport").onclick = () => $("importDialog").close();
  const chooseFile = () => {
    openImportDialog();
    $("sharedFile").click();
  };
  $("profileDropZone").onclick = chooseFile;
  $("importDropZone").onclick = chooseFile;
  document.addEventListener("click", (event) => {
    if (
      !actions.contains(event.target) &&
      !event.target.closest('[data-section="add"],#quickConnect,#quickPower')
    )
      closeProfileActions();
  });
  document.addEventListener("keydown", (event) => {
    if (menu.hidden) return;
    const choices = Array.from(menu.querySelectorAll("[role=menuitem]")),
      index = choices.indexOf(document.activeElement);
    if (event.key === "Escape") {
      event.preventDefault();
      closeProfileActions();
      trigger.focus();
    } else if (event.key === "Tab") {
      closeProfileActions();
      trigger.focus();
    } else if (["ArrowDown", "ArrowUp", "Home", "End"].includes(event.key)) {
      event.preventDefault();
      const next =
        event.key === "Home"
          ? 0
          : event.key === "End"
            ? choices.length - 1
            : index < 0
              ? event.key === "ArrowUp"
                ? choices.length - 1
                : 0
              : (index +
                  (event.key === "ArrowDown" ? 1 : -1) +
                  choices.length) %
                choices.length;
      choices[next]?.focus();
    }
  });
  const accepts = (event) =>
    Array.from(event.dataTransfer?.types || []).some((type) =>
      ["Files", "text/plain", "text/uri-list"].includes(type),
    );
  for (const target of [actions, $("importDropZone")]) {
    let depth = 0;
    target.addEventListener("dragenter", (event) => {
      if (!accepts(event)) return;
      event.preventDefault();
      depth++;
      target.classList.add("isDragging");
      if (target === actions) toggleProfileActions(true);
    });
    target.addEventListener("dragover", (event) => {
      if (!accepts(event)) return;
      event.preventDefault();
      event.dataTransfer.dropEffect = "copy";
    });
    target.addEventListener("dragleave", () => {
      depth = Math.max(0, depth - 1);
      if (!depth) target.classList.remove("isDragging");
    });
    target.addEventListener("drop", (event) => {
      depth = 0;
      target.classList.remove("isDragging");
      handleProfileDrop(event);
    });
  }
  // Dropped files outside an import target must never navigate the desktop window.
  document.addEventListener("dragover", (event) => {
    if (Array.from(event.dataTransfer?.types || []).includes("Files"))
      event.preventDefault();
  });
  document.addEventListener("drop", (event) => {
    if (Array.from(event.dataTransfer?.types || []).includes("Files"))
      event.preventDefault();
  });
  const rail = $("appRail"),
    shell = document.querySelector(".appShell"),
    toggle = $("sidebarToggle");
  let pinned = false,
    hovered = false,
    keyboardFocus = false;
  try {
    pinned = localStorage.getItem("tunnelnest-sidebar") === "expanded";
  } catch {}
  const render = () => {
    const expanded = pinned || hovered || keyboardFocus;
    shell.classList.toggle("sidebarExpanded", pinned);
    rail.classList.toggle("railExpanded", expanded);
    toggle.setAttribute("aria-expanded", String(expanded));
    const label = pinned
      ? "Collapse sidebar"
      : expanded
        ? "Pin sidebar open"
        : "Expand sidebar";
    toggle.setAttribute("aria-label", label);
    toggle.title = label;
    $("sidebarToggleText").textContent = label;
  };
  toggle.onclick = () => {
    pinned = !pinned;
    try {
      localStorage.setItem(
        "tunnelnest-sidebar",
        pinned ? "expanded" : "collapsed",
      );
    } catch {}
    render();
  };
  rail.addEventListener("pointerenter", () => {
    hovered = true;
    render();
  });
  rail.addEventListener("pointerleave", () => {
    hovered = false;
    render();
  });
  rail.addEventListener("pointerdown", () => {
    keyboardFocus = false;
  });
  rail.addEventListener("focusin", (event) => {
    if (event.target.matches(":focus-visible")) {
      keyboardFocus = true;
      render();
    }
  });
  rail.addEventListener("focusout", (event) => {
    if (!rail.contains(event.relatedTarget)) {
      keyboardFocus = false;
      render();
    }
  });
  render();
}
