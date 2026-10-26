(() => {
  'use strict';
  if (window !== window.top) return;
  const invoke = (command, args) => window.__TAURI__.core.invoke(command, args);
  Object.defineProperty(window, 'tunnelDesktop', {
    value: Object.freeze({
      request: (path, body) => invoke('control_request', { path, body: body === undefined ? null : body }),
      connectPrivileged: args => invoke('connect_full_device', { args }),
      saveShareFile: request => invoke('save_shared_profile', { request }),
    }),
    writable: false,
    configurable: false,
  });
})();
