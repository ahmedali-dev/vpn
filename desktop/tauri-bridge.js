(() => {
  'use strict';
  if (window !== window.top) return;
  const invoke = async (command, args) => {
    try { return await window.__TAURI__.core.invoke(command, args); }
    catch (reason) {
      throw new Error(typeof reason === 'string' ? reason : reason?.message || 'Desktop request failed');
    }
  };
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
