'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const bridge = fs.readFileSync(__dirname + '/tauri-bridge.js', 'utf8');
const api = fs.readFileSync(__dirname + '/ui/app.js', 'utf8').split('\nfunction setMode()')[0];

test('Tauri serves control requests without exposing a token or using browser fetch', async () => {
  const calls = [];
  const window = { __TAURI__: { core: { invoke: async (command, args) => {
    calls.push(JSON.parse(JSON.stringify({ command, args })));
    return { state: 'disconnected' };
  } } } };
  window.top = window;
  const context = vm.createContext({ window, document: {}, location: { hash: '' },
    sessionStorage: { getItem: () => null }, fetch: () => { throw Error('Unexpected browser HTTP request'); } });
  vm.runInContext(bridge, context);
  vm.runInContext(api, context);
  assert.equal((await vm.runInContext("api('status')", context)).state, 'disconnected');
  await vm.runInContext("api('stop', {})", context);
  assert.deepEqual(calls, [
    { command: 'control_request', args: { path: 'status', body: null } },
    { command: 'control_request', args: { path: 'stop', body: {} } },
  ]);
  assert.ok(Object.isFrozen(window.tunnelDesktop));
  assert.equal(Object.getOwnPropertyDescriptor(window, 'tunnelDesktop').writable, false);
});

test('Tauri privileged connection and export commands preserve request data and errors', async () => {
  const calls = [];
  const window = { __TAURI__: { core: { invoke: async (command, args) => {
    calls.push(JSON.parse(JSON.stringify({ command, args })));
    if (command === 'connect_full_device') throw Error('Administrator authorization declined');
    return { cancelled: false, filename: 'profile.tnprofile' };
  } } } };
  window.top = window;
  vm.runInNewContext(bridge, { window });
  await assert.rejects(window.tunnelDesktop.connectPrivileged(['-mode', 'ssh', '-tun']), /authorization declined/);
  const request = { format: 'profile', name: 'My profile', code: 'TN2.ABC_xyz' };
  const saved = await window.tunnelDesktop.saveShareFile(request);
  assert.equal(saved.filename, 'profile.tnprofile');
  assert.deepEqual(calls, [
    { command: 'connect_full_device', args: { args: ['-mode', 'ssh', '-tun'] } },
    { command: 'save_shared_profile', args: { request } },
  ]);
});

test('subframes do not receive the desktop bridge', () => {
  const window = { top: {} };
  vm.runInNewContext(bridge, { window });
  assert.equal(window.tunnelDesktop, undefined);
});


test('native string errors become readable errors for connection feedback', async () => {
  const window = { __TAURI__: { core: { invoke: async () => { throw 'Required networking core is missing'; } } } };
  window.top = window;
  vm.runInNewContext(bridge, { window });
  await assert.rejects(window.tunnelDesktop.connectPrivileged(['-tun']), /Required networking core is missing/);
});
