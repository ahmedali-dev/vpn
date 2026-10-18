'use strict';
const {contextBridge,ipcRenderer}=require('electron');
contextBridge.exposeInMainWorld('tunnelDesktop',{connectPrivileged:args=>ipcRenderer.invoke('connect-privileged',args)});
