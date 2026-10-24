'use strict';
const {contextBridge,ipcRenderer}=require('electron');
contextBridge.exposeInMainWorld('tunnelDesktop',{connectPrivileged:args=>ipcRenderer.invoke('connect-privileged',args),saveShareFile:request=>ipcRenderer.invoke('save-share-file',request)});
