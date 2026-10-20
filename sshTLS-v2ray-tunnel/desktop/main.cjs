'use strict';
const {app,BrowserWindow,dialog,ipcMain}=require('electron');
const {spawn}=require('node:child_process');
const path=require('node:path');
const os=require('node:os');
const fs=require('node:fs/promises');
const http=require('node:http');
const {createStartupLogger,checkBundle}=require('./startup.cjs');
const {prepareShareFile}=require('./share-files.cjs');
// Keep existing Electron preferences while changing the visible app name.
const existingUserData=app.getPath('userData');app.setName('TunnelNest');app.setPath('userData',existingUserData);
let startupLogger;
function startupLog(message){if(startupLogger)startupLogger.log(message);else console.error(String(message));}
function startupError(title,error){const message=error instanceof Error?error.message:String(error);startupLog(title+': '+message);dialog.showErrorBox(title,message+(startupLogger?.filename?'\n\nStartup log: '+startupLogger.filename:''));}
process.on('uncaughtException',error=>{startupError('TunnelNest startup error',error);app.quit()});
process.on('unhandledRejection',error=>{startupError('TunnelNest error',error);app.quit()});
let engine,window,control,quitting=false,elevating=false;
const key=process.platform+'-'+process.arch;
function runtimeDir(){return app.isPackaged?path.join(process.resourcesPath,key):path.resolve(__dirname,'../dist/runtime',key)}
function enginePath(){return path.join(runtimeDir(),process.platform==='win32'?'tunnel.exe':'tunnel')}
function validControl(raw){const url=new URL(raw);if(url.protocol!=='http:'||url.hostname!=='127.0.0.1'||!url.port||!/^#[0-9a-f]{64}$/.test(url.hash))throw new Error('Invalid local control address');return url;}
function requestControl(address,route,body={}){return new Promise((resolve,reject)=>{const url=new URL(route,address);const req=http.request(url,{method:'POST',headers:{'X-Tunnel-Token':address.hash.slice(1),'Content-Type':'application/json'}},res=>{let data='';res.on('data',part=>data+=part);res.on('end',()=>{try{const parsed=JSON.parse(data);if(res.statusCode>=400)reject(new Error(parsed.error||'Control request failed'));else resolve(parsed)}catch(error){reject(error)}})});req.setTimeout(25000,()=>req.destroy(new Error('Control request timed out')));req.on('error',reject);req.end(JSON.stringify(body));});}
function openWindow(){window=new BrowserWindow({width:1320,height:960,minWidth:820,minHeight:650,title:'TunnelNest',icon:path.join(__dirname,'assets','tunnelnest.png'),backgroundColor:'#f8f6f3',autoHideMenuBar:true,webPreferences:{nodeIntegration:false,contextIsolation:true,sandbox:true,preload:path.join(__dirname,'preload.cjs')}});window.webContents.setWindowOpenHandler(()=>({action:'deny'}));window.webContents.on('will-navigate',(event,url)=>{if(new URL(url).origin!==control.origin)event.preventDefault()});window.webContents.on('did-fail-load',(_event,code,description)=>startupLog('Window load failed '+code+': '+description));window.webContents.on('render-process-gone',(_event,details)=>startupError('Desktop renderer stopped',details.reason));return window.loadURL(control.href);}
function start(){
 if(process.platform==='darwin'&&app.dock)app.dock.setIcon(path.join(__dirname,'assets','tunnelnest.png'));
 startupLogger=createStartupLogger(process.platform==='win32'&&process.env.LOCALAPPDATA?path.join(process.env.LOCALAPPDATA,'TunnelDesktop','logs'):path.join(app.getPath('userData'),'logs'));
 startupLog('Starting '+app.getVersion()+' on '+process.platform+' '+process.arch+'; OS '+os.release());
 let executable;
 try{executable=checkBundle(runtimeDir(),process.platform)}catch(error){startupError('Incomplete desktop package',error);app.quit();return}
 startupLog('Engine: '+executable);
 const child=spawn(executable,['-ui','-ui-no-browser'],{cwd:runtimeDir(),windowsHide:true,stdio:['ignore','pipe','pipe']});engine=child;
 let buffer='',errors='';
 const timeout=setTimeout(()=>{if(!control&&engine===child){startupError('Tunnel engine did not become ready','The engine did not start within 30 seconds. '+errors);child.kill();app.quit()}},30000);
 child.stderr.on('data',data=>{errors=(errors+data).slice(-4000);startupLog('Engine stderr: '+data)});
 child.on('error',error=>{clearTimeout(timeout);startupError('Cannot start tunnel engine',error);app.quit()});
 child.on('exit',code=>{clearTimeout(timeout);startupLog('Engine exited: '+code);if(!quitting&&engine===child){startupError('Tunnel engine stopped',errors||'Exit code: '+code);app.quit()}});
 child.stdout.on('data',data=>{buffer+=data;let end;while((end=buffer.indexOf('\n'))>=0){const line=buffer.slice(0,end).replace(/\r$/,'');buffer=buffer.slice(end+1);if(line.startsWith('CONTROL_URL=')&&!control){clearTimeout(timeout);control=validControl(line.slice(12).trim());startupLog('Control service ready');openWindow().catch(error=>startupError('Cannot load desktop interface',error));}else if(line){startupLog('Engine: '+line)}}});
}

const shellQuote=value=>"'"+value.replaceAll("'","'\"'\"'")+"'";
const psQuote=value=>"'"+value.replaceAll("'","''")+"'";
async function elevateBackend(){
 const temporary=await fs.mkdtemp(path.join(os.tmpdir(),'tunnel-desktop-'));
 const ready=path.join(temporary,'ready');await fs.writeFile(ready,'',{mode:0o600});
 let launcher,launchError;
 const exe=enginePath();
 if(process.platform==='darwin'){
  const command=[exe,'-ui','-ui-ready-file',ready].map(shellQuote).join(' ')+' </dev/null >/dev/null 2>&1 &';
  launcher=spawn('/usr/bin/osascript',['-e','do shell script '+JSON.stringify(command)+' with administrator privileges'],{stdio:'ignore'});
 }else if(process.platform==='linux'){
  launcher=spawn('pkexec',[exe,'-ui','-ui-ready-file',ready],{stdio:'ignore'});
 }else if(process.platform==='win32'){
  const argumentLine='-ui -ui-ready-file "'+ready+'"';
  const script='Start-Process -FilePath '+psQuote(exe)+' -ArgumentList '+psQuote(argumentLine)+' -Verb RunAs -WindowStyle Hidden';
  launcher=spawn('powershell.exe',['-NoProfile','-NonInteractive','-Command',script],{windowsHide:true,stdio:'ignore'});
 }else{throw new Error('Administrator launch is unsupported on this platform')}
 launcher.on('error',error=>launchError=error);
 launcher.on('exit',code=>{if(code)launchError=new Error('Administrator authorization was declined or the helper could not start')});
 try{
  for(let i=0;i<400;i++){
   if(launchError)throw launchError;
   const value=await fs.readFile(ready,'utf8').catch(()=> '');
   if(value.trim())return validControl(value.trim());
   await new Promise(resolve=>setTimeout(resolve,200));
  }
  throw new Error('Timed out waiting for the administrator helper');
 }finally{await fs.rm(temporary,{recursive:true,force:true}).catch(()=>{})}
}
ipcMain.handle('save-share-file',async(event,request)=>{
 if(!window||event.sender!==window.webContents||event.senderFrame!==window.webContents.mainFrame||new URL(event.senderFrame.url).origin!==control.origin)throw new Error('Unauthorized desktop request');
 const file=prepareShareFile(request);
 const selected=await dialog.showSaveDialog(window,{title:request.format==='qr'?'Save profile QR code':'Save shared profile',defaultPath:path.join(app.getPath('downloads'),file.filename),filters:[{name:file.label,extensions:[file.extension]}]});
 if(selected.canceled||!selected.filePath)return {cancelled:true};
 await fs.writeFile(selected.filePath,file.data,{mode:0o600});
 if(process.platform!=='win32')await fs.chmod(selected.filePath,0o600);
 return {cancelled:false,filename:path.basename(selected.filePath)};
});
ipcMain.handle('connect-privileged',async(event,args)=>{
 if(!window||event.sender!==window.webContents||new URL(event.senderFrame.url).origin!==control.origin)throw new Error('Unauthorized desktop request');
 if(elevating)throw new Error('Administrator authorization is already in progress');
 if(!Array.isArray(args)||args.length>128||!args.every(value=>typeof value==='string'&&value.length<=65536)||!args.includes('-tun'))throw new Error('Invalid full-device connection request');
 elevating=true;let elevated;
 try{
  elevated=await elevateBackend();
  const safeArgs=[...args,'-tun-binary',path.join(runtimeDir(),'cores',process.platform==='win32'?'sing-box.exe':'sing-box')];
  if(!safeArgs.includes('-mode')||safeArgs[safeArgs.indexOf('-mode')+1]!=='ssh')safeArgs.push('-v2ray-binary',path.join(runtimeDir(),'cores',process.platform==='win32'?'xray.exe':'xray'));
  if(safeArgs.includes('-mode')&&safeArgs[safeArgs.indexOf('-mode')+1]==='ssh'&&!safeArgs.includes('-ssh-known-hosts'))safeArgs.push('-ssh-known-hosts',path.join(os.homedir(),'.ssh','known_hosts'));
  await requestControl(elevated,'/api/start',{args:safeArgs});
  const old=control;const oldEngine=engine;engine=undefined;control=elevated;
  await requestControl(old,'/api/quit').catch(()=>{});if(oldEngine)oldEngine.kill();
  await window.loadURL(control.href);
  return {ok:true};
 }catch(error){if(elevated)await requestControl(elevated,'/api/quit').catch(()=>{});throw error}finally{elevating=false}
});
if(!app.requestSingleInstanceLock()){app.quit()}else{app.on('second-instance',()=>{if(window){if(window.isMinimized())window.restore();window.focus()}});app.whenReady().then(start).catch(error=>{startupError('Cannot initialize desktop app',error);app.quit()});}
app.on('window-all-closed',()=>app.quit());
app.on('before-quit',event=>{if(quitting)return;event.preventDefault();quitting=true;const stop=control?requestControl(control,'/api/quit').catch(()=>{}):Promise.resolve();stop.finally(()=>{if(engine)engine.kill();app.exit(0)});});
