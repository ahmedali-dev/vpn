'use strict';
const fs=require('node:fs');
const path=require('node:path');
function createStartupLogger(directory){
 let filename;
 try{fs.mkdirSync(directory,{recursive:true});filename=path.join(directory,'startup.log')}catch{}
 function log(message){
  const clean=String(message).replace(/(http:\/\/127\.0\.0\.1:\d+\/)#[0-9a-f]{64}/g,'$1#[redacted]');
  if(filename){try{fs.appendFileSync(filename,new Date().toISOString()+' '+clean+'\n')}catch{}}
 }
 return {log,filename};
}
function checkBundle(runtime,platform){
 const executable=path.join(runtime,platform==='win32'?'tunnel.exe':'tunnel');
 if(!fs.existsSync(executable))throw new Error('The tunnel engine is missing: '+executable+'\n\nExtract the entire ZIP to a normal folder, then open Tunnel Desktop.exe from that folder. Keep its resources, locales and DLL files together.');
 return executable;
}
module.exports={createStartupLogger,checkBundle};
