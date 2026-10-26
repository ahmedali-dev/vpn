'use strict';
const path=require('node:path');
const maxCode=24*1024;
function prepareShareFile(request){
 if(!request||typeof request!=='object')throw new Error('Invalid share file request');
 const name=typeof request.name==='string'?request.name:'profile';
 const slug=name.replace(/[<>:"/\\|?*\x00-\x1f]/g,'-').replace(/[. ]+$/,'').slice(0,80)||'profile';
 if(request.format==='profile'){
  const code=typeof request.code==='string'?request.code.trim():'';
  if(code.length>maxCode||!/^TN(?:1|2|2P)\.[A-Za-z0-9_-]+$/.test(code))throw new Error('Invalid profile share code');
  return {filename:'TunnelNest-'+slug+'.tnprofile',extension:'tnprofile',label:'TunnelNest profile',data:Buffer.from(code+'\n','utf8')};
 }
 if(request.format==='qr'){
  if(typeof request.image!=='string'||request.image.length>2*1024*1024||!/^data:image\/png;base64,[A-Za-z0-9+/]+={0,2}$/.test(request.image))throw new Error('Invalid QR image');
  const data=Buffer.from(request.image.slice('data:image/png;base64,'.length),'base64');
  if(data.length>1024*1024||!data.subarray(0,8).equals(Buffer.from([137,80,78,71,13,10,26,10])))throw new Error('Invalid PNG image');
  return {filename:'TunnelNest-'+slug+'-QR.png',extension:'png',label:'QR code image',data};
 }
 throw new Error('Unsupported share file format');
}
module.exports={prepareShareFile};
