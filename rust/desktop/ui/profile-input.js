(function(root,factory){
 if(typeof module==='object'&&module.exports)module.exports=factory();
 else root.TunnelNestProfileInput=factory();
})(typeof globalThis!=='undefined'?globalThis:this,function(){
 'use strict';
 function classify(text){
  if(typeof text!=='string')throw new Error('Drop a profile file, QR image, share code, or protocol link.');
  const value=text.trim();
  if(value.length>24576)throw new Error('Profile code or link is too large.');
  if(/^TN(?:1|2|2P)\./.test(value))return{kind:'shared',value};
  if(/^(?:vmess|vless|trojan|ss):\/\/\S+$/i.test(value))return{kind:'link',value};
  throw new Error('Use a TunnelNest share code or a VMess, VLESS, Trojan, or Shadowsocks link.');
 }
 async function readFile(file,tools={}){
  if(!file)throw new Error('Choose one profile file or QR image.');
  let text;
  if((file.type||'').startsWith('image/')||/\.(png|jpe?g)$/i.test(file.name)){
   if(file.size>4*1024*1024)throw new Error('Choose a QR image smaller than 4 MB.');
   const bitmap=await (tools.createImageBitmap||globalThis.createImageBitmap)(file);
   try{
    if(bitmap.width*bitmap.height>4*1024*1024)throw new Error('QR image is too large. Choose an image under 4 megapixels.');
    const canvas=(tools.document||document).createElement('canvas');canvas.width=bitmap.width;canvas.height=bitmap.height;
    const context=canvas.getContext('2d',{willReadFrequently:true});context.drawImage(bitmap,0,0);
    const image=context.getImageData(0,0,canvas.width,canvas.height);
    const result=(tools.jsQR||globalThis.jsQR)(image.data,image.width,image.height);
    if(!result)throw new Error('No QR code found in this image.');
    text=result.data;
   }finally{bitmap.close();}
  }else{
   if(file.size>24577)throw new Error('Profile file is too large.');
   text=await file.text();
  }
  return classify(text);
 }
 return{classify,readFile};
});
