(function(root,factory){
 if(typeof module==='object'&&module.exports)module.exports=factory(require('./qrcode.js'));
 else root.TunnelNestQR=factory(root.qrcode);
})(typeof globalThis!=='undefined'?globalThis:this,function(qrcode){
 'use strict';
 function matrix(code){
  if(typeof code!=='string'||!/^TN(?:1|2|2P)\./.test(code))throw new Error('Invalid TunnelNest share code.');
  try{const qr=qrcode(0,'M');qr.addData(code,'Byte');qr.make();const size=qr.getModuleCount();return Array.from({length:size},(_,row)=>Array.from({length:size},(_,col)=>qr.isDark(row,col)));}
  catch{throw new Error('This profile is too large for one QR code. Choose File or Code instead.');}
 }
 function paint(code,canvas){
  const grid=matrix(code),quiet=4,scale=5,size=grid.length;canvas.width=canvas.height=(size+quiet*2)*scale;
  const context=canvas.getContext('2d');context.fillStyle='#ffffff';context.fillRect(0,0,canvas.width,canvas.height);context.fillStyle='#3f3d4a';
  for(let row=0;row<size;row++)for(let col=0;col<size;col++)if(grid[row][col])context.fillRect((col+quiet)*scale,(row+quiet)*scale,scale,scale);
  return canvas;
 }
 return {matrix,paint};
});
