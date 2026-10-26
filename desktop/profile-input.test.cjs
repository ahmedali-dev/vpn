'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const {classify,readFile}=require('./ui/profile-input.js');

test('shared profile drops retain protected codes and accept protocol links without connecting',()=>{
 for(const code of ['TN1.old','TN2.open','TN2P.protected'])assert.deepEqual(classify('  '+code+'\n'),{kind:'shared',value:code});
 for(const protocol of ['vmess','vless','trojan','ss'])assert.deepEqual(classify(protocol+'://sample'),{kind:'link',value:protocol+'://sample'});
 for(const value of ['', 'https://example.com/profile', '<script>alert(1)</script>', 'vless://one\nsecond'])assert.throws(()=>classify(value),/Use a TunnelNest/);
 assert.throws(()=>classify('TN2.'+'a'.repeat(24576)),/too large/);
});
test('text profile files use the same classifier and reject oversized input before reading',async()=>{
 assert.deepEqual(await readFile({name:'test.tnprofile',type:'text/plain',size:10,text:async()=> 'TN2.sample\n'}),{kind:'shared',value:'TN2.sample'});
 let read=false;
 await assert.rejects(readFile({name:'huge.txt',type:'text/plain',size:24578,text:async()=>{read=true;return 'TN2.sample'}}),/too large/);
 assert.equal(read,false);
 await assert.rejects(readFile({name:'bad.txt',type:'',size:5,text:async()=> 'wrong'}),/Use a TunnelNest/);
});
test('QR image limits apply before decoding and always close a created bitmap',async()=>{
 let opened=false,closed=false;
 const createImageBitmap=async()=>{opened=true;return{width:3000,height:2000,close(){closed=true}}};
 await assert.rejects(readFile({name:'huge.png',type:'image/png',size:5*1024*1024},{createImageBitmap}),/smaller than 4 MB/);
 assert.equal(opened,false);
 await assert.rejects(readFile({name:'large.png',type:'image/png',size:100},{createImageBitmap}),/4 megapixels/);
 assert.equal(closed,true);
});
test('QR decode validates its content and releases the bitmap on success and failure',async()=>{
 for(const decoded of ['TN2P.protected','vless://sample',null,'wrong']){
  let closed=false;
  const tools={createImageBitmap:async()=>({width:10,height:10,close(){closed=true}}),
   document:{createElement:()=>({getContext:()=>({drawImage(){},getImageData:()=>({data:new Uint8ClampedArray(400),width:10,height:10})})})},
   jsQR:()=>decoded===null?null:{data:decoded}};
  const file={name:'qr.jpg',type:'image/jpeg',size:100};
  if(decoded===null)await assert.rejects(readFile(file,tools),/No QR code/);
  else if(decoded==='wrong')await assert.rejects(readFile(file,tools),/Use a TunnelNest/);
  else assert.deepEqual(await readFile(file,tools),classify(decoded));
  assert.equal(closed,true);
 }
});
