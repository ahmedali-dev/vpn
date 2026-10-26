'use strict';
const test=require('node:test');const assert=require('node:assert/strict');const {prepareShareFile}=require('./share-files.cjs');
test('profile files preserve protected and open codes without including passwords',()=>{
 for(const code of ['TN1.old_code','TN2.compact_code','TN2P.protected_code']){
  const file=prepareShareFile({format:'profile',name:'Office/CON',code});assert.equal(file.extension,'tnprofile');assert.equal(file.data.toString(),code+'\n');assert.equal(file.filename,'TunnelNest-Office-CON.tnprofile');
 }
});
test('export rejects invalid file formats, codes, and non-PNG image data',()=>{
 for(const request of [{format:'executable',code:'TN2.code'},{format:'profile',code:'not a share code'},{format:'profile',code:'TN2.'+'a'.repeat(25000)},{format:'qr',image:'data:image/png;base64,'+Buffer.from('not a PNG').toString('base64')}])assert.throws(()=>prepareShareFile(request));
});
test('QR PNG export keeps the image bytes intact',()=>{
 const fs=require('node:fs');const path=require('node:path');const png=fs.readFileSync(path.join(__dirname,'assets/tunnelnest.png'));
 const file=prepareShareFile({format:'qr',name:'Test',image:'data:image/png;base64,'+png.toString('base64')});
 assert.equal(file.extension,'png');assert.deepEqual(file.data,png);
});
