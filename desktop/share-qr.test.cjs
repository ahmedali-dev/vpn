'use strict';
const test=require('node:test');const assert=require('node:assert/strict');
const {matrix}=require('./ui/share-qr.js');const readQR=require('./ui/qr-reader.js');
test('generated QR codes scan back into the original protected and open codes',()=>{
 for(const code of ['TN2.'+'aB9_-'.repeat(28),'TN2P.'+'7XbA_-'.repeat(50),'TN1.'+'abcdef123'.repeat(40)]){
  const grid=matrix(code),scale=5,quiet=4,size=(grid.length+quiet*2)*scale,pixels=new Uint8ClampedArray(size*size*4).fill(255);
  for(let row=0;row<grid.length;row++)for(let col=0;col<grid.length;col++)if(grid[row][col])for(let dy=0;dy<scale;dy++)for(let dx=0;dx<scale;dx++){const i=(((row+quiet)*scale+dy)*size+(col+quiet)*scale+dx)*4;pixels[i]=63;pixels[i+1]=61;pixels[i+2]=74;}
  const decoded=readQR(pixels,size,size);assert.equal(decoded?.data,code);
 }
});
test('oversized or invalid share data gives an actionable QR error',()=>{
 assert.throws(()=>matrix('invalid'),/Invalid/);
 assert.throws(()=>matrix('TN2.'+'x'.repeat(5000)),/too large/);
});
