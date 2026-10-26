'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),vm=require('node:vm');
function page(){
 const elements=new Map();let requests=0;
 const element=id=>{
  if(!elements.has(id))elements.set(id,{value:'',textContent:'',checked:false,hidden:true,open:false,
   setAttribute(){},addEventListener(){},dispatchEvent(){},reset(){},focus(){},append(){},
   classList:{add(){},remove(){},toggle(){}},showModal(){this.open=true},close(){this.open=false}});
  return elements.get(id);
 };
 const context=vm.createContext({document:{getElementById:element,querySelectorAll:()=>[],querySelector:()=>element('connectionView'),addEventListener(){}},
  location:{hash:'#test'},TunnelNestProfileInput:require('./ui/profile-input.js'),TunnelNestProfileOptions:require('./ui/profile-options.js'),Event:class{},
  setTimeout(){},clearTimeout(){},TextDecoder,TextEncoder,atob,btoa,fetch:async()=>{requests++;throw new Error('Unexpected network request')}});
 const source=fs.readFileSync(__dirname+'/ui/app.js','utf8');
 vm.runInContext(source.slice(0,source.lastIndexOf('setMode();loadProfiles();poll();')),context);
 return{context,element,requests:()=>requests};
}
test('dropped shared profiles are staged for review without saving or connecting',async()=>{
 const current=page();let prevented=0;
 current.context.drop={preventDefault(){prevented++},stopPropagation(){},dataTransfer:{files:[{name:'example.tnprofile',type:'text/plain',size:12,text:async()=> 'TN2P.sample'}]}};
 await vm.runInContext('handleProfileDrop(drop)',current.context);
 assert.equal(current.element('sharedInput').value,'TN2P.sample');assert.equal(current.element('sharedPassword').value,'');
 assert.equal(current.element('importDialog').open,true);assert.match(current.element('importSharedStatus').textContent,/Enter its password/);
 assert.equal(current.requests(),0);assert.equal(prevented,1);
});
test('multiple dropped files and invalid text are rejected without importing',async()=>{
 for(const transfer of [{files:[{},{}]},{files:[],getData:()=> 'https://untrusted.example/profile'}]){
  const current=page();current.context.drop={preventDefault(){},stopPropagation(){},dataTransfer:transfer};
  await vm.runInContext('handleProfileDrop(drop)',current.context);
  assert.equal(current.element('importSharedStatus').className,'notice error');assert.equal(current.requests(),0);
 }
});
test('trusted SSH details preserve fingerprint and known_hosts while opening for saved values',()=>{
 const current=page();
 current.context.saved=['-mode','ssh','-H','example.invalid','-ssh-host-key','SHA256:trusted','-ssh-known-hosts','/sample/known_hosts'];
 vm.runInContext('applyArgs(saved)',current.context);
 assert.equal(current.element('sshTrustDetails').open,true);
 const args=Array.from(vm.runInContext('args()',current.context));
 assert.equal(args[args.indexOf('-ssh-host-key')+1],'SHA256:trusted');assert.equal(args[args.indexOf('-ssh-known-hosts')+1],'/sample/known_hosts');
 vm.runInContext('newProfile()',current.context);assert.equal(current.element('sshTrustDetails').open,false);
});

test('existing profiles keep their certificate verification choices when new defaults change',()=>{
 const current=page();
 current.context.saved=['-mode','ssh','-ssh-cert-sha256','none'];
 vm.runInContext('applyArgs(saved)',current.context);assert.equal(current.element('sshPinMode').value,'none');
 current.context.saved=['-mode','ssh'];
 vm.runInContext('applyArgs(saved)',current.context);assert.equal(current.element('sshPinMode').value,'auto');
 current.context.saved=['-mode','xray','-v2ray-cert-sha256','insecure'];
 vm.runInContext('applyArgs(saved)',current.context);assert.equal(current.element('pinMode').value,'insecure');
 current.context.saved=['-mode','xray'];
 vm.runInContext('applyArgs(saved)',current.context);assert.equal(current.element('pinMode').value,'auto');
});
