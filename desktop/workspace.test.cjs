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


test('SSH session trust is preselected and an unchecked choice survives saving and reopening',()=>{
 const current=page();current.context.saved=['-mode','ssh','-H','example.invalid'];
 vm.runInContext('applyArgs(saved)',current.context);assert.equal(current.element('sshTOFU').checked,true);
 current.element('sshTOFU').checked=false;
 current.context.saved=Array.from(vm.runInContext('args()',current.context));
 assert.ok(current.context.saved.includes('-ssh-trust-on-first-use=false'));
 vm.runInContext('applyArgs(saved)',current.context);assert.equal(current.element('sshTOFU').checked,false);
 vm.runInContext('newProfile()',current.context);assert.equal(current.element('sshTOFU').checked,true);
});


test('TCP web fallback is opt-in and survives profile edits without altering other UDP options',()=>{
 const current=page();current.context.saved=['-mode','xray','-block-quic','-max-conns','24'];
 vm.runInContext('applyArgs(saved)',current.context);assert.equal(current.element('blockQuic').checked,true);
 let result=Array.from(vm.runInContext('args()',current.context));assert.ok(result.includes('-block-quic'));assert.equal(result[result.indexOf('-max-conns')+1],'24');
 current.element('blockQuic').checked=false;result=Array.from(vm.runInContext('args()',current.context));assert.ok(!result.includes('-block-quic'));
 current.element('blockQuic').checked=true;vm.runInContext('newProfile()',current.context);assert.equal(current.element('blockQuic').checked,false);
});


test('passing connectivity checks do not hide recent per-stream failures',()=>{
 const current=page();current.context.document.body=current.element('body');
 vm.runInContext("connectionState='connected';latestStatus={health:{state:'healthy'},transportErrors:{recentUpstreamFailures:4}};updateDashboard()",current.context);
 assert.match(current.element('healthState').textContent,/4 recent stream failures/);
 vm.runInContext("latestStatus.transportErrors.recentUpstreamFailures=0;updateDashboard()",current.context);
 assert.equal(current.element('healthState').textContent,'Connection verified');
});


test('verification timeout can be edited and does not duplicate the original flag',()=>{
 const current=page();current.context.saved=['-mode','xray','-health-timeout','30'];
 vm.runInContext('applyArgs(saved)',current.context);assert.equal(current.element('healthTimeout').value,'30');
 current.element('healthTimeout').value='45';const values=Array.from(vm.runInContext('args()',current.context));
 assert.equal(values.filter(v=>v==='-health-timeout').length,1);assert.equal(values[values.indexOf('-health-timeout')+1],'45');
 vm.runInContext('newProfile()',current.context);assert.equal(current.element('healthTimeout').value,'20');
});
