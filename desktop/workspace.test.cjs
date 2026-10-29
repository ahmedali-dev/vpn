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

test('VMess import keeps absent SNI blank and reports its runtime fallback separately',async()=>{
 const current=page();current.context.response={Protocol:'vmess',Address:'fr2.vpnjantit.com',Port:8080,Network:'ws',Security:'tls',SNI:'',EffectiveSNI:'fr2.vpnjantit.com',SNISource:'server',Host:'',Path:'/vpnjantit'};
 vm.runInContext("api=async()=>response;$('link').value='vmess://sample';sniOverride=false",current.context);
 await vm.runInContext('readProfile()',current.context);
 assert.equal(current.element('sni').value,'');assert.equal(current.element('wsHost').value,'');
 assert.match(current.element('profile').textContent,/No SNI in link/);assert.equal(current.element('sni').placeholder,'Automatic: fr2.vpnjantit.com');
 current.context.response={...current.context.response,Address:'us-23.hihu.net',Host:'web.whatsapp.com',EffectiveSNI:'web.whatsapp.com',SNISource:'host'};
 await vm.runInContext('readProfile()',current.context);
 assert.equal(current.element('sni').value,'');assert.equal(current.element('wsHost').value,'web.whatsapp.com');
 assert.match(current.element('profile').textContent,/Automatic TLS name: web.whatsapp.com/);
});
test('late import for the same link cannot overwrite a newer editor session',async()=>{
 const current=page();let resolve;current.context.pending=new Promise(r=>resolve=r);
 vm.runInContext("api=()=>pending;$('link').value='vmess://same'",current.context);
 const old=vm.runInContext('readProfile()',current.context);
 vm.runInContext("importGeneration++;$('sni').value='new-profile.example'",current.context);
 resolve({SNI:'old-profile.example'});await old;
 assert.equal(current.element('sni').value,'new-profile.example');
});
test('explicit empty SNI override survives saving instead of restoring the linked SNI',()=>{
 const current=page();vm.runInContext("$('mode').value='xray';$('link').value='vless://test@example.com:443?sni=linked.example';importedSni='linked.example';sniOverride=true;$('sni').value=''",current.context);
 const values=Array.from(vm.runInContext('args()',current.context));
 assert.equal(values[values.indexOf('-v2ray-sni')+1],'');
 vm.runInContext("connectionState='verifying'",current.context);assert.equal(vm.runInContext('isRunning()',current.context),true);
});

test('a recovered TUN startup failure does not remain an active connection alert',()=>{
 const current=page();current.context.status={health:{state:'healthy'},recovery:{lastFailure:{category:'routing',reason:'TUN during startup exited: exit status: 0'}}};
 assert.equal(vm.runInContext("profileFailure(status,'connected')",current.context),null);
 assert.equal(vm.runInContext("profileFailure(status,'reconnecting').category",current.context),'routing');
 current.context.status.recovery.lastFailure.recoveredAt='2026-10-29T18:28:30Z';
 assert.equal(vm.runInContext("profileFailure(status,'disconnected')",current.context),null);
 current.context.status.transportErrors={recentUpstreamFailures:2,lastReason:'current connection reset'};
 assert.equal(vm.runInContext("profileFailure(status,'connected').reason",current.context),'current connection reset');
});

test('routing rules and local bypass survive profile edits and clear for a new profile',()=>{
 const current=page();current.context.saved=['-mode','ssh','-routing-rules',JSON.stringify([{kind:'domain',value:'example.com',action:'direct'}]),'-bypass-lan'];
 vm.runInContext('applyArgs(saved)',current.context);assert.equal(current.element('bypassLan').checked,true);assert.equal(current.element('routingRules').value,'direct domain example.com');
 const values=Array.from(vm.runInContext('args()',current.context));assert.equal(JSON.parse(values[values.indexOf('-routing-rules')+1])[0].action,'direct');
 vm.runInContext('newProfile()',current.context);assert.equal(current.element('routingRules').value,'');assert.equal(current.element('bypassLan').checked,false);
});
