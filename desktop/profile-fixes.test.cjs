const test=require('node:test'),assert=require('node:assert/strict'),vm=require('node:vm'),fs=require('node:fs');
function fixture(){
 const elements=new Map();const el=id=>{if(!elements.has(id))elements.set(id,{value:'',checked:false,hidden:false,textContent:'',addEventListener(name,fn){this[name]=fn},reset(){},append(){},dispatchEvent(){},classList:{add(){},remove(){},toggle(){}}});return elements.get(id)};
 const context=vm.createContext({document:{getElementById:el,querySelectorAll:()=>[],addEventListener(){},querySelector:()=>el('connectionView')},location:{hash:'#test',pathname:'/'},history:{replaceState(){}},TextDecoder,TextEncoder,atob,btoa,URL,Event:class{},setTimeout(){},clearTimeout(){},TunnelNestProfileOptions:require('./ui/profile-options.js'),fetch:async()=>({ok:true,json:async()=>context.imported})});
 const source=fs.readFileSync(__dirname+'/ui/app.js','utf8');vm.runInContext(source.slice(0,source.lastIndexOf('setMode();loadProfiles();poll();')),context);
 return{el,context,run:code=>vm.runInContext(code,context)};
}
test('VLESS and Trojan editor edits survive save without dropping unknown query options',async()=>{
 for(const protocol of ['vless','trojan']){
  const{el,context,run}=fixture();el('mode').value='xray';el('link').value=protocol+'://secret@example.com:443?type=xhttp&security=tls&unknown=preserve&sni=original.example';
  context.imported={Protocol:protocol,Address:'example.com',Port:443,Network:'xhttp',Security:'tls',Host:'old.example',Path:'/old',XHTTPMode:'auto'};
  await run('readProfile()');assert.equal(el('wsDetails').hidden,false);assert.equal(el('grpcOptions').hidden,true);assert.equal(el('xhttpExtraOptions').hidden,false);
  el('wsHost').value='new.example';el('wsHost').input();el('wsPath').value='/new path';el('xhttpMode').value='stream-up';el('xhttpExtra').value='{"scMaxEachPostBytes":20000}';
  const saved=new URL(run('exportLink()'));assert.equal(saved.searchParams.get('host'),'new.example');assert.equal(saved.searchParams.get('path'),'/new path');assert.equal(saved.searchParams.get('unknown'),'preserve');assert.equal(saved.searchParams.get('sni'),'original.example');assert.equal(saved.searchParams.get('mode'),'stream-up');assert.equal(JSON.parse(saved.searchParams.get('extra')).scMaxEachPostBytes,20000);
  el('xhttpExtra').value='[]';assert.throws(()=>run('exportLink()'),/object/);
 }
});
test('observed SSH key requires explicit verification and matching server before filling; never autosaves',()=>{
 const{el,run}=fixture();el('mode').value='ssh';el('host').value='example.com';el('sshPort').value='444';
 run('latestStatus={connection:{sshAuthenticated:true,sshHost:"example.com",sshPort:444,sshFingerprint:"SHA256:first",sshTrust:"session_only",tlsTrust:"session_unverified"}};refreshTrust()');
 assert.equal(el('observedKeyPanel').hidden,false);assert.equal(el('useObservedKey').disabled,true);el('useObservedKey').onclick();assert.equal(el('hostKey').value,'');
 el('verifiedObservedKey').checked=true;el('verifiedObservedKey').onchange();assert.equal(el('useObservedKey').disabled,false);el('useObservedKey').onclick();assert.equal(el('hostKey').value,'SHA256:first');assert.equal(el('sshTOFU').checked,false);assert.match(el('error').textContent,/Save this profile/);
 run('latestStatus.connection.sshFingerprint="SHA256:changed";refreshTrust()');assert.equal(el('verifiedObservedKey').checked,false);assert.equal(el('useObservedKey').disabled,true);
 el('host').value='different.example';el('host').input();assert.equal(el('observedKeyPanel').hidden,true);assert.equal(el('useObservedKey').disabled,true);
});
test('custom TUN editor values replace old flags and restore on reopening',()=>{
 const{el,context,run}=fixture();context.saved=['-mode','ssh','-H','example.com','-tun-address4','10.83.0.1/30','-tun-address6','fd23:4567::1/126','-tun-stack','gvisor','-tun-mtu','1400'];run('applyArgs(saved)');assert.equal(el('tunAddress4').value,'10.83.0.1/30');assert.equal(el('tunStack').value,'gvisor');
 el('tunStack').value='system';const args=run('args()');assert.equal(args.filter(f=>f==='-tun-stack').length,1);assert.equal(args[args.indexOf('-tun-stack')+1],'system');assert.equal(args[args.indexOf('-tun-mtu')+1],'1400');
});
