'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');

test('switching VMess links and profiles clears old SNI overrides', async () => {
  const elements = new Map();
  const element = id => {
    if (!elements.has(id)) elements.set(id, {value:'', textContent:'', hidden:false,
      addEventListener(name, callback) { this[name] = callback; },
      reset() {}, append(){}, dispatchEvent() {}, classList:{add(){}, remove(){}, toggle(){}}});
    return elements.get(id);
  };
  const context = vm.createContext({document:{getElementById:element,querySelectorAll:()=>[],addEventListener(){},querySelector:()=>element('connectionView')}, location:{hash:'#test',pathname:'/'},
    history:{replaceState(){}}, TextDecoder, TextEncoder, atob, btoa, Event:class {}, setTimeout(){},clearTimeout(){},
    fetch:async (_url, request) => {
      const {link} = JSON.parse(request.body);
      const data = JSON.parse(Buffer.from(link.slice(8),'base64').toString());
      return {ok:true,json:async()=>({Protocol:'vmess',Address:data.add,Port:+data.port,Network:data.net,
        Host:data.host || '',Path:data.path,SNISource:data.sni?'link':data.host?'host':'server',SNI:data.sni || data.host || data.add})};
    }});
  const source = fs.readFileSync(__dirname+'/ui/app.js','utf8');
  vm.runInContext(source.slice(0, source.lastIndexOf('setMode();loadProfiles();poll();')),context);
  const link = host => 'vmess://'+Buffer.from(JSON.stringify({add:host?'us-23.hihu.net':'fr2.vpnjantit.com',
    host:host?'web.whatsapp.com':'',port:host?'443':'8080',net:'ws',path:host?'/wovfpasr':'/vpnjantit'})).toString('base64');
  element('mode').value='xray';
  element('link').value=link(true);
  await vm.runInContext('readProfile()',context);
  assert.equal(element('sni').value,'web.whatsapp.com');
  assert.equal(element('wsHost').value,'web.whatsapp.com');
  assert.equal(vm.runInContext('args().includes("-v2ray-sni")',context),false);
  element('sni').value='manual.example.com';
  element('link').value=link(false);
  element('link').input();
  await vm.runInContext('readProfile()',context);
  assert.equal(element('sni').value,'');
  assert.match(element('profile').textContent,/No SNI in link/);
  assert.equal(element('sni').placeholder,'Automatic: fr2.vpnjantit.com');
  assert.equal(element('wsHost').value,'');
  assert.equal(element('wsPath').value,'/vpnjantit');
  context.savedArgs=['-mode','xray','-v2ray-link',link(true)];
  vm.runInContext('applyArgs(savedArgs)',context);
  await new Promise(resolve=>setImmediate(resolve));
  assert.equal(element('sni').value,'web.whatsapp.com');
  context.savedArgs=['-mode','xray','-v2ray-link',link(false),'-v2ray-sni','explicit.example.com'];
  vm.runInContext('applyArgs(savedArgs)',context);
  await new Promise(resolve=>setImmediate(resolve));
  assert.equal(element('sni').value,'explicit.example.com');
  assert.equal(vm.runInContext('args().includes("-v2ray-sni")',context),true);
  context.savedArgs=['-mode','xray','-v2ray-link',link(false),'-tun','-v2ray-binary','/custom/xray','-tun-binary','/custom/sing-box','-tls-version','tls1.2'];
  vm.runInContext('applyArgs(savedArgs)',context);
  await new Promise(resolve=>setImmediate(resolve));
  assert.equal(element('tun').checked,true);
  assert.equal(element('corePath').value,'/custom/xray');
  assert.equal(element('tunPath').value,'/custom/sing-box');
  assert.equal(element('tlsVersion').value,'tls1.2');
  element('vmessAddress').value='edited.example.com';
  element('vmessPort').value='8443';
  element('vmessUUID').value='preview-id';
  element('vmessNetwork').value='ws';
  element('vmessTLS').value='tls';
  vm.runInContext('vmessDirty=true',context);
  const exported=vm.runInContext('exportLink()',context);
  const decoded=JSON.parse(Buffer.from(exported.slice(8),'base64').toString());
  assert.equal(decoded.add,'edited.example.com');
  assert.equal(decoded.port,'8443');
  assert.equal(decoded.host,'');
  assert.equal(decoded.sni,'');

});
