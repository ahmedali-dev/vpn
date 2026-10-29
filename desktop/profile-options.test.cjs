'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const {merge,normalize}=require('./ui/profile-options.js');
test('profile editor retains routing aliases and unsupported configuration values',()=>{
 const original=['-mode','ssh','-auto-route','-max-conns','5','-H','before.example'];
 const normalized=normalize(original);
 const result=merge(normalized,['-mode','ssh','-tun','-H','after.example']);
 assert.deepEqual(result,['-max-conns','5','-mode','ssh','-tun','-H','after.example']);
 assert.deepEqual(original,['-mode','ssh','-auto-route','-max-conns','5','-H','before.example']);
});
test('manual protocol fields survive editing without a share link',()=>{
 const result=merge(['-mode','xray','-v2ray-addr','example.com','-v2ray-uuid','secret','-v2ray-protocol','vless'],['-mode','xray','-socks-port','1082']);
 assert.ok(result.includes('-v2ray-uuid'));assert.ok(result.includes('-v2ray-addr'));
 assert.ok(!merge(result,['-mode','ssh']).includes('-v2ray-uuid'));
});

test('quick routing overrides preserve arguments and do not rewrite saved profiles',()=>{
 const {withRouting}=require('./ui/profile-options.js');
 const original=['-mode','ssh','-p','-tun','-auto-route','-max-conns','5'];
 assert.deepEqual(withRouting(original,false),['-mode','ssh','-p','-tun','-max-conns','5']);
 assert.deepEqual(withRouting(original,true),['-mode','ssh','-p','-tun','-max-conns','5','-tun']);
 assert.deepEqual(original,['-mode','ssh','-p','-tun','-auto-route','-max-conns','5']);
});


test('automatic session trust preserves explicit identities and strict opt-outs',()=>{
 const {withSessionTrustDefault}=require('./ui/profile-options.js');
 const original=['-mode','ssh','-H','example.invalid'];
 assert.ok(withSessionTrustDefault(original).includes('-ssh-trust-on-first-use'));
 assert.ok(!original.includes('-ssh-trust-on-first-use'));
 for(const policy of [['-ssh-host-key','SHA256:verified'],['-ssh-known-hosts','/sample/known_hosts'],['-ssh-trust-on-first-use=false']]){
  const profile=[...original,...policy];assert.deepEqual(withSessionTrustDefault(profile),profile);
 }
 const ray=['-mode','xray','-v2ray-link','vmess://example'];assert.deepEqual(withSessionTrustDefault(ray),ray);
 const edited=merge([...original,'-ssh-trust-on-first-use'],[...original,'-ssh-trust-on-first-use=false','-p','secret']);
 assert.ok(!edited.includes('-ssh-trust-on-first-use'));assert.equal(edited[edited.indexOf('-p')+1],'secret');
});

test('explicit false routing flags do not consume the next editor option',()=>{
 const options=require('./ui/profile-options.js');
 assert.deepEqual(options.withRouting(['-mode','ssh','-auto-route=false','-health-timeout','35'],true),['-mode','ssh','-health-timeout','35','-tun']);
 assert.deepEqual(options.withRouting(['-mode','ssh','-tun=false','-health-timeout','35'],false),['-mode','ssh','-health-timeout','35']);
});

test('ordered routing text roundtrips without exposing arbitrary core JSON',()=>{
 const options=require('./ui/profile-options.js');const text='direct domain example.com\nblock ip 192.0.2.1/32\nproxy process Firefox Helper';
 assert.equal(options.routesText(options.routeRules(text)),text);
 assert.throws(()=>options.routeRules('direct all everything'),/Rule 1/);
 assert.throws(()=>options.routeRules(Array(65).fill('proxy domain example.com').join('\n')),/64/);
 const merged=options.merge(['-mode','ssh','-bypass-lan','-routing-rules','[]'],['-mode','ssh']);assert.deepEqual(merged,['-mode','ssh']);
});
