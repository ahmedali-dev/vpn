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
