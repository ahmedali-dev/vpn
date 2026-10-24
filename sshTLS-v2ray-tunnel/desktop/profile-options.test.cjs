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
