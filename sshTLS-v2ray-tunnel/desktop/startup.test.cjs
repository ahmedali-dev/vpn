'use strict';
const {test}=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const os=require('node:os');
const path=require('node:path');
const {createStartupLogger,checkBundle}=require('./startup.cjs');
test('missing engine identifies incomplete extraction',()=>{assert.throws(()=>checkBundle(path.join(os.tmpdir(),'missing-tunnel-runtime'),'win32'),/Extract the entire ZIP/)});
test('startup logs redact local control token',t=>{const dir=fs.mkdtempSync(path.join(os.tmpdir(),'tunnel-log-test-'));t.after(()=>fs.rmSync(dir,{recursive:true,force:true}));const logger=createStartupLogger(dir);const token='a'.repeat(64);logger.log('CONTROL_URL=http://127.0.0.1:12345/#'+token);const data=fs.readFileSync(logger.filename,'utf8');assert.ok(!data.includes(token));assert.match(data,/redacted/)});

test('privileged connections preserve configured native core paths',()=>{
 const {connectionCoreArgs}=require('./startup.cjs');
 const args=['-mode','ssh','-tun','-tun-binary','/usr/bin/sing-box'];
 assert.deepEqual(connectionCoreArgs(args,'/bundled/linux-x64','linux'),args);
 const ray=['-mode','xray','-tun','-tun-binary','/native/sing-box','-v2ray-binary','/native/xray'];
 assert.deepEqual(connectionCoreArgs(ray,'/bundled/linux-x64','linux'),ray);
});
test('privileged connections default to cores in the matching runtime',()=>{
 const {connectionCoreArgs}=require('./startup.cjs');
 const args=['-mode','xray','-tun'];
 const actual=connectionCoreArgs(args,'/runtime/linux-arm64','linux');
 assert.deepEqual(args,['-mode','xray','-tun']);
 assert.equal(actual[actual.indexOf('-tun-binary')+1],path.join('/runtime/linux-arm64','cores','sing-box'));
 assert.equal(actual[actual.indexOf('-v2ray-binary')+1],path.join('/runtime/linux-arm64','cores','xray'));
});
