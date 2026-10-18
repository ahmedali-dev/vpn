'use strict';
const {test}=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const os=require('node:os');
const path=require('node:path');
const {createStartupLogger,checkBundle}=require('./startup.cjs');
test('missing engine identifies incomplete extraction',()=>{assert.throws(()=>checkBundle(path.join(os.tmpdir(),'missing-tunnel-runtime'),'win32'),/Extract the entire ZIP/)});
test('startup logs redact local control token',t=>{const dir=fs.mkdtempSync(path.join(os.tmpdir(),'tunnel-log-test-'));t.after(()=>fs.rmSync(dir,{recursive:true,force:true}));const logger=createStartupLogger(dir);const token='a'.repeat(64);logger.log('CONTROL_URL=http://127.0.0.1:12345/#'+token);const data=fs.readFileSync(logger.filename,'utf8');assert.ok(!data.includes(token));assert.match(data,/redacted/)});
