'use strict';
const test=require('node:test'),assert=require('node:assert/strict');const {signingOptions}=require('./signing.cjs');
test('production signing fails closed for missing or partial credentials',()=>{
 assert.throws(()=>signingOptions('darwin',{TUNNEL_REQUIRE_SIGNING:'1'}),/required/);
 assert.throws(()=>signingOptions('darwin',{MAC_SIGN_IDENTITY:'identity'}),/Incomplete/);
 assert.throws(()=>signingOptions('win32',{TUNNEL_REQUIRE_SIGNING:'1'}),/required/);
 assert.deepEqual(signingOptions('linux',{TUNNEL_REQUIRE_SIGNING:'1'}),{});
});
test('macOS requires notarization together with hardened signing',()=>{
 const options=signingOptions('darwin',{MAC_SIGN_IDENTITY:'identity',APPLE_API_KEY_PATH:'/private/key.p8',APPLE_API_KEY_ID:'id',APPLE_API_ISSUER:'issuer'});
 assert.equal(options.osxSign.hardenedRuntime,true);assert.equal(options.osxSign.continueOnError,false);assert.equal(options.osxNotarize.appleApiKey,'/private/key.p8');
});
