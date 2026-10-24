'use strict';
const test=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const vm=require('node:vm');
const source=fs.readFileSync(__dirname+'/ui/app.js','utf8').split('\nfunction setMode()')[0];
function page({hash='',storage=new Map(),fetch=async()=>({ok:true,status:200,json:async()=>({ok:true})}),blocked=false}={}){
 const location={hash,pathname:'/',search:''};
 const context=vm.createContext({document:{},location,history:{replaceState(_state,_title,url){location.hash='';location.url=url}},sessionStorage:{setItem(k,v){if(blocked)throw Error('blocked');storage.set(k,v)},getItem(k){return storage.get(k)},removeItem(k){storage.delete(k)}},fetch});
 vm.runInContext(source,context);
 return {context,location,storage,api:()=>vm.runInContext("api('status')",context)};
}
test('control token survives reload and a new URL replaces the saved session',async()=>{
 const storage=new Map();let sent;
 const fetch=async(_url,request)=>{sent=request.headers['X-Tunnel-Token'];return {ok:true,status:200,json:async()=>({ok:true})}};
 const first=page({hash:'#first-session',storage,fetch});await first.api();assert.equal(sent,'first-session');assert.equal(first.location.hash,'#first-session');
 await page({storage,fetch}).api();assert.equal(sent,'first-session');
 await page({hash:'#new-session',storage,fetch}).api();assert.equal(sent,'new-session');
});
test('missing and expired sessions explain how to reconnect without JSON parsing errors',async()=>{
 let fetched=false;await assert.rejects(page({fetch:async()=>{fetched=true}}).api(),/complete CONTROL_URL/);assert.equal(fetched,false);
 const current=page({hash:'#expired',fetch:async()=>({ok:false,status:401,json:async()=>{throw SyntaxError('Unexpected token')}})});
 await assert.rejects(current.api(),/session expired/);assert.equal(current.storage.size,0);
 await assert.rejects(current.api(),/session is missing/);
});
test('plain-text errors are handled and blocked storage keeps the fragment',async()=>{
 const current=page({hash:'#session',blocked:true,fetch:async()=>({ok:false,status:403,json:async()=>{throw SyntaxError('Unexpected token')}})});
 assert.equal(current.location.hash,'#session');await assert.rejects(current.api(),/HTTP 403/);
});

test('reload works when the browser discards all session storage',async()=>{
 const first=page({hash:'#persistent-fragment'});await first.api();
 let sent;const second=page({hash:first.location.hash,storage:new Map(),fetch:async(_url,request)=>{sent=request.headers['X-Tunnel-Token'];return {ok:true,status:200,json:async()=>({ok:true})}}});
 await second.api();assert.equal(sent,'persistent-fragment');
});
