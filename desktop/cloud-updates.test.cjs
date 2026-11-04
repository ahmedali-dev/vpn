"use strict";
const test=require('node:test'),assert=require('node:assert/strict'),vm=require('node:vm'),fs=require('node:fs');
function fixture(){
 const elements=new Map();const el=id=>{if(!elements.has(id))elements.set(id,{value:'',checked:false,disabled:false,hidden:false,textContent:'',children:[],showModal(){this.open=true},close(){this.open=false},replaceChildren(){this.children=[]},append(...c){this.children.push(...c)}});return elements.get(id)};
 const calls=[];const context=vm.createContext({document:{createElement:()=>({append(){}})},$:el,confirm:()=>false,loadProfiles:async()=>{},api:async(path,body)=>{calls.push({path,body});if(context.error)throw Error(context.error);return context.result||{};}});
 for(const file of ['updates','cloud-library'])vm.runInContext(fs.readFileSync(`${__dirname}/ui/features/${file}.js`,'utf8'),context);
 return {el,context,calls,run:code=>vm.runInContext(code,context)};
}
test('update check is manual and notes remain plain text',async()=>{const f=fixture();assert.equal(f.calls.length,0);f.context.result={currentVersion:'1.3.8',latestVersion:'1.4.0',tag:'rust-v1.4.0',updateAvailable:true,notes:'<script>evil()</script>'};await f.el('checkUpdates').onclick();assert.equal(f.el('updateNotes').textContent,'<script>evil()</script>');await f.el('openRelease').onclick();assert.equal(f.calls[1].body.tag,'rust-v1.4.0');f.context.error='offline';await f.el('retryUpdates').onclick();assert.equal(f.el('openRelease').hidden,true);assert.equal(f.el('retryUpdates').disabled,false);});
test('Mongo settings are session-only unless explicitly remembered and secret inputs clear on failure',async()=>{const f=fixture();assert.equal(f.calls.length,0);f.el('mongoURI').value='mongodb://secret';f.el('mongoPassphrase').value='secret passphrase';f.context.error='Cannot connect';await f.el('mongoConnect').onclick();assert.equal(f.calls[0].body.remember,false);assert.equal(f.el('mongoURI').value,'');assert.equal(f.el('mongoPassphrase').value,'');assert.equal(f.el('mongoConnect').disabled,false);});
test('failed remote saving explicitly preserves the local save',async()=>{const f=fixture();await assert.rejects(f.run('saveSelectedToMongo(10)'),/Profile saved locally/);f.run('mongoConnected=true');f.context.error='network failure';await assert.rejects(f.run('saveSelectedToMongo(10)'),/Profile saved locally; shared-library save failed/);assert.equal(f.calls[0].path,'mongo/save');assert.equal(f.calls[0].body.id,10);});

test('editor saves locally first and keeps the saved ID when MongoDB fails',async()=>{
 const elements=new Map();const el=id=>{if(!elements.has(id))elements.set(id,{value:'',checked:false,disabled:false,textContent:'',classList:{add(){},remove(){},toggle(){}},addEventListener(){},append(){}});return elements.get(id)};
 const calls=[];const context=vm.createContext({document:{getElementById:el,querySelectorAll:()=>[],addEventListener(){},querySelector:()=>null},location:{hash:'#test',pathname:'/'},history:{replaceState(){}},TextDecoder,TextEncoder,atob,btoa,URL,setTimeout(){},clearTimeout(){},TunnelNestProfileOptions:require('./ui/profile-options.js')});
 let source=require('./test-support/ui-source.cjs').applicationSource();vm.runInContext(source.slice(0,source.lastIndexOf('// START APPLICATION')),context);
 context.fakeApi=async(path,body)=>{calls.push({path,body});if(path==='profiles/save')return {id:42};if(path==='mongo/save')throw Error('offline');throw Error('Unexpected call');};
 vm.runInContext('api=fakeApi; args=()=>["-mode","ssh"]; loadProfiles=async()=>{}; showProfiles=()=>{throw Error("Editor must remain open")}; mongoConnected=true;',context);
 el('profileName').value='My connection';el('mode').value='ssh';el('rememberCredentials').checked=true;el('saveMongo').checked=true;
 await el('saveProfile').onclick();assert.deepEqual(calls.map(c=>c.path),['profiles/save','mongo/save']);assert.equal(vm.runInContext('currentProfileId',context),42);assert.match(el('error').textContent,/Profile saved locally/);assert.equal(el('saveProfile').disabled,false);
});
