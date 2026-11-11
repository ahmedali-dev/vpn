"use strict";
const test=require('node:test'),assert=require('node:assert/strict'),vm=require('node:vm'),fs=require('node:fs');
function fixture(){
 const elements=new Map();const el=id=>{if(!elements.has(id))elements.set(id,{value:'',checked:false,disabled:false,hidden:false,textContent:'',children:[],showModal(){this.open=true},close(){this.open=false},replaceChildren(){this.children=[]},append(...c){this.children.push(...c)}});return elements.get(id)};
 const calls=[];const context=vm.createContext({document:{createElement:()=>({append(){}})},$:el,confirm:()=>false,loadProfiles:async()=>{},api:async(path,body)=>{calls.push({path,body});if(context.error)throw Error(context.error);return context.result||{};}});
 for(const file of ['updates'])vm.runInContext(fs.readFileSync(`${__dirname}/ui/features/${file}.js`,'utf8'),context);
 return {el,context,calls,run:code=>vm.runInContext(code,context)};
}
test('update check is manual and notes remain plain text',async()=>{const f=fixture();assert.equal(f.calls.length,0);f.context.result={currentVersion:'1.3.8',latestVersion:'1.4.0',tag:'rust-v1.4.0',updateAvailable:true,notes:'<script>evil()</script>'};await f.el('checkUpdates').onclick();assert.equal(f.el('updateNotes').textContent,'<script>evil()</script>');await f.el('openRelease').onclick();assert.equal(f.calls[1].body.tag,'rust-v1.4.0');f.context.error='offline';await f.el('retryUpdates').onclick();assert.equal(f.el('openRelease').hidden,true);assert.equal(f.el('retryUpdates').disabled,false);});
