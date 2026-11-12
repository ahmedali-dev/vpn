const test = require('node:test'), assert = require('node:assert/strict'), vm = require('node:vm'), fs = require('node:fs');
function fixture({accept = true, error} = {}) {
  const nodes = new Map(), calls = [];
  const el = id => {
    if (!nodes.has(id)) nodes.set(id, {
      value:'', disabled:false, textContent:'', dataset:{}, hidden:true,
      showModal() {
        this.open = true;
        if (id === 'cloudConfirmDialog') queueMicrotask(() => el(accept ? 'acceptCloudAction' : 'cancelCloudAction').onclick());
      },
      close() { this.open = false; this.onclose?.(); },
    });
    return nodes.get(id);
  };
  const context = vm.createContext({$:el, loadProfiles:async()=>{}, api:async(path,body)=>{
    calls.push({path,body});
    if(path==='cloud/status') return {connected:true,url:'https://cloud.example.com'};
    if(error) throw error;
    if(path==='cloud/refresh') return {synced:2,conflicts:1,invalid:0};
    return {};
  }});
  vm.runInContext(fs.readFileSync(__dirname+'/ui/features/cloud.js','utf8'),context);
  return {el,calls,context,run:s=>vm.runInContext(s,context)};
}
test('upload uses app confirmation and shows persistent success', async()=>{
  const f=fixture(); await f.run('uploadCloud({id:4,name:"Test"})');
  assert.equal(f.calls[1].path,'cloud/upload'); assert.equal(f.calls[1].body.id,4);
  assert.equal(f.el('operationFeedback').hidden,false); assert.equal(f.el('operationFeedback').dataset.kind,'success');
  assert.match(f.el('operationFeedbackText').textContent,/published/);
});
test('refresh reports local conflicts without starting a VPN',async()=>{
  const f=fixture(); await f.el('refreshCloud').onclick();
  assert.deepEqual(f.calls.map(c=>c.path),['cloud/status','cloud/refresh']);
  assert.match(f.el('operationFeedbackText').textContent,/1 local edits kept/);
});
test('cloud connect sends URL only',async()=>{
  const f=fixture(); await f.el('cloudConnect').onclick();
  assert.equal(f.calls[0].path,'cloud/connect'); assert.deepEqual(Object.keys(f.calls[0].body),['url']);
});
test('cloud delete retains local profile and shows success',async()=>{
  const f=fixture(); await f.run('deleteCloud({id:4,name:"Public"})');
  assert.equal(f.calls[1].path,'cloud/delete'); assert.equal(f.calls[1].body.id,4);
  assert.match(f.el('operationFeedbackText').textContent,/Local profile kept/);
});
test('cancelled upload and delete never mutate the cloud',async()=>{
  const f=fixture({accept:false}); await f.run('uploadCloud({id:4,name:"Test"})');
  await f.run('deleteCloud({id:4,name:"Test"})');
  assert.deepEqual(f.calls.map(c=>c.path),['cloud/status','cloud/status']);
  assert.match(f.el('operationFeedbackText').textContent,/cancelled/);
});
test('upload and delete failures remain visible and controls recover',async()=>{
  for(const error of [Error('HTTP 403: rejected origin'),'HTTP 503: unavailable']) {
    const f=fixture({error}); await f.run('uploadCloud({id:4,name:"Test"})');
    assert.equal(f.el('operationFeedback').dataset.kind,'error');
    assert.match(f.el('operationFeedbackText').textContent,/Cloud action failed: HTTP/);
    assert.equal(f.el('refreshCloud').disabled,false);
    await f.run('deleteCloud({id:4,name:"Test"})');
    assert.match(f.el('operationFeedbackText').textContent,/Cloud action failed: HTTP/);
  }
});
test('locked profile explains the problem without a network request',async()=>{
  const f=fixture(); await f.run('uploadCloud({id:4,name:"Locked",locked:true})');
  assert.equal(f.calls.length,0); assert.equal(f.el('operationFeedback').dataset.kind,'error');
  assert.match(f.el('operationFeedbackText').textContent,/Unlock/);
});
test('feedback is not stored in the connection status area and can be dismissed',async()=>{
  const f=fixture(); await f.run('uploadCloud({id:4,name:"Test"})');
  f.el('pageError').textContent='Connection polling error';
  assert.match(f.el('operationFeedbackText').textContent,/published/);
  f.el('dismissOperationFeedback').onclick(); assert.equal(f.el('operationFeedback').hidden,true);
});
