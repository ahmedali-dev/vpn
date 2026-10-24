'use strict';
(function(root){
 const boolFlags=new Set(['-tun','-auto-route','-ssh-trust-on-first-use','-ssh-ipv4-only']);
 function pairs(args){const out=[];for(let i=0;i<args.length;i++){const flag=args[i];out.push([flag,...(boolFlags.has(flag)?[]:[args[++i]??''])]);}return out;}
 function normalize(args){return pairs(args).map(([flag,...values])=>[flag==='-auto-route'?'-tun':flag,...values]).flat();}
 const editorFlags=new Set(['-ssh-trust-on-first-use','-ssh-ipv4-only','-mode','-H','-P','-u','-p','-S','-ssh-cert-sha256','-ssh-host-key','-ssh-known-hosts','-tls-ca','-proxy','-payload-file','-payload-stage','-v2ray-link','-v2ray-sni','-v2ray-cert-sha256','-socks-port','-pac-port','-tun','-v2ray-binary','-tun-binary','-tls-version']);
 function merge(original,edited){
  original=normalize(original);edited=normalize(edited);
  const oldMode=pairs(original).find(p=>p[0]==='-mode')?.[1]||'ssh';
  const newMode=pairs(edited).find(p=>p[0]==='-mode')?.[1]||'ssh';
  const keep=pairs(original).filter(([flag])=>!editorFlags.has(flag)&&!(oldMode!==newMode&&(flag.startsWith('-v2ray-')||flag.startsWith('-ssh-'))));
  return [...keep.flat(),...edited];
 }
 const api={normalize,merge};if(typeof module==='object')module.exports=api;else root.TunnelNestProfileOptions=api;
})(typeof globalThis==='object'?globalThis:this);
