'use strict';
(function(root){
 const boolFlags=new Set(['-tun','-auto-route','-ssh-trust-on-first-use','-ssh-trust-on-first-use=false','-ssh-ipv4-only','-block-quic','-block-quic=false']);
 function pairs(args){const out=[];for(let i=0;i<args.length;i++){const flag=args[i];out.push([flag,...(boolFlags.has(flag)?[]:[args[++i]??''])]);}return out;}
 function normalize(args){return pairs(args).map(([flag,...values])=>[flag==='-auto-route'?'-tun':flag,...values]).flat();}
 const editorFlags=new Set(['-ssh-trust-on-first-use','-ssh-trust-on-first-use=false','-ssh-ipv4-only','-block-quic','-block-quic=false','-mode','-H','-P','-u','-p','-S','-ssh-cert-sha256','-ssh-host-key','-ssh-known-hosts','-tls-ca','-proxy','-payload-file','-payload-stage','-v2ray-link','-v2ray-sni','-v2ray-cert-sha256','-socks-port','-pac-port','-tun','-v2ray-binary','-tun-binary','-tls-version','-health-timeout']);
 function merge(original,edited){
  original=normalize(original);edited=normalize(edited);
  const oldMode=pairs(original).find(p=>p[0]==='-mode')?.[1]||'ssh';
  const newMode=pairs(edited).find(p=>p[0]==='-mode')?.[1]||'ssh';
  const keep=pairs(original).filter(([flag])=>!editorFlags.has(flag)&&!(oldMode!==newMode&&(flag.startsWith('-v2ray-')||flag.startsWith('-ssh-'))));
  return [...keep.flat(),...edited];
 }
 function withRouting(original,enabled){const result=pairs(normalize(original)).filter(([flag])=>flag!=='-tun').flat();return enabled?[...result,'-tun']:result;}
 function withSessionTrustDefault(original){
  const result=normalize(original),items=pairs(result),mode=items.find(p=>p[0]==='-mode')?.[1]||'ssh';
  const explicit=items.some(([flag])=>flag==='-ssh-trust-on-first-use'||flag==='-ssh-trust-on-first-use=false');
  const verified=items.some(([flag,value])=>(flag==='-ssh-host-key'||flag==='-ssh-known-hosts')&&String(value||'').trim());
  return mode==='ssh'&&!explicit&&!verified?[...result,'-ssh-trust-on-first-use']:result;
 }
 const api={normalize,merge,withRouting,withSessionTrustDefault};if(typeof module==='object')module.exports=api;else root.TunnelNestProfileOptions=api;
})(typeof globalThis==='object'?globalThis:this);
