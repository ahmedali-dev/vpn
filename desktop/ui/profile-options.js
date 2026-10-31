'use strict';
(function(root){
 const boolFlags=new Set(['-tun','-auto-route','-ssh-trust-on-first-use','-ssh-trust-on-first-use=false','-ssh-ipv4-only','-block-quic','-block-quic=false','-bypass-lan']);
 function pairs(args){const out=[];for(let i=0;i<args.length;i++){const flag=args[i];out.push([flag,...((boolFlags.has(flag)||boolFlags.has(flag.split('=')[0]))?[]:[args[++i]??''])]);}return out;}
 function normalize(args){return pairs(args).map(([flag,...values])=>[flag==='-auto-route'?'-tun':flag==='-auto-route=false'?'-tun=false':flag,...values]).flat();}
 const editorFlags=new Set(['-ssh-trust-on-first-use','-ssh-trust-on-first-use=false','-ssh-ipv4-only','-block-quic','-block-quic=false','-mode','-H','-P','-u','-p','-S','-ssh-cert-sha256','-ssh-host-key','-ssh-known-hosts','-tls-ca','-proxy','-payload-file','-payload-stage','-v2ray-link','-v2ray-sni','-v2ray-cert-sha256','-socks-port','-pac-port','-tun','-v2ray-binary','-tun-binary','-tls-version','-health-timeout','-routing-rules','-bypass-lan','-tun-address4','-tun-address6','-tun-stack','-tun-mtu']);
 function merge(original,edited){
  original=normalize(original);edited=normalize(edited);
  const oldMode=pairs(original).find(p=>p[0]==='-mode')?.[1]||'ssh';
  const newMode=pairs(edited).find(p=>p[0]==='-mode')?.[1]||'ssh';
  const keep=pairs(original).filter(([flag])=>!editorFlags.has(flag)&&!editorFlags.has(flag.split('=')[0])&&!(oldMode!==newMode&&(flag.startsWith('-v2ray-')||flag.startsWith('-ssh-'))));
  return [...keep.flat(),...edited];
 }
 function withRouting(original,enabled){const result=pairs(normalize(original)).filter(([flag])=>flag.split('=')[0]!=='-tun').flat();return enabled?[...result,'-tun']:result;}
 function withSessionTrustDefault(original){
  const result=normalize(original),items=pairs(result),mode=items.find(p=>p[0]==='-mode')?.[1]||'ssh';
  const explicit=items.some(([flag])=>flag==='-ssh-trust-on-first-use'||flag==='-ssh-trust-on-first-use=false');
  const verified=items.some(([flag,value])=>(flag==='-ssh-host-key'||flag==='-ssh-known-hosts')&&String(value||'').trim());
  return mode==='ssh'&&!explicit&&!verified?[...result,'-ssh-trust-on-first-use']:result;
 }
 function routeRules(text){
  const lines=text.split(/\r?\n/).map(s=>s.trim()).filter(s=>s&&!s.startsWith('#'));
  if(lines.length>64)throw new Error('Use at most 64 routing rules.');
  return lines.map((line,index)=>{const match=/^(direct|proxy|block)\s+(domain|ip|process)\s+(.+)$/.exec(line);if(!match)throw new Error('Rule '+(index+1)+': use direct, proxy or block; then domain, ip or process; then its value.');return{action:match[1],kind:match[2],value:match[3]};});
 }
 function routesText(rules){return rules.map(r=>r.action+' '+r.kind+' '+r.value).join('\n');}
 function rewriteLink(link,fields){
  if(link.startsWith('vmess://')){
   const encoded=link.slice(8).replace(/-/g,'+').replace(/_/g,'/');
   const data=JSON.parse(new TextDecoder().decode(Uint8Array.from(atob(encoded),c=>c.charCodeAt(0))));
   Object.assign(data,fields);
   return 'vmess://'+btoa(Array.from(new TextEncoder().encode(JSON.stringify(data)),b=>String.fromCharCode(b)).join(''));
  }
  const url=new URL(link);
  if(!['vless:','trojan:'].includes(url.protocol))return link;
  for(const [key,value] of Object.entries(fields)){
   if(!['host','path','serviceName','mode','extra','spx'].includes(key))continue;
   if(value===''||value===null)url.searchParams.delete(key);else url.searchParams.set(key,typeof value==='object'?JSON.stringify(value):value);
  }
  return url.toString();
 }
 const api={normalize,merge,withRouting,withSessionTrustDefault,routeRules,routesText,rewriteLink};if(typeof module==='object')module.exports=api;else root.TunnelNestProfileOptions=api;
})(typeof globalThis==='object'?globalThis:this);
