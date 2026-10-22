#!/usr/bin/env python3
"""Import CI-provided signing material into temporary locations; never print secrets."""
import base64, os, pathlib, secrets, subprocess
folder=pathlib.Path(os.environ.get('RUNNER_TEMP','/tmp'))/'tunnelnest-signing'
folder.mkdir(mode=0o700,parents=True,exist_ok=True)
def export(name,value):
 if '\n' in str(value) or '\r' in str(value): raise ValueError('Invalid signing environment value')
 with open(os.environ['GITHUB_ENV'],'a') as stream:stream.write(name+'='+str(value)+'\n')
def decode(name,filename):
 path=folder/filename;path.write_bytes(base64.b64decode(os.environ[name],validate=True));path.chmod(0o600);return path
if os.environ['TUNNEL_PACKAGE_TARGET'].startswith('darwin') and os.environ.get('MAC_CERT_P12_B64'):
 cert=decode('MAC_CERT_P12_B64','signing.p12');api=decode('APPLE_API_KEY_B64','notary.p8')
 keychain=folder/'build.keychain-db';password=secrets.token_urlsafe(32)
 for args in (['create-keychain','-p',password,str(keychain)],['set-keychain-settings','-lut','21600',str(keychain)],['unlock-keychain','-p',password,str(keychain)],['import',str(cert),'-k',str(keychain),'-P',os.environ['MAC_CERT_PASSWORD'],'-T','/usr/bin/codesign'],['set-key-partition-list','-S','apple-tool:,apple:','-s','-k',password,str(keychain)],['list-keychains','-d','user','-s',str(keychain)]):
  subprocess.run(['security',*args],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
 export('APPLE_API_KEY_PATH',api)
 for name in ('MAC_SIGN_IDENTITY','APPLE_API_KEY_ID','APPLE_API_ISSUER'):export(name,os.environ[name])
if os.environ['TUNNEL_PACKAGE_TARGET'].startswith('win32') and os.environ.get('WIN_CERT_PFX_B64'):
 export('WIN_CERT_PATH',decode('WIN_CERT_PFX_B64','signing.pfx'))
 export('WIN_CERT_PASSWORD',os.environ['WIN_CERT_PASSWORD'])
