#!/usr/bin/env python3
"""Sign nested/CLI networking executables when credentials are configured."""
import os, pathlib, subprocess, sys
root=pathlib.Path(__file__).resolve().parents[1]
target=os.environ['TUNNEL_PACKAGE_TARGET']
runtime=root/'dist/runtime'/target
required=os.environ.get('TUNNEL_REQUIRE_SIGNING')=='1'
if target.startswith('darwin'):
 identity=os.environ.get('MAC_SIGN_IDENTITY')
 if not identity:
  if required: raise SystemExit('Missing macOS signing identity')
  print('Unsigned development build');sys.exit(0)
 for path in (runtime/'tunnel',runtime/'cores/xray',runtime/'cores/sing-box'):
  subprocess.run(['codesign','--force','--timestamp','--options','runtime','--sign',identity,str(path)],check=True)
  subprocess.run(['codesign','--verify','--strict',str(path)],check=True)
elif target.startswith('win32'):
 cert=os.environ.get('WIN_CERT_PATH');password=os.environ.get('WIN_CERT_PASSWORD')
 if not cert or not password:
  if required: raise SystemExit('Missing Windows signing credentials')
  print('Unsigned development build');sys.exit(0)
 tool=os.environ.get('SIGNTOOL_PATH',str(root/'desktop/node_modules/@electron/windows-sign/vendor/signtool.exe'))
 for path in sorted(p for p in runtime.rglob('*') if p.suffix.lower() in ('.exe','.dll')):
  subprocess.run([tool,'sign','/fd','SHA256','/f',cert,'/p',password,'/tr','http://timestamp.digicert.com','/td','SHA256',str(path)],check=True)
