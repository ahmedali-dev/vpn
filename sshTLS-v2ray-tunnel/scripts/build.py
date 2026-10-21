#!/usr/bin/env python3
"""Cross-compile all engines; fetch cores separately with fetch-cores.py."""
import concurrent.futures, os, pathlib, shutil, subprocess
ROOT=pathlib.Path(__file__).resolve().parents[1]
TARGETS={'win32-x64':('windows','amd64'),'linux-x64':('linux','amd64'),'linux-arm64':('linux','arm64'),'darwin-arm64':('darwin','arm64'),'darwin-x64':('darwin','amd64')}
def build(item):
 name,(system,arch)=item
 folder=ROOT/'dist/runtime'/name;folder.mkdir(parents=True,exist_ok=True)
 binary=folder/('tunnel.exe' if system=='windows' else 'tunnel')
 env=os.environ.copy();env.update(GOOS=system,GOARCH=arch,CGO_ENABLED='0',GOTOOLCHAIN='local')
 subprocess.run(['go','build','-trimpath','-ldflags=-s -w','-o',str(binary),'.'],cwd=ROOT,env=env,check=True)
 licenses=folder/'licenses';licenses.mkdir(exist_ok=True)
 for license_file in (ROOT/'desktop/assets').glob('LICENSE-*.txt'): shutil.copy2(license_file,licenses/license_file.name)
 print('Built',name,flush=True)
if __name__=='__main__':
 target=os.environ.get('TUNNEL_PACKAGE_TARGET')
 if target:
  if target not in TARGETS: raise SystemExit('Unsupported target: '+target)
  TARGETS={target:TARGETS[target]}
 with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:list(pool.map(build,TARGETS.items()))
