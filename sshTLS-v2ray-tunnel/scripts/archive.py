#!/usr/bin/env python3
"""Refresh packaged engine resources and archive desktop/CLI deliverables."""
import hashlib, pathlib, shutil, subprocess, tarfile, zipfile
ROOT=pathlib.Path(__file__).resolve().parents[1]
TARGETS={'win32-x64':'windows-x64','linux-x64':'linux-x64','darwin-arm64':'macos-arm64','darwin-x64':'macos-x64'}
DOWNLOADS=ROOT/'dist/downloads';DOWNLOADS.mkdir(parents=True,exist_ok=True)
for key,label in TARGETS.items():
 folder=ROOT/'dist/desktop'/('Tunnel Desktop-'+key)
 resources=folder/'resources'
 if key.startswith('darwin'):resources=folder/'Tunnel Desktop.app/Contents/Resources'
 runtime=ROOT/'dist/runtime'/key
 destination=resources/key
 destination.mkdir(parents=True,exist_ok=True)
 # Packaging may have started before the final Go validation finished.
 binary='tunnel.exe' if key.startswith('win32') else 'tunnel'
 if not (destination/binary).exists() or hashlib.sha256((runtime/binary).read_bytes()).digest()!=hashlib.sha256((destination/binary).read_bytes()).digest():
  shutil.copy2(runtime/binary,destination/binary)
 shutil.copy2(ROOT/'README.md',folder/'README.md')
 if key.startswith('darwin'):
  output=DOWNLOADS/('TunnelDesktop-'+label+'.zip')
  subprocess.run(['ditto','-c','-k','--sequesterRsrc','--keepParent',str(folder),str(output)],check=True)
 elif key.startswith('linux'):
  output=DOWNLOADS/('TunnelDesktop-'+label+'.tar.gz')
  with tarfile.open(output,'w:gz') as archive:archive.add(folder,arcname=folder.name)
 else:
  output=DOWNLOADS/('TunnelDesktop-'+label+'.zip')
  with zipfile.ZipFile(output,'w',zipfile.ZIP_DEFLATED,compresslevel=6) as archive:
   for path in sorted(folder.rglob('*')):
    if path.is_file():archive.write(path,path.relative_to(folder.parent))
 print(output.name,output.stat().st_size,flush=True)
 # Small CLI bundle is also available for testing the engine independently.
 cli=DOWNLOADS/('TunnelCLI-'+label+'.zip')
 with zipfile.ZipFile(cli,'w',zipfile.ZIP_DEFLATED) as archive:
  for path in sorted(runtime.rglob('*')):
   if path.is_file():archive.write(path,pathlib.Path('TunnelCLI-'+label)/path.relative_to(runtime))
  archive.write(ROOT/'README.md',pathlib.Path('TunnelCLI-'+label)/'README.md')
lines=[]
for path in sorted(DOWNLOADS.iterdir()):
 if path.name=='SHA256SUMS.txt' or not path.is_file():continue
 digest=hashlib.sha256()
 with path.open('rb') as stream:
  for chunk in iter(lambda:stream.read(1024*1024),b''):digest.update(chunk)
 lines.append(digest.hexdigest()+'  '+path.name)
(DOWNLOADS/'SHA256SUMS.txt').write_text('\n'.join(lines)+'\n')
