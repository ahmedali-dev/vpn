#!/usr/bin/env python3
"""Fetch official networking cores, checking GitHub release SHA-256 metadata."""
import concurrent.futures, hashlib, io, json, os, pathlib, tarfile, urllib.request, zipfile
ROOT = pathlib.Path(__file__).resolve().parents[1]
VERSIONS = {'XTLS/Xray-core': 'v26.3.27', 'SagerNet/sing-box': 'v1.14.3'}
TARGETS = {
 'darwin-arm64': ('Xray-macos-arm64-v8a.zip', 'sing-box-1.14.3-darwin-arm64.tar.gz'),
 'darwin-x64': ('Xray-macos-64.zip', 'sing-box-1.14.3-darwin-amd64.tar.gz'),
 'win32-x64': ('Xray-windows-64.zip', 'sing-box-1.14.3-windows-amd64.zip'),
 'linux-arm64': ('Xray-linux-arm64-v8a.zip', 'sing-box-1.14.3-linux-arm64.tar.gz'),
 'linux-x64': ('Xray-linux-64.zip', 'sing-box-1.14.3-linux-amd64.tar.gz'),
}
def get(url):
 headers={'User-Agent': 'TunnelDesktopBuild/1.0'}
 if url.startswith('https://api.github.com/') and os.environ.get('GH_TOKEN'): headers['Authorization']='Bearer '+os.environ['GH_TOKEN']
 request = urllib.request.Request(url, headers=headers)
 with urllib.request.urlopen(request, timeout=120) as response: return response.read()
def fetch(task):
 target, repo, filename, asset = task
 expected = asset.get('digest', '')
 if not expected.startswith('sha256:'): raise RuntimeError('No trusted SHA256 metadata: '+filename)
 cache = pathlib.Path('/private/tmp/tunnel-core-downloads') if os.name != 'nt' and pathlib.Path('/private/tmp').exists() else ROOT/'dist/core-downloads'
 cache.mkdir(parents=True, exist_ok=True)
 download = cache/filename
 data = download.read_bytes() if download.exists() else get(asset['browser_download_url'])
 actual = hashlib.sha256(data).hexdigest()
 if 'sha256:'+actual != expected: raise RuntimeError('Checksum mismatch: '+filename)
 download.write_bytes(data)
 destination = ROOT/'dist/runtime'/target/'cores'; destination.mkdir(parents=True, exist_ok=True)
 allowed = {'xray', 'xray.exe', 'sing-box', 'sing-box.exe', 'geoip.dat', 'geosite.dat', 'wintun.dll', 'LICENSE', 'LICENSE.txt'}
 if filename.endswith('.zip'):
  with zipfile.ZipFile(io.BytesIO(data)) as archive:
   members = [(name,archive.read(name)) for name in archive.namelist() if not name.endswith('/') and pathlib.PurePosixPath(name).name in allowed]
 else:
  with tarfile.open(fileobj=io.BytesIO(data),mode='r:gz') as archive:
   members = [(member.name,archive.extractfile(member).read()) for member in archive.getmembers() if member.isfile() and pathlib.PurePosixPath(member.name).name in allowed]
 for name, content in members:
  basename = pathlib.PurePosixPath(name).name
  if basename.startswith('LICENSE'): basename = 'LICENSE-'+repo.split('/')[1]+'.txt'
  path=destination/basename; path.write_bytes(content)
  if basename in {'xray','sing-box'}: path.chmod(0o755)
 print('Verified',target,filename,flush=True)
 return {'target':target,'repository':repo,'version':VERSIONS[repo],'asset':filename,'sha256':actual,'url':asset['browser_download_url']}
def main():
 targets=TARGETS
 target=os.environ.get('TUNNEL_PACKAGE_TARGET')
 if target:
  if target not in TARGETS: raise SystemExit('Unsupported target: '+target)
  targets={target:TARGETS[target]}
 releases = {}
 for repo,version in VERSIONS.items():
  release=json.loads(get('https://api.github.com/repos/'+repo+'/releases/tags/'+version))
  releases[repo]={asset['name']:asset for asset in release['assets']}
 tasks=[]
 for target,names in targets.items():
  for repo,name in zip(VERSIONS,names): tasks.append((target,repo,name,releases[repo][name]))
 with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool: manifest=list(pool.map(fetch,tasks))
 path=ROOT/'dist/core-manifest.json';path.write_text(json.dumps(manifest,indent=2)+'\n')
 for target in targets: (ROOT/'dist/runtime'/target/'core-manifest.json').write_text(json.dumps([x for x in manifest if x['target']==target],indent=2)+'\n')
if __name__=='__main__':main()
