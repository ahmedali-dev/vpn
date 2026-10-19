#!/usr/bin/env python3
"""Add Windows diagnostics launchers and archive a Windows desktop release."""
from pathlib import Path
import hashlib,shutil,zipfile,json
ROOT=Path(__file__).resolve().parents[1]
folder=ROOT/'dist/desktop/Tunnel Desktop-win32-x64'
VERSION=json.loads((ROOT/'desktop/package.json').read_text())['version']
launcher=r'''@echo off
setlocal
cd /d "%~dp0"
set "TUNNEL_LOGS=%LOCALAPPDATA%\TunnelDesktop\logs"
if not exist "%TUNNEL_LOGS%" mkdir "%TUNNEL_LOGS%"
echo Tunnel Desktop - Windows startup diagnostics
echo.
if not exist "resources\app.asar" goto incomplete
if not exist "resources\win32-x64\tunnel.exe" goto incomplete
if not exist "icudtl.dat" goto incomplete
echo Checking the tunnel engine...
"resources\win32-x64\tunnel.exe" -h > "%TUNNEL_LOGS%\engine-check.log" 2>&1
if errorlevel 1 goto engine_failed
echo Opening Tunnel Desktop. Keep this folder intact.
echo Logs: %TUNNEL_LOGS%
echo.
"Tunnel Desktop.exe" --enable-logging --log-file="%TUNNEL_LOGS%\chromium.log" %*
set "TUNNEL_EXIT=%ERRORLEVEL%"
echo.
echo Desktop exited with code %TUNNEL_EXIT%.
echo Startup log: %TUNNEL_LOGS%\startup.log
echo Chromium log: %TUNNEL_LOGS%\chromium.log
pause
exit /b %TUNNEL_EXIT%
:incomplete
echo Required files are missing. Right-click the downloaded ZIP and choose Extract All.
echo Open Start-Tunnel.cmd from the extracted folder. Do not copy only the EXE.
pause
exit /b 1
:engine_failed
echo The tunnel engine could not start. Details:
type "%TUNNEL_LOGS%\engine-check.log"
echo Share the error text above to diagnose the Windows failure.
pause
exit /b 1
'''
(folder/'Start-Tunnel.cmd').write_bytes(launcher.replace('\n','\r\n').encode('ascii'))
(folder/'Start-Software-Rendering.cmd').write_bytes(b'@echo off\r\ncall "%~dp0Start-Tunnel.cmd" --disable-gpu\r\n')
(folder/'WINDOWS-START.txt').write_text('''Tunnel Desktop VERSION - Windows 11 / Windows 10 x64

1. Right-click the downloaded ZIP and choose Extract All.
2. Open the extracted Tunnel Desktop-win32-x64 folder.
3. Run Start-Tunnel.cmd for the first diagnostic launch.
4. After it opens successfully, Tunnel Desktop.exe can be used directly.

Keep the EXE, resources folder, locales folder, and DLL files together.
This desktop package includes its tunnel engine, Xray, sing-box and Wintun.
Do not run the app directly inside the ZIP or copy just the EXE.

If the app still does not open:
- Read the error in the launcher console.
- The logs are under %LOCALAPPDATA%\\TunnelDesktop\\logs.
- Share startup.log and the last lines of chromium.log, or the exact Windows
  error if the operating system prevents the program from starting.
- Start-Software-Rendering.cmd provides a GPU-free diagnostic launch if the
  normal launcher reports graphics/renderer errors.

No administrator privileges are needed to open the app or use proxy mode.
Full-device VPN asks for administrator authorization separately when enabled.

This build is unsigned. GitHub Actions builds and tests the engine on Windows.
A successful automated build does not verify interactive GUI startup, server
connectivity, or administrator-approved TUN routing on your machine.
'''.replace('VERSION',VERSION))
shutil.copy2(ROOT/'README.md',folder/'README.md')
output=ROOT/'dist/downloads'/('TunnelDesktop-windows-x64-'+VERSION+'.zip')
with zipfile.ZipFile(output,'w',zipfile.ZIP_DEFLATED) as archive:
 for path in sorted(folder.rglob('*')):
  if path.is_file():archive.write(path,path.relative_to(folder.parent))
with zipfile.ZipFile(output) as archive:
 assert archive.testzip() is None
 names=archive.namelist()
 for suffix in ['/Start-Tunnel.cmd','/WINDOWS-START.txt','/resources/app.asar','/resources/win32-x64/tunnel.exe','/resources/win32-x64/cores/xray.exe','/resources/win32-x64/cores/sing-box.exe']:
  assert any(name.endswith(suffix) for name in names),suffix
h=hashlib.sha256()
with output.open('rb') as stream:
 for chunk in iter(lambda:stream.read(1024*1024),b''):h.update(chunk)
(output.parent/(output.name+'.sha256')).write_text(h.hexdigest()+'  '+output.name+'\n')
print('Verified Windows release:',output,output.stat().st_size,flush=True)
