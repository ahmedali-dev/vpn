# Native x64 Windows build: install missing dependencies, then package the Tauri app.
[CmdletBinding()]
param([switch]$Check, [switch]$Help)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
if ($Help) {
    Write-Host 'Usage: .\build_for_windows.ps1 [-Check]'
    Write-Host 'Installs missing dependencies and creates a Windows x64 ZIP with networking cores.'
    Write-Host '-Check reports missing dependencies without installing or building.'
    exit 0
}
if ($env:OS -ne 'Windows_NT' -or
    [Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString() -ne 'X64' -or
    -not [Environment]::Is64BitProcess) {
    throw 'Run this script in 64-bit PowerShell on x86_64 Windows.'
}
function Invoke-Checked {
    param([string]$Program, [string[]]$Arguments)
    & $Program @Arguments
    if ($LASTEXITCODE -ne 0) { throw "$Program failed with exit code $LASTEXITCODE" }
}
function Refresh-Path {
    $cargoHome = if ($env:CARGO_HOME) { $env:CARGO_HOME } else { Join-Path $HOME '.cargo' }
    $env:Path = "$cargoHome\bin;" +
        [Environment]::GetEnvironmentVariable('Path', 'Machine') + ';' +
        [Environment]::GetEnvironmentVariable('Path', 'User') + ';' + $env:Path
}
function Find-Python {
    foreach ($name in @('py', 'python', 'python3')) {
        $command = Get-Command $name -All -ErrorAction SilentlyContinue |
            Where-Object { $_.Source -notlike '*\Microsoft\WindowsApps\*' } | Select-Object -First 1
        if (-not $command) { continue }
        $arguments = if ($name -eq 'py') { @('-3') } else { @() }
        try {
            & $command.Source @arguments -c 'import sys; sys.exit(0 if sys.version_info >= (3, 9) else 1)' 2>$null
        } catch { continue }
        if ($LASTEXITCODE -eq 0) {
            return @{ Path = $command.Source; Arguments = $arguments }
        }
    }
    return $null
}
function Find-VisualStudio {
    $vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
    if (-not (Test-Path $vswhere)) { return $null }
    $path = & $vswhere -latest -products '*' -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
    if ($LASTEXITCODE -eq 0 -and $path) { return ($path | Select-Object -First 1) }
    return $null
}
function Has-WindowsSDK {
    return [bool](Get-ChildItem "${env:ProgramFiles(x86)}\Windows Kits\10\Include\*\um\Windows.h" -ErrorAction SilentlyContinue)
}
function Has-WebView {
    foreach ($key in @('HKLM:\SOFTWARE\WOW6432Node\Microsoft\EdgeUpdate\Clients\*',
                       'HKLM:\SOFTWARE\Microsoft\EdgeUpdate\Clients\*',
                       'HKCU:\SOFTWARE\Microsoft\EdgeUpdate\Clients\*')) {
        $found = Get-ItemProperty $key -ErrorAction SilentlyContinue |
            Where-Object { $_.PSObject.Properties['name'] -and $_.name -like '*WebView2*' -and
                           $_.PSObject.Properties['pv'] -and $_.pv -and $_.pv -ne '0.0.0.0' }
        if ($found) { return $true }
    }
    return $false
}
function Install-WingetPackage {
    param([string]$Id)
    if (-not (Get-Command winget -ErrorAction SilentlyContinue)) {
        throw "Install Microsoft's App Installer (winget), then rerun this script to install $Id."
    }
    Invoke-Checked 'winget' @('install', '--id', $Id, '--exact', '--source', 'winget',
        '--accept-source-agreements', '--accept-package-agreements', '--disable-interactivity')
    Refresh-Path
}
Refresh-Path
$python = Find-Python
$visualStudio = Find-VisualStudio
$hasSdk = Has-WindowsSDK
$hasWebView = Has-WebView
$hasGit = [bool](Get-Command git -ErrorAction SilentlyContinue)
$hasRust = $false
if (Get-Command rustup -ErrorAction SilentlyContinue) {
    try {
        & rustup run stable-x86_64-pc-windows-msvc cargo --version *> $null
        $hasRust = $LASTEXITCODE -eq 0
    } catch { $hasRust = $false }
}
$vcpkg = if ($env:VCPKG_INSTALLATION_ROOT) { $env:VCPKG_INSTALLATION_ROOT }
         elseif ($env:VCPKG_ROOT) { $env:VCPKG_ROOT }
         else { Join-Path $env:LOCALAPPDATA 'TunnelNest\build-deps\vcpkg' }
$openssl = Join-Path $vcpkg 'installed\x64-windows-static-md'
$hasOpenSSL = (Test-Path "$openssl\lib\libssl.lib") -and
              (Test-Path "$openssl\lib\libcrypto.lib") -and
              (Test-Path "$openssl\include\openssl\ssl.h")
$missing = @()
if (-not $python) { $missing += 'Python 3.9+' }
if (-not $hasGit) { $missing += 'Git' }
if (-not $visualStudio -or -not $hasSdk) { $missing += 'Visual Studio C++ Build Tools and Windows SDK' }
if (-not $hasWebView) { $missing += 'Microsoft WebView2 Runtime' }
if (-not $hasRust) { $missing += 'Rust stable x64 MSVC' }
if (-not $hasOpenSSL) { $missing += 'OpenSSL x64-windows-static-md (vcpkg)' }
if ($missing.Count) { Write-Host ('Missing dependencies: ' + ($missing -join ', ')) }
else { Write-Host 'All build dependencies are ready.' }
if ($Check) {
    if ($missing.Count) { exit 1 }
    exit 0
}
if (-not $python) { Install-WingetPackage 'Python.Python.3.12' }
if (-not $hasGit) { Install-WingetPackage 'Git.Git' }
if (-not $hasWebView) { Install-WingetPackage 'Microsoft.EdgeWebView2Runtime' }
if (-not $visualStudio -or -not $hasSdk) {
    # The official bootstrapper can add a workload to an existing VS installation.
    $installer = Join-Path ([IO.Path]::GetTempPath()) ('tunnelnest-buildtools-' + [guid]::NewGuid() + '.exe')
    try {
        Invoke-WebRequest 'https://aka.ms/vs/17/release/vs_buildtools.exe' -OutFile $installer -UseBasicParsing
        $signature = Get-AuthenticodeSignature $installer
        if ($signature.Status -ne 'Valid' -or $signature.SignerCertificate.Subject -notlike '*O=Microsoft Corporation*') {
            throw 'Visual Studio installer has no valid Microsoft signature.'
        }
        $arguments = '--passive --wait --norestart --add Microsoft.VisualStudio.Workload.VCTools --includeRecommended'
        if ($visualStudio) {
            $arguments = 'modify --installPath "' + $visualStudio + '" ' + $arguments
        }
        $process = Start-Process $installer -ArgumentList $arguments -Verb RunAs -Wait -PassThru
        if ($process.ExitCode -eq 3010) { throw 'Build Tools installed. Restart Windows, then rerun this script.' }
        if ($process.ExitCode -ne 0) { throw "Visual Studio installation failed: $($process.ExitCode)" }
    } finally { Remove-Item $installer -Force -ErrorAction SilentlyContinue }
}
$visualStudio = Find-VisualStudio
if (-not $visualStudio -or -not (Has-WindowsSDK)) { throw 'C++ tools or Windows SDK are still missing. Rerun after installation/restart.' }
# Import the x64 compiler and SDK environment into this PowerShell process.
$devcmd = Join-Path $visualStudio 'Common7\Tools\VsDevCmd.bat'
$command = '"' + $devcmd + '" -no_logo -arch=x64 -host_arch=x64 >nul && set'
$variables = & $env:ComSpec /d /s /c "`"$command`""
if ($LASTEXITCODE -ne 0) { throw 'Cannot initialize Visual Studio x64 build environment.' }
foreach ($line in $variables) {
    if ($line -match '^([^=]+)=(.*)$') { [Environment]::SetEnvironmentVariable($matches[1], $matches[2], 'Process') }
}
Refresh-Path
if (-not (Get-Command rustup -ErrorAction SilentlyContinue)) { Install-WingetPackage 'Rustlang.Rustup' }
if (-not $hasRust) {
    Invoke-Checked 'rustup' @('toolchain', 'install', 'stable-x86_64-pc-windows-msvc', '--profile', 'minimal')
}
$python = Find-Python
if (-not $python) { throw 'Python is not available yet. Open a new PowerShell window and rerun this script.' }
if (-not $hasOpenSSL) {
    if (-not (Test-Path "$vcpkg\.vcpkg-root")) {
        New-Item -ItemType Directory -Path (Split-Path $vcpkg -Parent) -Force | Out-Null
        Invoke-Checked 'git' @('clone', 'https://github.com/microsoft/vcpkg.git', $vcpkg)
    }
    if (-not (Test-Path "$vcpkg\vcpkg.exe")) {
        Invoke-Checked "$vcpkg\bootstrap-vcpkg.bat" @('-disableMetrics')
    }
    Invoke-Checked "$vcpkg\vcpkg.exe" @('install', 'openssl:x64-windows-static-md', '--disable-metrics')
}
$env:OPENSSL_DIR = $openssl
$env:OPENSSL_LIB_DIR = Join-Path $openssl 'lib'
$env:OPENSSL_INCLUDE_DIR = Join-Path $openssl 'include'
$env:OPENSSL_LIBS = 'libssl:libcrypto'
$env:OPENSSL_STATIC = '1'
$env:RUSTUP_TOOLCHAIN = 'stable-x86_64-pc-windows-msvc'
$env:TUNNEL_PACKAGE_TARGET = 'win32-x64'
$env:TUNNELNEST_CLI_ONLY = '0'
$root = Split-Path $PSScriptRoot -Parent
Push-Location $root
try {
    $pythonArgs = @($python.Arguments)
    $version = & $python.Path @pythonArgs -c "from scripts.version import package_version; from pathlib import Path; print(package_version(Path('Cargo.toml').read_text()))"
    if ($LASTEXITCODE -ne 0) { throw 'Cannot read Cargo.toml version.' }
    Invoke-Checked $python.Path ($pythonArgs + @('scripts/version.py', $version, '--check'))
    Invoke-Checked $python.Path ($pythonArgs + @('scripts/fetch-cores.py'))
    Invoke-Checked $python.Path ($pythonArgs + @('scripts/build.py'))
    Invoke-Checked $python.Path ($pythonArgs + @('scripts/archive.py', '--target', 'win32-x64', '--version', $version))
    Write-Host "Build complete. ZIP and checksum: $root\dist\release\"
} finally { Pop-Location }
