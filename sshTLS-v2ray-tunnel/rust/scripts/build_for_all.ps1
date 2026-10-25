# Windows entry point matching build_for_all.sh on Linux/Git Bash.
[CmdletBinding()]
param([switch]$Check, [switch]$Help)
$ErrorActionPreference = 'Stop'
& (Join-Path $PSScriptRoot 'build_for_windows.ps1') -Check:$Check -Help:$Help
