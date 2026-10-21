<#
    .SYNOPSIS
        Builds the deployable package and the matching versioned detection script.

    .DESCRIPTION
        - Resolves the single-source-of-truth version (package\Engine\version.txt) and Organization
          (package\Config\Settings.json).
        - Regenerates package\Config\Settings.schema.json from the catalog.
        - Emits a standalone detection script with the version and Organization stamped in. The
          same script serves an Intune Win32 app and a ConfigMgr application.
        - Target Intune (the default): runs the Microsoft Win32 Content Prep Tool
          (IntuneWinAppUtil.exe) over the package\ folder (which is exactly the payload) to emit
          the .intunewin.
        - Target ConfigMgr: copies the package\ folder to out\ConfigMgr\<version>\, the content
          source for a Configuration Manager package or application (see docs\ConfigMgr.md).

    .PARAMETER Target
        Intune (default) builds the .intunewin; ConfigMgr builds a content source folder.

    .PARAMETER ContentPrepToolPath
        Path to IntuneWinAppUtil.exe (Intune target only). Download from
        https://github.com/microsoft/Microsoft-Win32-Content-Prep-Tool

    .EXAMPLE
        .\tools\New-Package.ps1 -ContentPrepToolPath C:\Tools\IntuneWinAppUtil.exe

    .EXAMPLE
        .\tools\New-Package.ps1 -Target ConfigMgr
#>

[CmdletBinding()]
param
(
    [Parameter(Mandatory = $false)][ValidateSet('Intune', 'ConfigMgr')][string]$Target = 'Intune',
    [Parameter(Mandatory = $false)][string]$RepoRoot = (Split-Path -Path $PSScriptRoot -Parent),
    [Parameter(Mandatory = $false)][string]$ContentPrepToolPath,
    [Parameter(Mandatory = $false)][string]$OutputPath
)

$ErrorActionPreference = 'Stop'

if (-not $OutputPath)
{
    $OutputPath = Join-Path -Path $RepoRoot -ChildPath 'out'
}
if (-not (Test-Path -Path $OutputPath))
{
    New-Item -Path $OutputPath -ItemType Directory -Force | Out-Null
}

$PackageRoot = Join-Path -Path $RepoRoot -ChildPath 'package'
$Version = (Get-Content -Path (Join-Path -Path $PackageRoot -ChildPath 'Engine\version.txt') -Raw).Trim()
$Config = Get-Content -Path (Join-Path -Path $PackageRoot -ChildPath 'Config\Settings.json') -Raw | ConvertFrom-Json
$Organization = $Config.Organization
Write-Host "Version: $Version | Organization: $Organization" -ForegroundColor Cyan

# 1. Keep the schema in sync with the catalog ----------------------------------------------
& (Join-Path -Path $PSScriptRoot -ChildPath 'Update-SettingsSchema.ps1') -RepoRoot $RepoRoot

# 2. The payload is the package\ folder as-is (entry points + Engine + Config + Assets) ----
if (-not (Test-Path -Path $PackageRoot))
{
    throw "Package folder not found: $PackageRoot"
}

# 3. Emit the versioned standalone detection script ----------------------------------------
$DetectionSource = Get-Content -Path (Join-Path -Path $PSScriptRoot -ChildPath 'Detect-WindowsCustomizations.ps1') -Raw
$DetectionSource = $DetectionSource -replace "(\`$Organization\s*=\s*)'[^']*'", "`$1'$Organization'"
$DetectionSource = $DetectionSource -replace "(\`$ExpectedVersion\s*=\s*)'[^']*'", "`$1'$Version'"
$DetectionOut = Join-Path -Path $OutputPath -ChildPath "Detect-WindowsCustomizations.$Version.ps1"
$DetectionSource = (($DetectionSource -replace "`r`n", "`n") -replace "`r", "`n") -split "`n" -join "`r`n"
[System.IO.File]::WriteAllText($DetectionOut, $DetectionSource, [System.Text.UTF8Encoding]::new($false))
Write-Host "Wrote detection script: $DetectionOut" -ForegroundColor Green

# 4a. ConfigMgr: a versioned copy of the payload is the content source ---------------------
if ($Target -eq 'ConfigMgr')
{
    $ContentRoot = Join-Path -Path $OutputPath -ChildPath "ConfigMgr\$Version"
    if (Test-Path -Path $ContentRoot)
    {
        Remove-Item -Path $ContentRoot -Recurse -Force
    }
    New-Item -Path $ContentRoot -ItemType Directory -Force | Out-Null
    Copy-Item -Path (Join-Path -Path $PackageRoot -ChildPath '*') -Destination $ContentRoot -Recurse -Force
    Write-Host "Content source written to $ContentRoot" -ForegroundColor Green

    Write-Host ''
    Write-Host 'Configuration Manager settings (details: docs\ConfigMgr.md):' -ForegroundColor Cyan
    Write-Host '  Content source: copy the folder above to your package source share'
    Write-Host '  Task sequence:  Run Command Line step in the full OS, after Setup Windows and ConfigMgr,'
    Write-Host '                  with the package selected:'
    Write-Host '                  powershell.exe -NoProfile -ExecutionPolicy Bypass -File Set-WindowsCustomizations.ps1'
    Write-Host '  Application (optional, instead of a package):'
    Write-Host '    Install:   powershell.exe -NoProfile -ExecutionPolicy Bypass -File Set-WindowsCustomizations.ps1'
    Write-Host '    Uninstall: powershell.exe -NoProfile -ExecutionPolicy Bypass -File Remove-WindowsCustomizations.ps1'
    Write-Host "    Detection: custom script $DetectionOut"
    return
}

# 4b. Intune: run the content prep tool ----------------------------------------------------
if (-not $ContentPrepToolPath)
{
    $ContentPrepToolPath = (Get-Command -Name 'IntuneWinAppUtil.exe' -ErrorAction SilentlyContinue).Source
}
if (-not $ContentPrepToolPath -or -not (Test-Path -Path $ContentPrepToolPath))
{
    Write-Warning 'IntuneWinAppUtil.exe not found. The detection script is ready.'
    Write-Warning 'Download the Win32 Content Prep Tool and re-run with -ContentPrepToolPath:'
    Write-Warning '  https://github.com/microsoft/Microsoft-Win32-Content-Prep-Tool'
    Write-Warning 'Deploying with Configuration Manager instead? Re-run with -Target ConfigMgr.'
    return
}

& $ContentPrepToolPath -c $PackageRoot -s 'Set-WindowsCustomizations.ps1' -o $OutputPath -q
Write-Host "Package written to $OutputPath" -ForegroundColor Green

Write-Host ''
Write-Host 'Intune Win32 app settings:' -ForegroundColor Cyan
Write-Host '  Install:   powershell.exe -NoProfile -ExecutionPolicy Bypass -File Set-WindowsCustomizations.ps1'
Write-Host '  Uninstall: powershell.exe -NoProfile -ExecutionPolicy Bypass -File Remove-WindowsCustomizations.ps1'
Write-Host "  Detection: custom script $DetectionOut"
