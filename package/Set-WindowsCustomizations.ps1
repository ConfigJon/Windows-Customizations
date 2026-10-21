<#
    .SYNOPSIS
        Applies Windows 11 customizations as user-changeable defaults during device provisioning.

    .DESCRIPTION
        Data-driven engine: loads a catalog of customization definitions (Catalog.psd1) and
        a per-deployment selection file (Config\Settings.json), then applies each selected
        customization through its mechanism handler. Designed to run as SYSTEM (Windows
        PowerShell 5.1) before any user signs in: by default in the Intune Management Extension
        during the Autopilot device ESP phase, or as a Configuration Manager task sequence step
        in the full OS (see docs\ConfigMgr.md).

    .NOTES
        Created by: Jon Anderson (@ConfigJon)
        See docs\Design.md for detailed information.
#>

[CmdletBinding()]
param()

# Re-launch under 64-bit PowerShell when started from a 32-bit host -------------------------
# The IME is 32-bit, and so is a task sequence Run Command Line step unless 64-bit file system
# redirection is disabled on it. PROCESSOR_ARCHITEW6432 is only set in a 32-bit process on
# 64-bit Windows; it reports the native architecture (AMD64 or ARM64). SysNative redirects to
# the native PowerShell.
if ($env:PROCESSOR_ARCHITEW6432 -in 'AMD64', 'ARM64')
{
    try
    {
        & "$env:WINDIR\SysNative\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -ExecutionPolicy Bypass -File $PSCommandPath @args
        exit $LASTEXITCODE
    }
    catch
    {
        throw "Failed to relaunch under SysNative: $($_.Exception.Message)"
    }
}

$ErrorActionPreference = 'Stop'
$PackageRoot = $PSScriptRoot
$EngineRoot = Join-Path -Path $PackageRoot -ChildPath 'Engine'

. (Join-Path -Path $EngineRoot -ChildPath 'Functions.ps1')

Initialize-Logging
Write-LogEntry -Message 'START - Windows Customization Script'

# Resolve the package version (single source of truth) -------------------------------------
$VersionFile = Join-Path -Path $EngineRoot -ChildPath 'version.txt'
if (Test-Path -Path $VersionFile)
{
    $ScriptVersion = (Get-Content -Path $VersionFile -Raw).Trim()
}
else
{
    $ScriptVersion = '0.0.0'
    Write-LogEntry -Message "version.txt not found; using $ScriptVersion" -Level Warning
}
Write-LogEntry -Message "Engine version $ScriptVersion"

# Refuse to run in WinPE -------------------------------------------------------------------
# Every handler targets the running OS (-Online DISM/Appx, C:\Users\Default), so in WinPE it
# would change WinPE itself. In a task sequence the step belongs after Setup Windows and ConfigMgr.
if (Test-IsWinPE)
{
    Write-LogEntry -Message 'Running in WinPE. Run this step in the full OS, after Setup Windows and ConfigMgr.' -Level Error
    Write-LogEntry -Message 'END - Windows Customization Script'
    exit 1
}
if (Get-TaskSequenceStatus)
{
    Write-LogEntry -Message 'Running in a Configuration Manager task sequence'
}

# Confirm the target OS --------------------------------------------------------------------
if (-not (Test-IsWindows11))
{
    Write-LogEntry -Message 'Operating system is not Windows 11. Nothing to do.' -Level Warning
    Write-LogEntry -Message 'END - Windows Customization Script'
    exit 0
}

# Load and parse the per-deployment config -------------------------------------------------
$ConfigPath = Join-Path -Path $PackageRoot -ChildPath 'Config\Settings.json'
if (-not (Test-Path -Path $ConfigPath))
{
    Write-LogEntry -Message "Config not found: $ConfigPath" -Level Error
    exit 1
}
try
{
    $Config = Get-Content -Path $ConfigPath -Raw | ConvertFrom-Json
}
catch
{
    Write-LogEntry -Message "Failed to parse $ConfigPath : $($_.Exception.Message)" -Level Error
    exit 1
}

$Organization = if ($Config.Organization) { $Config.Organization } else { 'Organization' }
$FailureMode = if ($Config.FailureMode) { $Config.FailureMode } else { 'Lenient' }
Write-LogEntry -Message "Organization: $Organization | FailureMode: $FailureMode"

# Load the catalog and index it by Name ----------------------------------------------------
$CatalogData = Import-PowerShellDataFile -Path (Join-Path -Path $EngineRoot -ChildPath 'Catalog.psd1')
$CatalogIndex = @{}
foreach ($Definition in $CatalogData.Customizations)
{
    $CatalogIndex[$Definition.Name] = $Definition
}

# Validate the config against the catalog (fail-fast, independent of FailureMode) -----------
$Selected = New-Object System.Collections.Generic.List[object]
$ConfigErrors = New-Object System.Collections.Generic.List[string]

if ($null -ne $Config.Customizations)
{
    foreach ($Property in $Config.Customizations.PSObject.Properties)
    {
        $Name = $Property.Name
        $Value = $Property.Value
        if (-not $CatalogIndex.ContainsKey($Name))
        {
            $ConfigErrors.Add("Unknown customization '$Name' (not in catalog)")
            continue
        }
        $Definition = $CatalogIndex[$Name]
        if (($Definition.AllowedValues) -and ($Value -isnot [System.Array]) -and ($Definition.AllowedValues -notcontains $Value))
        {
            $ConfigErrors.Add("Value '$Value' is not allowed for '$Name' (allowed: $($Definition.AllowedValues -join ', '))")
            continue
        }
        $Selected.Add([pscustomobject]@{ Definition = $Definition; Value = $Value })
    }
}

if ($ConfigErrors.Count -gt 0)
{
    foreach ($ConfigError in $ConfigErrors)
    {
        Write-LogEntry -Message $ConfigError -Level Error
    }
    Write-LogEntry -Message 'Config validation failed. No customizations applied.' -Level Error
    exit 1
}

if ($Selected.Count -eq 0)
{
    Write-LogEntry -Message 'No customizations selected in config. Nothing to do.' -Level Warning
    Write-VersionStamp -Organization $Organization -Version $ScriptVersion
    Write-LogEntry -Message 'END - Windows Customization Script'
    exit 0
}

$Results = New-Object System.Collections.Generic.List[object]

# Pass 1: machine-level items (no Default User hive needed) ---------------------------------
Write-LogEntry -Message 'Pass 1: machine-level customizations'
foreach ($Item in $Selected)
{
    if (-not (Test-NeedsHive -Definition $Item.Definition))
    {
        Write-LogEntry -Message "Apply: $($Item.Definition.Name)"
        $Results.Add((Invoke-Customization -Definition $Item.Definition -Value $Item.Value))
    }
}

# Pass 2: Default User hive items -----------------------------------------------------------
$HiveItems = $Selected | Where-Object { Test-NeedsHive -Definition $_.Definition }
if ($HiveItems)
{
    Write-LogEntry -Message 'Pass 2: Default User hive customizations'
    $HiveDrive = 'WCDefault'
    Import-RegistryHive -File 'C:\Users\Default\NTUSER.DAT' -Key 'HKLM\WC_DefaultUser' -Name $HiveDrive
    try
    {
        foreach ($Item in $HiveItems)
        {
            Write-LogEntry -Message "Apply: $($Item.Definition.Name)"
            $Results.Add((Invoke-Customization -Definition $Item.Definition -Value $Item.Value -HiveDrive $HiveDrive))
        }
    }
    finally
    {
        Remove-RegistryHiveWithRetry -Name $HiveDrive
        Write-LogEntry -Message 'Default User hive unloaded'
    }
}

# Summary and exit code --------------------------------------------------------------------
$Applied = @($Results | Where-Object { $_.Status -eq 'Applied' }).Count
$Failed = @($Results | Where-Object { $_.Status -eq 'Failed' }).Count
$Skipped = @($Results | Where-Object { $_.Status -eq 'Skipped' }).Count
Write-LogEntry -Message "Summary: $Applied applied, $Skipped skipped, $Failed failed"

$Success = -not (($Failed -gt 0) -and ($FailureMode -eq 'Strict'))
if ($Success)
{
    Write-VersionStamp -Organization $Organization -Version $ScriptVersion
    Write-LogEntry -Message 'END - Windows Customization Script'
    exit 0
}
else
{
    Write-LogEntry -Message "FailureMode is Strict and $Failed customization(s) failed. Returning non-zero." -Level Error
    Write-LogEntry -Message 'END - Windows Customization Script'
    exit 1
}
