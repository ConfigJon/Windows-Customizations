<#
    .SYNOPSIS
        Uninstall action for the Windows Customizations Win32 app.

    .DESCRIPTION
        Removes only the HKLM version stamp, which flips the Intune detection rule to
        "not installed". It does NOT revert any customization: the Default User hive seeds,
        the ClassicContextMenu Active Setup component, machine-level/policy registry keys,
        replaced branding files, and removed apps all remain. So new users still inherit most
        customizations after uninstall. Per-user values are intentionally left in place - they
        live in individual profiles and are user-changeable by design. A full teardown
        (clearing the default hive, Active Setup, and HKLM/policy keys) is not implemented.
#>

[CmdletBinding()]
param()

# Re-launch 64-bit when started from the 32-bit IME host (AMD64 or ARM64 native).
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

Initialize-Logging -FileName 'Remove-WindowsCustomizations.log'
Write-LogEntry -Message 'START - Remove Windows Customizations'

$ConfigPath = Join-Path -Path $PackageRoot -ChildPath 'Config\Settings.json'
$Organization = 'Organization'
if (Test-Path -Path $ConfigPath)
{
    try
    {
        $Config = Get-Content -Path $ConfigPath -Raw | ConvertFrom-Json
        if ($Config.Organization)
        {
            $Organization = $Config.Organization
        }
    }
    catch
    {
        Write-LogEntry -Message "Failed to read Organization from config: $($_.Exception.Message)" -Level Warning
    }
}

try
{
    Remove-VersionStamp -Organization $Organization
    Write-LogEntry -Message "Removed version stamp under HKLM:\SOFTWARE\$Organization\WindowsCustomizations"
}
catch
{
    Write-LogEntry -Message "Failed to remove version stamp: $($_.Exception.Message)" -Level Error
}

Write-LogEntry -Message 'END - Remove Windows Customizations'
exit 0
