<#
    .SYNOPSIS
        Detection script for the Windows Customizations app (Intune Win32 app or ConfigMgr application).

    .DESCRIPTION
        Checks the version stamp written by the engine on success. Detected when the stamped
        version is greater than or equal to the packaged version; a version bump therefore
        re-triggers application on already-deployed devices.

        Follows the contract Intune and Configuration Manager share: exit 0 with output on
        STDOUT = detected, exit 0 with no output = not detected. ConfigMgr treats a non-zero exit
        as a script failure (state Unknown), not as "not installed", so the not-detected path
        exits 0 too.

        $Organization and $ExpectedVersion are stamped by tools\New-Package.ps1 at package
        time (this script runs standalone and cannot read packaged files).
#>

$Organization = 'Organization'        # {{ORGANIZATION}}
$ExpectedVersion = '0.0.0'            # {{VERSION}}

$StampKey = "HKLM:\SOFTWARE\$Organization\WindowsCustomizations"
try
{
    $Stamp = Get-ItemProperty -Path $StampKey -Name 'Version' -ErrorAction Stop
    if ([version]$Stamp.Version -ge [version]$ExpectedVersion)
    {
        Write-Output "Detected version $($Stamp.Version)"
        exit 0
    }
}
catch
{
    # Not installed or stamp unreadable -> fall through to not-detected.
}
# Not detected: no output and exit 0 (a non-zero exit is a script failure to ConfigMgr).
exit 0
