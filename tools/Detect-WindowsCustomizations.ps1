<#
    .SYNOPSIS
        Win32 app detection rule for the Windows Customizations solution.

    .DESCRIPTION
        Checks the version stamp written by the engine on success. Detected when the stamped
        version is greater than or equal to the packaged version; a version bump therefore
        re-triggers application on already-deployed devices.

        $Organization and $ExpectedVersion are stamped by tools\New-Package.ps1 at package
        time (this script runs standalone in Intune and cannot read packaged files).
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
exit 1
