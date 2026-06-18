<#
    .SYNOPSIS
        Runs the Windows Customizations Pester test suite.

    .PARAMETER CI
        Emit an NUnit results file (out\TestResults.xml) and set the process exit code so
        the run can gate a pipeline.

    .EXAMPLE
        .\Tests\Invoke-Tests.ps1
        .\Tests\Invoke-Tests.ps1 -CI
#>

[CmdletBinding()]
param
(
    [Parameter(Mandatory = $false)][switch]$CI
)

$ErrorActionPreference = 'Stop'
Import-Module -Name Pester -MinimumVersion 5.0 -ErrorAction Stop

$Configuration = New-PesterConfiguration
$Configuration.Run.Path = $PSScriptRoot
$Configuration.Output.Verbosity = 'Detailed'

if ($CI)
{
    $OutputDirectory = Join-Path -Path (Split-Path -Path $PSScriptRoot -Parent) -ChildPath 'out'
    if (-not (Test-Path -Path $OutputDirectory))
    {
        New-Item -Path $OutputDirectory -ItemType Directory -Force | Out-Null
    }
    $Configuration.TestResult.Enabled = $true
    $Configuration.TestResult.OutputPath = Join-Path -Path $OutputDirectory -ChildPath 'TestResults.xml'
    $Configuration.Run.Exit = $true
}

Invoke-Pester -Configuration $Configuration
