<#
    .SYNOPSIS
        Generates package\Config\Settings.schema.json from package\Engine\Catalog.psd1.

    .DESCRIPTION
        Keeps the JSON Schema (VS Code validation/autocomplete) in sync with the catalog so
        the two can't drift. Run after editing the catalog, and as part of tools\New-Package.ps1.

    .EXAMPLE
        .\tools\Update-SettingsSchema.ps1
#>

[CmdletBinding()]
param
(
    [Parameter(Mandatory = $false)][string]$RepoRoot = (Split-Path -Path $PSScriptRoot -Parent)
)

$ErrorActionPreference = 'Stop'

$CatalogPath = Join-Path -Path $RepoRoot -ChildPath 'package\Engine\Catalog.psd1'
$SchemaPath = Join-Path -Path $RepoRoot -ChildPath 'package\Config\Settings.schema.json'

$Catalog = Import-PowerShellDataFile -Path $CatalogPath

$Properties = [ordered]@{}
foreach ($Definition in $Catalog.Customizations)
{
    if ($Definition.AllowedValues)
    {
        $Schema = [ordered]@{
            description = $Definition.Description
            enum        = @($Definition.AllowedValues)
        }
    }
    elseif ($Definition.Mechanism -eq 'AppRemoval')
    {
        # true = use the catalog's default list; an array overrides it.
        $Schema = [ordered]@{
            description = $Definition.Description
            oneOf       = @(
                [ordered]@{ type = 'boolean' },
                [ordered]@{ type = 'array'; items = [ordered]@{ type = 'string' } }
            )
        }
    }
    else
    {
        # File / Dism / Custom / non-enumerated: "apply or not".
        $Schema = [ordered]@{
            description = $Definition.Description
            type        = @('boolean', 'integer')
        }
    }
    $Properties[$Definition.Name] = $Schema
}

$RootSchema = [ordered]@{
    '$schema'            = 'http://json-schema.org/draft-07/schema#'
    title                = 'Windows Customizations settings'
    type                 = 'object'
    additionalProperties = $false
    properties           = [ordered]@{
        '$schema'      = [ordered]@{ type = 'string' }
        Organization   = [ordered]@{ type = 'string'; description = 'Org name; used in the version-stamp registry path.' }
        FailureMode    = [ordered]@{ description = 'Lenient = log and continue; Strict = any failure fails the app.'; enum = @('Lenient', 'Strict') }
        Customizations = [ordered]@{
            type                 = 'object'
            additionalProperties = $false
            properties           = $Properties
        }
    }
    required             = @('Organization', 'Customizations')
}

$Json = $RootSchema | ConvertTo-Json -Depth 12
$Json = (($Json -replace "`r`n", "`n") -replace "`r", "`n") -split "`n" -join "`r`n"
[System.IO.File]::WriteAllText($SchemaPath, $Json + "`r`n", [System.Text.UTF8Encoding]::new($false))
Write-Host "Wrote $SchemaPath ($($Properties.Count) customizations)" -ForegroundColor Green
