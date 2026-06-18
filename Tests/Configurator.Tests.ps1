<#
    .SYNOPSIS
        Tests for Configure-Settings.ps1 - the interactive Settings.json configurator (Pester 5).

    .DESCRIPTION
        Asserts that JSON produced by the configurator's emitter passes the same catalog
        validation the engine performs at apply time (package\Set-WindowsCustomizations.ps1):
        every key exists in the catalog, and every non-array value is within AllowedValues.
        Driving every catalog entry through the emitter means a newly added catalog setting
        cannot silently produce config the engine would reject. Also covers round-trip
        fidelity and idempotency. Runs anywhere (no Windows 11 / GUI required).

    .EXAMPLE
        .\Tests\Invoke-Tests.ps1
#>

# ---- Discovery phase ----------------------------------------------------------------------
$RepoRoot = Split-Path -Path $PSScriptRoot -Parent
$DiscoveryCatalog = Import-PowerShellDataFile -Path (Join-Path -Path $RepoRoot -ChildPath 'package\Engine\Catalog.psd1')
$EntryCases = foreach ($Entry in $DiscoveryCatalog.Customizations) { @{ Name = $Entry.Name } }

# ---- Run phase: shared state --------------------------------------------------------------
BeforeAll {
    $RepoRoot = Split-Path -Path $PSScriptRoot -Parent
    $ConfiguratorPath = Join-Path -Path $RepoRoot -ChildPath 'tools\Configure-Settings.ps1'

    # Dot-source to reach the helper functions; the entry-point guard skips the GUI.
    . $ConfiguratorPath

    $Catalog = (Import-PowerShellDataFile -Path (Join-Path -Path $RepoRoot -ChildPath 'package\Engine\Catalog.psd1')).Customizations
    $CatalogIndex = @{}
    foreach ($Entry in $Catalog) { $CatalogIndex[$Entry.Name] = $Entry }

    # Build one selection per catalog entry, typed exactly as the GUI would emit it:
    #   enum   -> first allowed integer
    #   array  -> a sample override list
    #   toggle -> boolean true
    $AllSelections = New-Object System.Collections.Generic.List[object]
    foreach ($Entry in $Catalog)
    {
        switch (Get-SettingKind -Definition $Entry)
        {
            'enum'  { $value = [int]$Entry.AllowedValues[0] }
            'array' { $value = @('Microsoft.BingNews', 'Microsoft.GamingApp') }
            default { $value = $true }
        }
        $AllSelections.Add([pscustomobject]@{ Name = $Entry.Name; Value = $value })
    }

    $FullJson = ConvertTo-SettingsJson -Organization 'Contoso' -FailureMode 'Lenient' `
        -Selections $AllSelections
    $FullParsed = $FullJson | ConvertFrom-Json

    # Mirror the engine's apply-time validation (Set-WindowsCustomizations.ps1).
    function Test-EngineValidates
    {
        param($Parsed, $Index)
        $errs = New-Object System.Collections.Generic.List[string]
        foreach ($prop in $Parsed.Customizations.PSObject.Properties)
        {
            if (-not $Index.ContainsKey($prop.Name))
            {
                $errs.Add("Unknown customization '$($prop.Name)'")
                continue
            }
            $def = $Index[$prop.Name]
            if ($def.ContainsKey('AllowedValues') -and ($prop.Value -isnot [System.Array]) -and ($def.AllowedValues -notcontains $prop.Value))
            {
                $errs.Add("Value '$($prop.Value)' not allowed for '$($prop.Name)'")
            }
        }
        return $errs
    }
}

Describe 'Configurator output is valid JSON' {
    It 'emits parseable JSON for a full selection' {
        { $FullJson | ConvertFrom-Json } | Should -Not -Throw
    }

    It 'includes the schema reference and required top-level fields' {
        $FullParsed.'$schema'    | Should -Be './Settings.schema.json'
        $FullParsed.Organization | Should -Be 'Contoso'
        $FullParsed.FailureMode  | Should -Be 'Lenient'
    }
}

Describe 'Configurator output passes engine catalog validation' {
    It 'produces no validation errors for a full selection' {
        $errs = Test-EngineValidates -Parsed $FullParsed -Index $CatalogIndex
        $errs | Should -BeNullOrEmpty -Because ($errs -join '; ')
    }

    It 'emits catalog entry <Name> with a catalog-legal value' -ForEach $EntryCases {
        $prop = $FullParsed.Customizations.PSObject.Properties[$Name]
        $prop | Should -Not -BeNullOrEmpty -Because 'every selected entry must appear in the output'

        $def = $CatalogIndex[$Name]
        if ($def.ContainsKey('AllowedValues') -and ($prop.Value -isnot [System.Array]))
        {
            $def.AllowedValues | Should -Contain $prop.Value
        }
    }
}

Describe 'Value typing is correct per setting kind' {
    It 'enum values serialize as integers' {
        $v = $FullParsed.Customizations.SearchBoxMode
        $v | Should -Be 0
        ($v -is [int] -or $v -is [long]) | Should -BeTrue -Because 'enum must serialize as a JSON number, not a string or bool'
    }

    It 'toggle values serialize as booleans' {
        $FullParsed.Customizations.OneDriveSetup | Should -BeOfType [bool]
        $FullParsed.Customizations.OneDriveSetup | Should -BeTrue
    }

    It 'array overrides serialize as a JSON array' {
        ($FullParsed.Customizations.RemoveProvisionedApps -is [System.Array]) | Should -BeTrue
        $FullParsed.Customizations.RemoveProvisionedApps | Should -Contain 'Microsoft.BingNews'
    }
}

Describe 'Round-trip of the committed Settings.json' {
    BeforeAll {
        $Committed = Get-Content -Path (Join-Path -Path $RepoRoot -ChildPath 'package\Config\Settings.json') -Raw | ConvertFrom-Json

        $RoundTrip = New-Object System.Collections.Generic.List[object]
        foreach ($Entry in $Catalog)
        {
            $existing = Get-ExistingCustomization -Config $Committed -Name $Entry.Name
            if ($null -eq $existing) { continue }
            $RoundTrip.Add([pscustomobject]@{ Name = $Entry.Name; Value = $existing })
        }
        $Regenerated = (ConvertTo-SettingsJson -Organization $Committed.Organization `
            -FailureMode $Committed.FailureMode `
            -Selections $RoundTrip) | ConvertFrom-Json
    }

    It 'preserves every selected customization and its value' {
        foreach ($prop in $Committed.Customizations.PSObject.Properties)
        {
            $round = $Regenerated.Customizations.PSObject.Properties[$prop.Name]
            $round | Should -Not -BeNullOrEmpty -Because "round-trip dropped '$($prop.Name)'"
            $round.Value | Should -Be $prop.Value
        }
    }

    It 'adds no customizations that were not in the source' {
        $sourceNames = $Committed.Customizations.PSObject.Properties.Name
        foreach ($prop in $Regenerated.Customizations.PSObject.Properties)
        {
            $sourceNames | Should -Contain $prop.Name
        }
    }
}

Describe 'Provisioned-app list handling' {
    BeforeAll {
        $AppEntry = $CatalogIndex['RemoveProvisionedApps']
        $Default  = [string[]]@($AppEntry.PackageNames)
        $Available = [string[]]@($AppEntry.AvailablePackages)
    }

    It 'Test-SamePackageSet is order- and case-insensitive' {
        Test-SamePackageSet -A @('A', 'B') -B @('B', 'A') | Should -BeTrue
        Test-SamePackageSet -A @('Microsoft.App') -B @('microsoft.app') | Should -BeTrue
    }

    It 'Test-SamePackageSet detects differing sets' {
        Test-SamePackageSet -A @('A', 'B') -B @('A') | Should -BeFalse
        Test-SamePackageSet -A @('A', 'B') -B @('A', 'C') | Should -BeFalse
    }

    It 'the default removal set is a subset of the available menu' {
        foreach ($pkg in $Default) { $Available | Should -Contain $pkg }
    }

    It 'a selection equal to the default would serialize as boolean true' {
        # Mirrors the GUI save rule: selection == default -> write `true`.
        $value = if (Test-SamePackageSet -A $Default -B $Default) { $true } else { $Default }
        $json = ConvertTo-SettingsJson -Organization 'X' -FailureMode 'Lenient' `
            -Selections @([pscustomobject]@{ Name = 'RemoveProvisionedApps'; Value = $value })
        ($json | ConvertFrom-Json).Customizations.RemoveProvisionedApps | Should -BeTrue
    }

    It 'a custom selection serializes as a JSON array and passes engine validation' {
        $custom = [string[]]@($Available[0], $Available[1])
        $value = if (Test-SamePackageSet -A $custom -B $Default) { $true } else { $custom }
        $parsed = (ConvertTo-SettingsJson -Organization 'X' -FailureMode 'Lenient' `
            -Selections @([pscustomobject]@{ Name = 'RemoveProvisionedApps'; Value = $value })) | ConvertFrom-Json
        ($parsed.Customizations.RemoveProvisionedApps -is [System.Array]) | Should -BeTrue
        $parsed.Customizations.RemoveProvisionedApps.Count | Should -Be 2
    }

    It 'an empty array serializes as []' {
        Format-JsonValue -Value ([string[]]@()) | Should -Be '[]'
    }
}

Describe 'File-asset handling' {
    It 'classifies <Name> as kind <Expected>' -ForEach @(
        @{ Name = 'DefaultAppAssociations'; Expected = 'file' }
        @{ Name = 'TaskbarPins';            Expected = 'file' }
        @{ Name = 'StartLayout';            Expected = 'file' }
        @{ Name = 'OneDriveSetup';          Expected = 'toggle' }
        @{ Name = 'SearchBoxMode';          Expected = 'enum' }
        @{ Name = 'RemoveProvisionedApps';  Expected = 'array' }
    ) {
        Get-SettingKind -Definition $CatalogIndex[$Name] | Should -Be $Expected
    }

    It 'accepts well-formed XML with the expected root' {
        $p = Join-Path $TestDrive 'good.xml'
        Set-Content -Path $p -Value '<LayoutModificationTemplate/>'
        (Test-AssetFile -Path $p -ExpectedRoot 'LayoutModificationTemplate').Ok | Should -BeTrue
    }

    It 'rejects XML with the wrong root element' {
        $p = Join-Path $TestDrive 'wrong.xml'
        Set-Content -Path $p -Value '<SomethingElse/>'
        $r = Test-AssetFile -Path $p -ExpectedRoot 'LayoutModificationTemplate'
        $r.Ok | Should -BeFalse
        $r.Message | Should -Match 'Wrong file'
    }

    It 'rejects malformed XML' {
        $p = Join-Path $TestDrive 'bad.xml'
        Set-Content -Path $p -Value '<broken'
        (Test-AssetFile -Path $p -ExpectedRoot $null).Ok | Should -BeFalse
    }

    It 'rejects an empty non-XML asset but accepts a non-empty one' {
        $empty = Join-Path $TestDrive 'empty.bin'
        New-Item -ItemType File -Path $empty -Force | Out-Null
        (Test-AssetFile -Path $empty -ExpectedRoot $null).Ok | Should -BeFalse

        $ok = Join-Path $TestDrive 'ok.bin'
        Set-Content -Path $ok -Value 'data'
        (Test-AssetFile -Path $ok -ExpectedRoot $null).Ok | Should -BeTrue
    }

    It 'reports a missing file' {
        (Test-AssetFile -Path (Join-Path $TestDrive 'nope.xml') -ExpectedRoot $null).Ok | Should -BeFalse
    }

    It 'Copy-AssetFile creates missing directories and copies content' {
        $src = Join-Path $TestDrive 'src.xml'
        Set-Content -Path $src -Value '<DefaultAssociations/>'
        $dest = Join-Path $TestDrive 'new\nested\dest.xml'
        Copy-AssetFile -Source $src -Destination $dest
        Test-Path -Path $dest | Should -BeTrue
        (Get-Content -Path $dest -Raw).Trim() | Should -Be '<DefaultAssociations/>'
    }

    It 'a file-backed customization still serializes as boolean true' {
        $json = ConvertTo-SettingsJson -Organization 'X' -FailureMode 'Lenient' `
            -Selections @([pscustomobject]@{ Name = 'TaskbarPins'; Value = $true })
        ($json | ConvertFrom-Json).Customizations.TaskbarPins | Should -BeTrue
    }
}

Describe 'Emitter is idempotent' {
    It 'produces identical text on repeated calls' {
        $a = ConvertTo-SettingsJson -Organization 'Contoso' -FailureMode 'Lenient' -Selections $AllSelections
        $b = ConvertTo-SettingsJson -Organization 'Contoso' -FailureMode 'Lenient' -Selections $AllSelections
        $a | Should -Be $b
    }
}
