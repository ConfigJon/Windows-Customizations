<#
    .SYNOPSIS
        Static consistency tests for the Windows Customizations engine (Pester 5).

    .DESCRIPTION
        Validates catalog integrity, catalog<->config<->schema consistency, custom-handler
        coverage, source parsing, module exports, encoding/style, and PSScriptAnalyzer
        cleanliness. These run anywhere (no Windows 11 / SYSTEM required). Runtime behavior
        (hive seeding, app removal, branding) must be validated on a test device - see
        Tests\README.md.

    .EXAMPLE
        .\Tests\Invoke-Tests.ps1
#>

# ---- Discovery phase: build data used by -ForEach -----------------------------------------
$RepoRoot = Split-Path -Path $PSScriptRoot -Parent
$PackageDir = Join-Path -Path $RepoRoot -ChildPath 'package'
$EngineDir = Join-Path -Path $PackageDir -ChildPath 'Engine'
$ToolsDir = Join-Path -Path $RepoRoot -ChildPath 'tools'

$DiscoveryCatalog = Import-PowerShellDataFile -Path (Join-Path -Path $EngineDir -ChildPath 'Catalog.psd1')
$EntryCases = foreach ($Entry in $DiscoveryCatalog.Customizations) { @{ Name = $Entry.Name; Entry = $Entry } }

$DiscoveryConfig = Get-Content -Path (Join-Path -Path $PackageDir -ChildPath 'Config\Settings.json') -Raw | ConvertFrom-Json
$ConfigCases = foreach ($Property in $DiscoveryConfig.Customizations.PSObject.Properties) { @{ Name = $Property.Name; Value = $Property.Value } }

$PsFiles = @()
$PsFiles += Get-ChildItem -Path $EngineDir -Recurse -Include *.ps1, *.psm1, *.psd1
$PsFiles += Get-Item -Path (Join-Path -Path $PackageDir -ChildPath 'Set-WindowsCustomizations.ps1')
$PsFiles += Get-Item -Path (Join-Path -Path $PackageDir -ChildPath 'Remove-WindowsCustomizations.ps1')
$PsFiles += Get-ChildItem -Path $ToolsDir -Recurse -Include *.ps1
$FileCases = foreach ($File in $PsFiles) { @{ Name = $File.Name; Path = $File.FullName; Ext = $File.Extension } }
$PsOnlyCases = $FileCases | Where-Object { $_.Ext -in '.ps1', '.psm1', '.psd1' }

$HasAnalyzer = $null -ne (Get-Module -ListAvailable -Name PSScriptAnalyzer)

# ---- Run phase: shared state --------------------------------------------------------------
BeforeAll {
    $RepoRoot = Split-Path -Path $PSScriptRoot -Parent
    $PackageDir = Join-Path -Path $RepoRoot -ChildPath 'package'
    $EngineDir = Join-Path -Path $PackageDir -ChildPath 'Engine'

    $Catalog = Import-PowerShellDataFile -Path (Join-Path -Path $EngineDir -ChildPath 'Catalog.psd1')
    $CatalogIndex = @{}
    foreach ($Entry in $Catalog.Customizations) { $CatalogIndex[$Entry.Name] = $Entry }

    $MechanismsText = Get-Content -Path (Join-Path -Path $EngineDir -ChildPath 'Functions.ps1') -Raw
    $Config = Get-Content -Path (Join-Path -Path $PackageDir -ChildPath 'Config\Settings.json') -Raw | ConvertFrom-Json
    $Schema = Get-Content -Path (Join-Path -Path $PackageDir -ChildPath 'Config\Settings.schema.json') -Raw | ConvertFrom-Json

    $ValidMechanisms = 'DefaultHive', 'HKLM', 'Policy', 'File', 'AppRemoval', 'Dism', 'Custom'
    $ValidTypes = 'String', 'ExpandString', 'Binary', 'DWord', 'MultiString', 'QWord'
    $RegistryMechanisms = 'DefaultHive', 'HKLM', 'Policy'
    $AnalyzerAllow = 'PSAvoidUsingWriteHost', 'PSUseShouldProcessForStateChangingFunctions',
        'PSReviewUnusedParameter', 'PSAvoidUsingEmptyCatchBlock'
}

Describe 'Catalog integrity' {
    It 'has no duplicate customization names' {
        $Names = $Catalog.Customizations.Name
        ($Names | Group-Object | Where-Object Count -GT 1).Count | Should -Be 0
    }

    It 'every DependsOn references an existing entry' {
        $Names = $Catalog.Customizations.Name
        foreach ($Entry in $Catalog.Customizations)
        {
            if ($Entry.ContainsKey('DependsOn'))
            {
                $Names | Should -Contain $Entry.DependsOn -Because "'$($Entry.Name)' DependsOn '$($Entry.DependsOn)', which is not a catalog entry"
            }
        }
    }

    It 'Entry <Name> is well-formed' -ForEach $EntryCases {
        $Entry.Name        | Should -Not -BeNullOrEmpty
        $Entry.Category     | Should -Not -BeNullOrEmpty
        $Entry.Description  | Should -Not -BeNullOrEmpty
        $ValidMechanisms    | Should -Contain $Entry.Mechanism

        if ($Entry.ContainsKey('AllowedValues'))
        {
            ($Entry.AllowedValues -is [System.Array]) | Should -BeTrue -Because 'AllowedValues must be an array'
        }

        switch ($Entry.Mechanism)
        {
            { $_ -in $RegistryMechanisms }
            {
                $Entry.Path      | Should -Not -BeNullOrEmpty
                $Entry.ValueName | Should -Not -BeNullOrEmpty
                $ValidTypes      | Should -Contain $Entry.Type
            }
            'File'
            {
                $Entry.Source      | Should -Not -BeNullOrEmpty
                $Entry.Destination | Should -Not -BeNullOrEmpty
            }
            'AppRemoval'
            {
                $Entry.PackageNames | Should -Not -BeNullOrEmpty
                if ($Entry.ContainsKey('AvailablePackages'))
                {
                    $Entry.AvailablePackages | Should -Not -BeNullOrEmpty
                    # The default removal set must be selectable from the configurator's menu.
                    foreach ($Pkg in $Entry.PackageNames)
                    {
                        $Entry.AvailablePackages | Should -Contain $Pkg -Because "'$Pkg' is a default but not in AvailablePackages"
                    }
                }
            }
            'Dism'
            {
                $Entry.Operation | Should -Not -BeNullOrEmpty
                $Entry.Source    | Should -Not -BeNullOrEmpty
            }
            'Custom'
            {
                $MechanismsText | Should -Match "'$([regex]::Escape($Entry.Name))'" -Because 'every Custom entry needs a handler case in Functions.ps1'
            }
        }
    }
}

Describe 'Config matches catalog' {
    It 'Selection <Name> exists in the catalog' -ForEach $ConfigCases {
        $CatalogIndex.ContainsKey($Name) | Should -BeTrue
    }

    It 'Selection <Name> has an allowed value' -ForEach $ConfigCases {
        $Definition = $CatalogIndex[$Name]
        if ($Definition -and $Definition.AllowedValues -and ($Value -isnot [System.Array]))
        {
            $Definition.AllowedValues | Should -Contain $Value
        }
    }

    It 'FailureMode is Lenient or Strict' {
        $Config.FailureMode | Should -BeIn @('Lenient', 'Strict')
    }

    It 'Organization is set' {
        $Config.Organization | Should -Not -BeNullOrEmpty
    }
}

Describe 'Schema is in sync with the catalog' {
    It 'Schema exposes catalog entry <Name>' -ForEach $EntryCases {
        $SchemaProps = $Schema.properties.Customizations.properties.PSObject.Properties.Name
        $SchemaProps | Should -Contain $Entry.Name
    }

    It 'Schema has no properties without a catalog entry' {
        $SchemaProps = $Schema.properties.Customizations.properties.PSObject.Properties.Name
        foreach ($SchemaProp in $SchemaProps)
        {
            $CatalogIndex.ContainsKey($SchemaProp) | Should -BeTrue -Because "schema property '$SchemaProp' has no catalog entry (regenerate with tools\Update-SettingsSchema.ps1)"
        }
    }
}

Describe 'Source files parse' {
    It '<Name> parses without errors' -ForEach $FileCases {
        $Tokens = $null
        $ParseErrors = $null
        $null = [System.Management.Automation.Language.Parser]::ParseFile($Path, [ref]$Tokens, [ref]$ParseErrors)
        $ParseErrors | Should -BeNullOrEmpty
    }
}

Describe 'Function library (Functions.ps1)' {
    BeforeAll {
        # Dot-source exactly as the engine does; all functions land in one shared scope.
        . (Join-Path -Path $EngineDir -ChildPath 'Functions.ps1')
    }

    It 'defines <FunctionName>' -ForEach @(
        @{ FunctionName = 'Get-DeploymentLogDirectory' }
        @{ FunctionName = 'Initialize-Logging' }
        @{ FunctionName = 'Write-LogEntry' }
        @{ FunctionName = 'Test-IsWindows11' }
        @{ FunctionName = 'Test-IsWinPE' }
        @{ FunctionName = 'Get-TaskSequenceStatus' }
        @{ FunctionName = 'Set-RegistryValue' }
        @{ FunctionName = 'Import-RegistryHive' }
        @{ FunctionName = 'Remove-RegistryHive' }
        @{ FunctionName = 'Remove-RegistryHiveWithRetry' }
        @{ FunctionName = 'Write-VersionStamp' }
        @{ FunctionName = 'Remove-VersionStamp' }
        @{ FunctionName = 'Get-PackageRoot' }
        @{ FunctionName = 'Set-ProtectedFile' }
        @{ FunctionName = 'New-CustomizationResult' }
        @{ FunctionName = 'Invoke-Customization' }
        @{ FunctionName = 'Test-NeedsHive' }
    ) {
        Get-Command -Name $FunctionName -CommandType Function -ErrorAction SilentlyContinue | Should -Not -BeNullOrEmpty
    }

    It 'Test-NeedsHive classifies mechanisms correctly' {
        Test-NeedsHive -Definition @{ Mechanism = 'DefaultHive' } | Should -BeTrue
        Test-NeedsHive -Definition @{ Mechanism = 'HKLM' } | Should -BeFalse
        Test-NeedsHive -Definition @{ Mechanism = 'Custom'; NeedsHive = $true } | Should -BeTrue
        Test-NeedsHive -Definition @{ Mechanism = 'Custom' } | Should -BeFalse
    }

    It 'New-CustomizationResult returns a well-formed result object' {
        $Result = New-CustomizationResult -Name 'X' -Status 'Applied'
        $Result.Name | Should -Be 'X'
        $Result.Status | Should -Be 'Applied'
    }

    It 'Test-IsWinPE keys off the MiniNT control key' {
        Test-IsWinPE | Should -BeFalse -Because 'the suite runs in a full OS'
        Mock Test-Path { $true } -ParameterFilter { $Path -like '*\Control\MiniNT' }
        Test-IsWinPE | Should -BeTrue
    }

    It 'Get-TaskSequenceStatus is false outside a running task sequence' {
        Get-TaskSequenceStatus | Should -BeFalse
    }

    Context 'Get-DeploymentLogDirectory follows the deployment channel' {
        BeforeAll {
            $ImeLogs = Join-Path -Path $env:ALLUSERSPROFILE -ChildPath 'Microsoft\IntuneManagementExtension\Logs'
            $CcmLogs = Join-Path -Path $env:WINDIR -ChildPath 'CCM\Logs'
        }

        It 'uses _SMSTSLogPath inside a running task sequence' {
            Mock Get-TaskSequenceStatus { $true }
            Mock New-Object {
                [pscustomobject]@{} | Add-Member -MemberType ScriptMethod -Name 'Value' -Value { param($Name) 'C:\Windows\CCM\Logs\SMSTSLog' } -PassThru
            } -ParameterFilter { $ComObject -eq 'Microsoft.SMS.TSEnvironment' }
            Get-DeploymentLogDirectory | Should -Be 'C:\Windows\CCM\Logs\SMSTSLog'
        }

        It 'uses CCM\Logs on a ConfigMgr client without the IME' {
            Mock Get-TaskSequenceStatus { $false }
            Mock Get-Service { $null }
            Mock Test-Path { $true } -ParameterFilter { $LiteralPath -eq $CcmLogs }
            Get-DeploymentLogDirectory | Should -Be $CcmLogs
        }

        It 'keeps the IME Logs folder when the IME is installed, even beside a ConfigMgr client' {
            Mock Get-TaskSequenceStatus { $false }
            Mock Get-Service { [pscustomobject]@{ Name = 'IntuneManagementExtension' } }
            Mock Test-Path { $true } -ParameterFilter { $LiteralPath -eq $CcmLogs }
            Get-DeploymentLogDirectory | Should -Be $ImeLogs
        }

        It 'defaults to the IME Logs folder with neither agent present' {
            Mock Get-TaskSequenceStatus { $false }
            Mock Get-Service { $null }
            Mock Test-Path { $false } -ParameterFilter { $LiteralPath -eq $CcmLogs }
            Get-DeploymentLogDirectory | Should -Be $ImeLogs
        }
    }
}

Describe 'Detection script' {
    BeforeAll {
        # Stamp an Organization no machine has (as New-Package.ps1 stamps the real one), so the
        # version stamp is guaranteed absent.
        $DetectionSource = Get-Content -Path (Join-Path -Path $RepoRoot -ChildPath 'tools\Detect-WindowsCustomizations.ps1') -Raw
        $TestOrganization = 'WCTest' + [guid]::NewGuid().ToString('N')
        $DetectionSource = $DetectionSource -replace "(\`$Organization\s*=\s*)'[^']*'", "`$1'$TestOrganization'"
        $DetectionCopy = Join-Path -Path $TestDrive -ChildPath 'Detect-WindowsCustomizations.ps1'
        Set-Content -Path $DetectionCopy -Value $DetectionSource
    }

    It 'reports not-detected as exit 0 with no output (the contract Intune and ConfigMgr share)' {
        $PowerShell = Join-Path -Path $env:WINDIR -ChildPath 'System32\WindowsPowerShell\v1.0\powershell.exe'
        $Output = & $PowerShell -NoProfile -ExecutionPolicy Bypass -File $DetectionCopy
        $LASTEXITCODE | Should -Be 0 -Because 'ConfigMgr reads a non-zero exit as a script failure, not "not installed"'
        $Output | Should -BeNullOrEmpty
    }
}

Describe 'Encoding and style' {
    It '<Name> has no UTF-8 BOM' -ForEach $FileCases {
        $Bytes = [System.IO.File]::ReadAllBytes($Path)
        ($Bytes.Length -ge 3 -and $Bytes[0] -eq 0xEF -and $Bytes[1] -eq 0xBB -and $Bytes[2] -eq 0xBF) | Should -BeFalse
    }

    It '<Name> uses CRLF line endings' -ForEach $FileCases {
        $Text = [System.IO.File]::ReadAllText($Path)
        [regex]::IsMatch($Text, '(?<!\r)\n') | Should -BeFalse -Because 'committed PowerShell files use CRLF'
    }

    It '<Name> has no trailing whitespace' -ForEach $FileCases {
        $Text = [System.IO.File]::ReadAllText($Path)
        [regex]::IsMatch($Text, '[ \t]+(\r?\n|$)') | Should -BeFalse
    }

    It '<Name> is ASCII-only (PowerShell source)' -ForEach $PsOnlyCases {
        $Text = [System.IO.File]::ReadAllText($Path)
        [regex]::IsMatch($Text, '[^\x00-\x7F]') | Should -BeFalse -Because 'PS files stay ASCII so no BOM is needed'
    }
}

Describe 'PSScriptAnalyzer' -Skip:(-not $HasAnalyzer) {
    It '<Name> has no Error findings and only allowed warnings' -ForEach $FileCases {
        $Findings = Invoke-ScriptAnalyzer -Path $Path -Severity Warning, Error
        ($Findings | Where-Object Severity -EQ 'Error') | Should -BeNullOrEmpty
        $Disallowed = $Findings | Where-Object { $_.RuleName -notin $AnalyzerAllow }
        $Disallowed | Should -BeNullOrEmpty -Because ("unexpected: " + (($Disallowed | ForEach-Object RuleName) -join ', '))
    }
}
