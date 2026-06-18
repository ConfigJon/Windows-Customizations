#Requires -Version 5.1
<#
.SYNOPSIS
    Interactive, point-and-click configurator for package\Config\Settings.json.

.DESCRIPTION
    Reads the customization catalog (package\Engine\Catalog.psd1) and opens a window where
    you tick the customizations you want and pick their values from drop-downs. On
    Save it writes a valid package\Config\Settings.json - no JSON editing, no flipping between
    the settings file and the schema to look up names and allowed values.

    The window is built entirely from the catalog, so it always lists exactly the
    settings the engine supports. Advanced users can still hand-edit Settings.json
    directly; this tool is an optional convenience and round-trips the existing file
    (your current selections are pre-ticked when it opens).

.PARAMETER CatalogPath
    Override the catalog location. Defaults to package\Engine\Catalog.psd1.

.PARAMETER ConfigPath
    Override the output config location. Defaults to package\Config\Settings.json.

.PARAMETER SelfTest
    Non-GUI sanity check: load the catalog, round-trip the existing Settings.json, and
    print the regenerated JSON to the console without writing any file. Used for testing.

.EXAMPLE
    .\Configure-Settings.ps1
    Opens the configurator window, pre-loaded with the current Settings.json.

.EXAMPLE
    .\Configure-Settings.ps1 -SelfTest
    Prints the JSON that would be generated from the current selections (no GUI, no write).
#>
[CmdletBinding()]
param(
    [string]$CatalogPath,
    [string]$ConfigPath,
    [switch]$SelfTest
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# This tool lives in tools\; the payload (catalog, config, assets) is the sibling package\ folder.
$PackageRoot = Join-Path -Path (Split-Path -Path $PSScriptRoot -Parent) -ChildPath 'package'
if (-not $CatalogPath) { $CatalogPath = Join-Path -Path $PackageRoot -ChildPath 'Engine\Catalog.psd1' }
if (-not $ConfigPath)  { $ConfigPath  = Join-Path -Path $PackageRoot -ChildPath 'Config\Settings.json' }

# ----------------------------------------------------------------------------------------------
# Core (GUI-independent) helpers
# ----------------------------------------------------------------------------------------------

function Get-Catalog
{
    param([string]$Path)
    if (-not (Test-Path -Path $Path)) { throw "Catalog not found: $Path" }
    $data = Import-PowerShellDataFile -Path $Path
    return $data.Customizations
}

function Get-SettingKind
{
    # 'enum'  -> has AllowedValues (drop-down of integers)
    # 'array' -> AppRemoval (on/off, with an editable package list; may carry a custom string array)
    # 'file'  -> File/Dism backed by a single in-package asset (on/off, with a Browse button)
    # 'toggle'-> everything else (on writes boolean true)
    param([hashtable]$Definition)
    if ($Definition.ContainsKey('AllowedValues') -and @($Definition.AllowedValues).Count -gt 0) { return 'enum' }
    if ($Definition.Mechanism -eq 'AppRemoval') { return 'array' }
    if (($Definition.Mechanism -in @('File', 'Dism')) -and $Definition.ContainsKey('Source')) { return 'file' }
    return 'toggle'
}

function Get-ValueLabel
{
    # Pull the "N = meaning" wording out of a Description so a drop-down can show
    # "1 = icon" instead of a bare "1". Falls back to the number if no wording exists.
    param([string]$Description, [int]$Value)
    foreach ($m in [regex]::Matches($Description, '(\d+)\s*=\s*([^,]+)'))
    {
        if ([int]$m.Groups[1].Value -eq $Value)
        {
            return ('{0} = {1}' -f $Value, $m.Groups[2].Value.Trim())
        }
    }
    return [string]$Value
}

function Test-AssetFile
{
    # Structural validation of a browsed asset before it is copied into Assets\.
    # XML files must parse; if $ExpectedRoot is given, the root element must match (catches
    # "browsed the wrong file"). Non-XML assets (e.g. start2.bin) get a non-empty check only.
    # Returns an object with .Ok (bool) and .Message (string).
    param([string]$Path, [string]$ExpectedRoot)

    if (-not (Test-Path -Path $Path -PathType Leaf))
    {
        return [pscustomobject]@{ Ok = $false; Message = "File not found: $Path" }
    }
    if ([System.IO.Path]::GetExtension($Path).ToLowerInvariant() -eq '.xml')
    {
        try
        {
            $xml = New-Object System.Xml.XmlDocument
            $xml.Load($Path)
        }
        catch
        {
            return [pscustomobject]@{ Ok = $false; Message = "Not valid XML: $($_.Exception.Message)" }
        }
        if ($ExpectedRoot)
        {
            if ((-not $xml.DocumentElement) -or ($xml.DocumentElement.LocalName -ne $ExpectedRoot))
            {
                $got = if ($xml.DocumentElement) { $xml.DocumentElement.LocalName } else { '(none)' }
                return [pscustomobject]@{ Ok = $false; Message = "Unexpected root <$got>; expected <$ExpectedRoot>. Wrong file?" }
            }
        }
        return [pscustomobject]@{ Ok = $true; Message = 'OK' }
    }
    if ((Get-Item -Path $Path).Length -eq 0)
    {
        return [pscustomobject]@{ Ok = $false; Message = 'File is empty.' }
    }
    return [pscustomobject]@{ Ok = $true; Message = 'OK' }
}

function Copy-AssetFile
{
    param([string]$Source, [string]$Destination)
    $dir = Split-Path -Path $Destination -Parent
    if ($dir -and -not (Test-Path -Path $dir)) { New-Item -Path $dir -ItemType Directory -Force | Out-Null }
    Copy-Item -Path $Source -Destination $Destination -Force -ErrorAction Stop
}

function Test-SamePackageSet
{
    # Order- and case-insensitive set equality for package-name lists. Used to decide whether
    # a selection equals the catalog default (write `true`) or differs (write an explicit array).
    param([string[]]$A, [string[]]$B)
    $sa = @($A | Sort-Object -Unique)
    $sb = @($B | Sort-Object -Unique)
    if ($sa.Count -ne $sb.Count) { return $false }
    for ($i = 0; $i -lt $sa.Count; $i++)
    {
        if ($sa[$i] -ne $sb[$i]) { return $false }
    }
    return $true
}

function ConvertTo-JsonString
{
    param([string]$Text)
    $escaped = $Text.Replace('\', '\\').Replace('"', '\"')
    return '"' + $escaped + '"'
}

function Format-JsonValue
{
    # Render a single Customizations value. Base indent for the key is 4 spaces, so an
    # array's items sit at 6 and its closing bracket back at 4.
    param($Value)
    if ($Value -is [bool])
    {
        if ($Value) { return 'true' } else { return 'false' }
    }
    if ($Value -is [array])
    {
        if (@($Value).Count -eq 0) { return '[]' }
        $nl = "`r`n"
        $items = foreach ($element in $Value) { '      ' + (ConvertTo-JsonString ([string]$element)) }
        return '[' + $nl + ($items -join (',' + $nl)) + $nl + '    ]'
    }
    if ($Value -is [int] -or $Value -is [long] -or $Value -is [int16] -or $Value -is [byte])
    {
        return [string]$Value
    }
    return ConvertTo-JsonString ([string]$Value)
}

function ConvertTo-SettingsJson
{
    # Selections: ordered collection of objects with .Name and .Value (already typed).
    param(
        [string]$Organization,
        [string]$FailureMode,
        $Selections
    )
    $nl = "`r`n"
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.Append('{' + $nl)
    [void]$sb.Append('  "$schema": "./Settings.schema.json",' + $nl)
    [void]$sb.Append('  "Organization": ' + (ConvertTo-JsonString $Organization) + ',' + $nl)
    [void]$sb.Append('  "FailureMode": ' + (ConvertTo-JsonString $FailureMode) + ',' + $nl)
    [void]$sb.Append('  "Customizations": {' + $nl)

    $lines = @()
    foreach ($s in $Selections)
    {
        $lines += '    ' + (ConvertTo-JsonString $s.Name) + ': ' + (Format-JsonValue $s.Value)
    }
    if ($lines.Count -gt 0) { [void]$sb.Append(($lines -join (',' + $nl)) + $nl) }

    [void]$sb.Append('  }' + $nl)
    [void]$sb.Append('}' + $nl)
    return $sb.ToString()
}

function Read-ExistingConfig
{
    param([string]$Path)
    if (-not (Test-Path -Path $Path)) { return $null }
    try { return (Get-Content -Path $Path -Raw | ConvertFrom-Json) }
    catch { return $null }
}

function Get-ExistingCustomization
{
    # Returns the configured value for $Name, or $null if not present/enabled.
    param($Config, [string]$Name)
    if ($null -eq $Config -or -not $Config.PSObject.Properties['Customizations']) { return $null }
    if ($null -eq $Config.Customizations) { return $null }
    $prop = $Config.Customizations.PSObject.Properties[$Name]
    if ($null -eq $prop) { return $null }
    return $prop.Value
}

function Write-SettingsFile
{
    param([string]$Path, [string]$Content)
    $dir = Split-Path -Path $Path -Parent
    if ($dir -and -not (Test-Path -Path $dir)) { New-Item -Path $dir -ItemType Directory -Force | Out-Null }
    # UTF-8 without BOM, CRLF line endings (repo .gitattributes treats *.json as crlf).
    $utf8 = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($Path, $Content, $utf8)
}

# ----------------------------------------------------------------------------------------------
# Self-test: round-trip the existing config through the emitter, print, and exit.
# ----------------------------------------------------------------------------------------------

function Invoke-SelfTest
{
    param([string]$CatalogPath, [string]$ConfigPath)
    $catalog = Get-Catalog -Path $CatalogPath
    $config  = Read-ExistingConfig -Path $ConfigPath

    $org    = 'Organization'
    $fail   = 'Lenient'
    if ($null -ne $config)
    {
        if ($config.PSObject.Properties['Organization']) { $org = $config.Organization }
        if ($config.PSObject.Properties['FailureMode'])  { $fail = $config.FailureMode }
    }

    $selections = New-Object System.Collections.Generic.List[object]
    foreach ($def in $catalog)
    {
        $value = Get-ExistingCustomization -Config $config -Name $def.Name
        if ($null -eq $value) { continue }
        $selections.Add([pscustomobject]@{ Name = $def.Name; Value = $value })
    }

    ConvertTo-SettingsJson -Organization $org -FailureMode $fail -Selections $selections |
        Write-Output
}

# ----------------------------------------------------------------------------------------------
# GUI
# ----------------------------------------------------------------------------------------------

function Set-AssetStatusLabel
{
    # Reflects whether the in-package asset file currently exists.
    param($Label, [string]$Target)
    if (Test-Path -Path $Target -PathType Leaf)
    {
        $Label.Text = 'Provided'
        $Label.ForeColor = [System.Drawing.Color]::ForestGreen
    }
    else
    {
        $Label.Text = 'Not set'
        $Label.ForeColor = [System.Drawing.Color]::DimGray
    }
}

function Show-PackageListDialog
{
    # Modal checklist of provisioned apps. $Available is the catalog menu; $Checked is the current
    # selection (its members are pre-ticked, and any not in $Available are added as custom rows).
    # Returns the selected string[] (possibly empty) on OK, or $null on Cancel.
    param([string[]]$Available, [string[]]$Checked, [string]$Title)

    $dlg = New-Object System.Windows.Forms.Form
    $dlg.Text = $Title
    $dlg.Size = New-Object System.Drawing.Size(400, 500)
    $dlg.StartPosition = 'CenterParent'
    $dlg.FormBorderStyle = 'FixedDialog'
    $dlg.MaximizeBox = $false
    $dlg.MinimizeBox = $false

    $lbl = New-Object System.Windows.Forms.Label
    $lbl.Text = 'Check the apps to remove. Add custom package names below.'
    $lbl.Location = New-Object System.Drawing.Point(12, 10)
    $lbl.AutoSize = $true

    $clb = New-Object System.Windows.Forms.CheckedListBox
    $clb.Location = New-Object System.Drawing.Point(12, 36)
    $clb.Size = New-Object System.Drawing.Size(360, 350)
    $clb.CheckOnClick = $true
    $clb.IntegralHeight = $false

    $ordered = New-Object System.Collections.Generic.List[string]
    foreach ($a in $Available) { if (-not $ordered.Contains($a)) { $ordered.Add($a) } }
    foreach ($c in $Checked) { if (-not $ordered.Contains($c)) { $ordered.Add($c) } }
    foreach ($name in $ordered) { [void]$clb.Items.Add($name, ($Checked -contains $name)) }

    $txtAdd = New-Object System.Windows.Forms.TextBox
    $txtAdd.Location = New-Object System.Drawing.Point(12, 396)
    $txtAdd.Width = 260
    $tipAdd = New-Object System.Windows.Forms.ToolTip
    $tipAdd.SetToolTip($txtAdd, 'Provisioned package name, e.g. Microsoft.SomeApp')

    $btnAdd = New-Object System.Windows.Forms.Button
    $btnAdd.Text = 'Add'
    $btnAdd.Location = New-Object System.Drawing.Point(282, 394)
    $btnAdd.Size = New-Object System.Drawing.Size(90, 25)
    $btnAdd.Add_Click({
        $name = $txtAdd.Text.Trim()
        if ($name)
        {
            $idx = $clb.Items.IndexOf($name)
            if ($idx -lt 0) { $idx = $clb.Items.Add($name, $true) }
            $clb.SetItemChecked($idx, $true)
            $txtAdd.Clear()
        }
    }.GetNewClosure())

    $btnOk = New-Object System.Windows.Forms.Button
    $btnOk.Text = 'OK'
    $btnOk.DialogResult = [System.Windows.Forms.DialogResult]::OK
    $btnOk.Size = New-Object System.Drawing.Size(90, 28)
    $btnOk.Location = New-Object System.Drawing.Point(192, 430)

    $btnCancel = New-Object System.Windows.Forms.Button
    $btnCancel.Text = 'Cancel'
    $btnCancel.DialogResult = [System.Windows.Forms.DialogResult]::Cancel
    $btnCancel.Size = New-Object System.Drawing.Size(90, 28)
    $btnCancel.Location = New-Object System.Drawing.Point(282, 430)

    $dlg.AcceptButton = $btnOk
    $dlg.CancelButton = $btnCancel
    $dlg.Controls.AddRange(@($lbl, $clb, $txtAdd, $btnAdd, $btnOk, $btnCancel))

    if ($dlg.ShowDialog() -ne [System.Windows.Forms.DialogResult]::OK) { return $null }

    $selected = New-Object System.Collections.Generic.List[string]
    foreach ($item in $clb.CheckedItems) { $selected.Add([string]$item) }
    return , ([string[]]$selected.ToArray())
}

function Show-ConfiguratorWindow
{
    param([string]$CatalogPath, [string]$ConfigPath)

    Add-Type -AssemblyName System.Windows.Forms
    Add-Type -AssemblyName System.Drawing
    [System.Windows.Forms.Application]::EnableVisualStyles()

    $catalog = Get-Catalog -Path $CatalogPath
    $config  = Read-ExistingConfig -Path $ConfigPath

    # ---- Form shell -----------------------------------------------------------------------
    $form = New-Object System.Windows.Forms.Form
    $form.Text = 'Windows Customizations - Settings'
    $form.MinimumSize = New-Object System.Drawing.Size(640, 480)
    # Size to the preferred dimensions but never larger than the visible work area, and center
    # it there manually. Otherwise on a short / high-DPI screen the window can be taller than the
    # desktop and the bottom-docked Save/Cancel footer ends up below the screen edge. The body
    # panel scrolls, so a smaller window still shows every setting.
    $work = [System.Windows.Forms.Screen]::PrimaryScreen.WorkingArea
    $w = [Math]::Min(820, $work.Width)
    $h = [Math]::Min(760, $work.Height)
    $form.StartPosition = 'Manual'
    $form.Size = New-Object System.Drawing.Size($w, $h)
    $form.Location = New-Object System.Drawing.Point(
        ($work.X + [int](($work.Width - $w) / 2)),
        ($work.Y + [int](($work.Height - $h) / 2)))
    $tip = New-Object System.Windows.Forms.ToolTip
    $tip.AutoPopDelay = 20000

    # ---- Header: Organization / FailureMode -----------------------------------------------
    $header = New-Object System.Windows.Forms.Panel
    $header.Dock = 'Top'
    $header.Height = 96
    $header.Padding = New-Object System.Windows.Forms.Padding(12, 10, 12, 6)

    $lblOrg = New-Object System.Windows.Forms.Label
    $lblOrg.Text = 'Organization:'
    $lblOrg.Location = New-Object System.Drawing.Point(12, 14)
    $lblOrg.AutoSize = $true

    $txtOrg = New-Object System.Windows.Forms.TextBox
    $txtOrg.Location = New-Object System.Drawing.Point(110, 11)
    $txtOrg.Width = 240
    $txtOrg.Text = if ($config -and $config.PSObject.Properties['Organization']) { [string]$config.Organization } else { 'Organization' }
    $tip.SetToolTip($txtOrg, 'Registry namespace for the install version-stamp (HKLM\SOFTWARE\<name>\WindowsCustomizations), checked by the Intune detection rule. If you change it, rebuild the package and re-upload the detection script.')

    # Visible hint (the same info as the tooltip, in case the user does not hover).
    $lblOrgHint = New-Object System.Windows.Forms.Label
    $lblOrgHint.Text = 'Names the version-stamp registry key; rebuild package if changed.'
    $lblOrgHint.Location = New-Object System.Drawing.Point(360, 14)
    $lblOrgHint.AutoSize = $true
    $lblOrgHint.ForeColor = [System.Drawing.Color]::DimGray

    # On failure: own row under Organization, with its description right beside the dropdown.
    $lblFail = New-Object System.Windows.Forms.Label
    $lblFail.Text = 'On failure:'
    $lblFail.Location = New-Object System.Drawing.Point(12, 50)
    $lblFail.AutoSize = $true

    $cmbFail = New-Object System.Windows.Forms.ComboBox
    $cmbFail.DropDownStyle = 'DropDownList'
    $cmbFail.Location = New-Object System.Drawing.Point(110, 47)
    $cmbFail.Width = 120
    [void]$cmbFail.Items.AddRange(@('Lenient', 'Strict'))
    $curFail = if ($config -and $config.PSObject.Properties['FailureMode']) { [string]$config.FailureMode } else { 'Lenient' }
    $cmbFail.SelectedItem = if ($cmbFail.Items.Contains($curFail)) { $curFail } else { 'Lenient' }
    $tip.SetToolTip($cmbFail, 'Lenient = log and continue; Strict = any failure fails the app.')

    $lblFailHelp = New-Object System.Windows.Forms.Label
    $lblFailHelp.Text = 'Lenient = log failures and continue.   Strict = any failure fails the whole app.'
    $lblFailHelp.Location = New-Object System.Drawing.Point(244, 50)
    $lblFailHelp.AutoSize = $true
    $lblFailHelp.ForeColor = [System.Drawing.Color]::DimGray

    $header.Controls.AddRange(@($lblOrg, $txtOrg, $lblOrgHint, $lblFail, $cmbFail, $lblFailHelp))

    # ---- Scrolling body: one section per category -----------------------------------------
    $body = New-Object System.Windows.Forms.Panel
    $body.Dock = 'Fill'
    $body.AutoScroll = $true
    $body.Padding = New-Object System.Windows.Forms.Padding(12, 4, 12, 4)

    $rows = New-Object System.Collections.Generic.List[object]
    $boldFont = New-Object System.Drawing.Font($form.Font.FontFamily, 10, [System.Drawing.FontStyle]::Bold)
    $grayBrush = [System.Drawing.Color]::DimGray
    $y = 6
    $lastCategory = $null
    $lockHeaderShown = $false

    # Render preference (user-changeable) settings first, then the locking Group-Policy settings as a
    # clearly delineated group at the bottom. Preferences are grouped by Category (preserving the
    # first-seen category order and the order within each category) so settings of the same category
    # always share one header even when scattered in the catalog - e.g. the File-seed TaskbarPins /
    # StartLayout entries, which live in a separate catalog section but belong under Taskbar / Start.
    $prefDefs = @($catalog | Where-Object { $_.Mechanism -ne 'Policy' })
    $lockDefs = @($catalog | Where-Object { $_.Mechanism -eq 'Policy' })

    $catOrder = New-Object System.Collections.Generic.List[string]
    $byCategory = @{}
    foreach ($d in $prefDefs)
    {
        if (-not $byCategory.ContainsKey($d.Category))
        {
            $catOrder.Add($d.Category)
            $byCategory[$d.Category] = New-Object System.Collections.Generic.List[object]
        }
        $byCategory[$d.Category].Add($d)
    }

    $orderedCatalog = @()
    foreach ($c in $catOrder) { $orderedCatalog += $byCategory[$c] }
    $orderedCatalog += $lockDefs

    # Master header for the preference (user-changeable) section, matching the locking banner below.
    $prefHdr = New-Object System.Windows.Forms.Label
    $prefHdr.Text = 'Preference settings'
    $prefHdr.Font = $boldFont
    $prefHdr.ForeColor = [System.Drawing.Color]::SteelBlue
    $prefHdr.Location = New-Object System.Drawing.Point(6, $y)
    $prefHdr.AutoSize = $true
    $body.Controls.Add($prefHdr)
    $y += 22

    $prefNote = New-Object System.Windows.Forms.Label
    $prefNote.UseMnemonic = $false
    $prefNote.Text = 'Seeded as defaults; users can still change them in Windows.'
    $prefNote.ForeColor = $grayBrush
    $prefNote.Location = New-Object System.Drawing.Point(6, $y)
    $prefNote.AutoSize = $true
    $body.Controls.Add($prefNote)
    $y += 24

    foreach ($def in $orderedCatalog)
    {
        $isLocking = ($def.Mechanism -eq 'Policy')

        # Divider + banner marking the boundary between preference and locking settings.
        if ($isLocking -and -not $lockHeaderShown)
        {
            $y += 12
            $sep = New-Object System.Windows.Forms.Panel
            $sep.Location = New-Object System.Drawing.Point(6, $y)
            $sep.Size = New-Object System.Drawing.Size(760, 1)
            $sep.BackColor = [System.Drawing.Color]::Silver
            $body.Controls.Add($sep)
            $y += 8

            $lockHdr = New-Object System.Windows.Forms.Label
            $lockHdr.Text = 'Locking settings (Group Policy)'
            $lockHdr.Font = $boldFont
            $lockHdr.ForeColor = [System.Drawing.Color]::Firebrick
            $lockHdr.Location = New-Object System.Drawing.Point(6, $y)
            $lockHdr.AutoSize = $true
            $body.Controls.Add($lockHdr)
            $y += 22

            $lockNote = New-Object System.Windows.Forms.Label
            $lockNote.UseMnemonic = $false
            $lockNote.Text = 'Applied as Group Policy: greys out the control in Windows so users cannot change it. Leave unchecked unless locking is intended.'
            $lockNote.ForeColor = $grayBrush
            $lockNote.Location = New-Object System.Drawing.Point(6, $y)
            $lockNote.AutoSize = $true
            $body.Controls.Add($lockNote)
            $y += 24

            $lockHeaderShown = $true
            $lastCategory = $null   # don't carry a preference category into the locking group
        }

        # Per-category headers apply only within the preference section.
        if (-not $isLocking -and $def.Category -ne $lastCategory)
        {
            $hdr = New-Object System.Windows.Forms.Label
            $hdr.Text = $def.Category
            $hdr.Font = $boldFont
            $hdr.Location = New-Object System.Drawing.Point(6, $y)
            $hdr.AutoSize = $true
            $body.Controls.Add($hdr)
            $y += 26
            $lastCategory = $def.Category
        }

        $kind = Get-SettingKind -Definition $def
        $existing = Get-ExistingCustomization -Config $config -Name $def.Name
        $dependsOn = if ($def.ContainsKey('DependsOn')) { [string]$def.DependsOn } else { $null }

        $chk = New-Object System.Windows.Forms.CheckBox
        $chk.Text = $def.Name
        $chk.Location = New-Object System.Drawing.Point(20, ($y + 2))
        $chk.Width = 230
        $chk.Checked = ($null -ne $existing)
        $tip.SetToolTip($chk, $def.Description)

        $combo = $null
        $packageState = $null
        $defaultPackages = $null
        if ($kind -eq 'enum')
        {
            $combo = New-Object System.Windows.Forms.ComboBox
            $combo.DropDownStyle = 'DropDownList'
            $combo.Location = New-Object System.Drawing.Point(256, $y)
            $combo.Width = 150
            foreach ($v in $def.AllowedValues)
            {
                $item = [pscustomobject]@{ Text = (Get-ValueLabel -Description $def.Description -Value ([int]$v)); Value = [int]$v }
                [void]$combo.Items.Add($item)
            }
            $combo.DisplayMember = 'Text'
            # Pre-select existing value, else first allowed value.
            $target = if ($null -ne $existing -and ($existing -is [int] -or $existing -is [long])) { [int]$existing } else { [int]$def.AllowedValues[0] }
            for ($i = 0; $i -lt $combo.Items.Count; $i++)
            {
                if ($combo.Items[$i].Value -eq $target) { $combo.SelectedIndex = $i; break }
            }
            if ($combo.SelectedIndex -lt 0) { $combo.SelectedIndex = 0 }
            $combo.Enabled = $chk.Checked
            # Capture this row's combo for the CheckedChanged handler.
            $chk.Add_CheckedChanged({ param($s, $e) $s.Tag.Enabled = $s.Checked }.GetNewClosure())
            $chk.Tag = $combo
            $body.Controls.Add($combo)
        }
        elseif ($kind -eq 'array')
        {
            $defaultPackages = [string[]]@($def.PackageNames)
            $available = if ($def.ContainsKey('AvailablePackages')) { [string[]]@($def.AvailablePackages) } else { $defaultPackages }
            # Current selection: an explicit array overrides; otherwise start from the default set.
            $initial = if ($existing -is [array]) { [string[]]$existing } else { [string[]]$defaultPackages }
            # Mutable holder so the dialog's closure can write back the edited list.
            $packageState = [pscustomobject]@{ Selected = $initial; Available = $available }

            $btnEdit = New-Object System.Windows.Forms.Button
            $btnEdit.Text = 'Edit list...'
            $btnEdit.Location = New-Object System.Drawing.Point(256, ($y - 1))
            $btnEdit.Size = New-Object System.Drawing.Size(100, 24)
            $btnEdit.Enabled = $chk.Checked
            $btnEdit.Tag = $packageState
            # No GetNewClosure here: this handler calls the script-level Show-PackageListDialog,
            # which a closure's private module scope cannot see. Per-row state travels via $s.Tag.
            $btnEdit.Add_Click({
                param($s, $e)
                $picked = Show-PackageListDialog -Available $s.Tag.Available -Checked $s.Tag.Selected -Title 'Provisioned apps to remove'
                if ($null -ne $picked) { $s.Tag.Selected = $picked }
            })

            $chk.Add_CheckedChanged({ param($s, $e) $s.Tag.Enabled = $s.Checked }.GetNewClosure())
            $chk.Tag = $btnEdit
            $body.Controls.Add($btnEdit)
        }
        elseif ($kind -eq 'file')
        {
            $target = Join-Path -Path $PackageRoot -ChildPath $def.Source
            $ext = [System.IO.Path]::GetExtension($target)
            $expectedRoot = if ($def.ContainsKey('AssetRoot')) { [string]$def.AssetRoot } else { $null }

            $statusLabel = New-Object System.Windows.Forms.Label
            $statusLabel.Location = New-Object System.Drawing.Point(348, ($y + 4))
            $statusLabel.AutoSize = $true
            Set-AssetStatusLabel -Label $statusLabel -Target $target

            $btnBrowse = New-Object System.Windows.Forms.Button
            $btnBrowse.Text = 'Browse...'
            $btnBrowse.Location = New-Object System.Drawing.Point(256, ($y - 1))
            $btnBrowse.Size = New-Object System.Drawing.Size(85, 24)
            $btnBrowse.Enabled = $chk.Checked
            $btnBrowse.Tag = [pscustomobject]@{
                Target       = $target
                ExpectedRoot = $expectedRoot
                Status       = $statusLabel
                Filter       = "$ext files (*$ext)|*$ext|All files (*.*)|*.*"
                Name         = $def.Name
            }
            # No GetNewClosure: this handler calls the script-level Test-AssetFile / Copy-AssetFile;
            # per-row data travels via $s.Tag.
            $btnBrowse.Add_Click({
                param($s, $e)
                $ofd = New-Object System.Windows.Forms.OpenFileDialog
                $ofd.Title = "Select file for $($s.Tag.Name)"
                $ofd.Filter = $s.Tag.Filter
                if ($ofd.ShowDialog() -ne [System.Windows.Forms.DialogResult]::OK) { return }

                $check = Test-AssetFile -Path $ofd.FileName -ExpectedRoot $s.Tag.ExpectedRoot
                if (-not $check.Ok)
                {
                    [System.Windows.Forms.MessageBox]::Show($check.Message, 'Invalid file',
                        [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Warning) | Out-Null
                    return
                }
                if (Test-Path -Path $s.Tag.Target)
                {
                    $resp = [System.Windows.Forms.MessageBox]::Show("Replace the existing asset?`n$($s.Tag.Target)", 'Confirm overwrite',
                        [System.Windows.Forms.MessageBoxButtons]::YesNo, [System.Windows.Forms.MessageBoxIcon]::Question)
                    if ($resp -ne [System.Windows.Forms.DialogResult]::Yes) { return }
                }
                try { Copy-AssetFile -Source $ofd.FileName -Destination $s.Tag.Target }
                catch
                {
                    [System.Windows.Forms.MessageBox]::Show("Copy failed:`n$($_.Exception.Message)", 'Error',
                        [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error) | Out-Null
                    return
                }
                Set-AssetStatusLabel -Label $s.Tag.Status -Target $s.Tag.Target
                [System.Windows.Forms.MessageBox]::Show("Copied to:`n$($s.Tag.Target)", 'Asset staged',
                    [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information) | Out-Null
            })

            $chk.Add_CheckedChanged({ param($s, $e) $s.Tag.Enabled = $s.Checked }.GetNewClosure())
            $chk.Tag = $btnBrowse
            $body.Controls.Add($btnBrowse)
            $body.Controls.Add($statusLabel)
        }

        $desc = New-Object System.Windows.Forms.Label
        $desc.UseMnemonic = $false   # show literal '&' (e.g. "app & system"), not a keyboard accelerator
        $desc.Text = $def.Description
        $desc.ForeColor = $grayBrush
        $desc.Location = New-Object System.Drawing.Point(416, ($y + 3))
        $desc.AutoSize = $false
        $desc.Width = 350
        $desc.Height = 30
        $body.Controls.Add($desc)
        $body.Controls.Add($chk)

        $rows.Add([pscustomobject]@{
            Name            = $def.Name
            Kind            = $kind
            CheckBox        = $chk
            Combo           = $combo
            Original        = $existing
            PackageState    = $packageState
            DefaultPackages = $defaultPackages
            DependsOn       = $dependsOn
        })

        $y += 32
    }

    # Wire prerequisite dependencies: a dependent setting is enabled only while its prerequisite
    # is checked (e.g. DynamicTime requires EnableLocationServices). Unchecking the prerequisite
    # greys out and clears the dependent.
    foreach ($depRow in $rows)
    {
        if (-not $depRow.DependsOn) { continue }
        $prereqRow = $rows | Where-Object { $_.Name -eq $depRow.DependsOn } | Select-Object -First 1
        if (-not $prereqRow) { continue }
        $depChk = $depRow.CheckBox
        $depChk.Enabled = $prereqRow.CheckBox.Checked
        if (-not $prereqRow.CheckBox.Checked) { $depChk.Checked = $false }
        $prereqRow.CheckBox.Add_CheckedChanged({
            param($s, $e)
            $depChk.Enabled = $s.Checked
            if (-not $s.Checked) { $depChk.Checked = $false }
        }.GetNewClosure())
    }

    # ---- Footer: Save / Cancel ------------------------------------------------------------
    $footer = New-Object System.Windows.Forms.Panel
    $footer.Dock = 'Bottom'
    $footer.Height = 52

    $lblPath = New-Object System.Windows.Forms.Label
    $lblPath.Text = "Writes: $ConfigPath"
    $lblPath.ForeColor = $grayBrush
    $lblPath.Location = New-Object System.Drawing.Point(14, 18)
    $lblPath.AutoSize = $true

    $btnSave = New-Object System.Windows.Forms.Button
    $btnSave.Text = 'Save'
    $btnSave.Size = New-Object System.Drawing.Size(100, 30)
    $btnSave.Margin = New-Object System.Windows.Forms.Padding(6, 10, 6, 0)

    $btnCancel = New-Object System.Windows.Forms.Button
    $btnCancel.Text = 'Cancel'
    $btnCancel.Size = New-Object System.Drawing.Size(100, 30)
    $btnCancel.Margin = New-Object System.Windows.Forms.Padding(6, 10, 6, 0)
    $btnCancel.Add_Click({ $form.Close() })

    $btnSave.Add_Click({
        $org = $txtOrg.Text.Trim()
        if (-not $org)
        {
            [System.Windows.Forms.MessageBox]::Show('Organization cannot be empty.', 'Validation',
                [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Warning) | Out-Null
            return
        }

        $selections = New-Object System.Collections.Generic.List[object]
        foreach ($row in $rows)
        {
            if (-not $row.CheckBox.Checked) { continue }
            switch ($row.Kind)
            {
                'enum'  { $value = [int]$row.Combo.SelectedItem.Value }
                'array'
                {
                    # Write `true` (use the catalog default) when the selection matches it; an
                    # explicit array only when the user picked a different set.
                    $picked = [string[]]@($row.PackageState.Selected)
                    if (Test-SamePackageSet -A $picked -B $row.DefaultPackages) { $value = $true }
                    else { $value = $picked }
                }
                default { $value = $true }
            }
            $selections.Add([pscustomobject]@{ Name = $row.Name; Value = $value })
        }

        $json = ConvertTo-SettingsJson -Organization $org -FailureMode ([string]$cmbFail.SelectedItem) `
            -Selections $selections
        try
        {
            Write-SettingsFile -Path $ConfigPath -Content $json
        }
        catch
        {
            [System.Windows.Forms.MessageBox]::Show("Failed to write config:`n$($_.Exception.Message)", 'Error',
                [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error) | Out-Null
            return
        }
        [System.Windows.Forms.MessageBox]::Show(
            ("Saved {0} customization(s) to:`n{1}" -f $selections.Count, $ConfigPath), 'Saved',
            [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information) | Out-Null
        $form.Close()
    })

    # Right-aligned button bar. A docked FlowLayoutPanel positions the buttons regardless of form
    # size / DPI. (The earlier absolute Location from $form.ClientSize.Width left them off-screen:
    # the footer panel had not been sized to the form width when the buttons were placed, so the
    # right anchor pinned them past the visible edge.)
    $btnBar = New-Object System.Windows.Forms.FlowLayoutPanel
    $btnBar.Dock = 'Right'
    $btnBar.FlowDirection = 'RightToLeft'
    $btnBar.WrapContents = $false
    $btnBar.Width = 232
    $btnBar.Controls.Add($btnCancel)   # rightmost
    $btnBar.Controls.Add($btnSave)     # left of Cancel -> reads "Save  Cancel"

    $footer.Controls.Add($lblPath)
    $footer.Controls.Add($btnBar)
    $form.CancelButton = $btnCancel    # Esc cancels; Enter intentionally left unbound

    # Order matters: Fill first, then docked edges around it.
    $form.Controls.Add($body)
    $form.Controls.Add($header)
    $form.Controls.Add($footer)

    [void]$form.ShowDialog()
}

# ----------------------------------------------------------------------------------------------
# Entry point
# ----------------------------------------------------------------------------------------------

# Dispatch only when run directly. When dot-sourced (e.g. by the Pester suite to reach the
# helper functions) $MyInvocation.InvocationName is '.', so we skip launching the window.
if ($MyInvocation.InvocationName -ne '.')
{
    if ($SelfTest)
    {
        Invoke-SelfTest -CatalogPath $CatalogPath -ConfigPath $ConfigPath
    }
    else
    {
        Show-ConfiguratorWindow -CatalogPath $CatalogPath -ConfigPath $ConfigPath
    }
}
