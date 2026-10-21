<#
    .SYNOPSIS
        Function library for the Windows Customizations engine.

    .DESCRIPTION
        Dot-sourced (not imported) by Set-WindowsCustomizations.ps1 and
        Remove-WindowsCustomizations.ps1 so every function shares one scope. Do not run this
        file directly - it only defines functions. See docs\Design.md for the architecture.

        Sections: Logging | Registry & system helpers | Mechanism handlers.
#>

# Captured at dot-source time; $PSScriptRoot here is the Engine directory regardless of which
# script dot-sources this file. Used to resolve packaged assets under <PackageRoot>\Assets.
$WindowsCustomizationsEngineRoot = $PSScriptRoot

# =============================================================================================
# Logging
# =============================================================================================

$script:LogFilePath = $null

# From Script Reference Functions\ConfigMgr.ps1 (harvested 2026-10-20)
function Get-DeploymentLogDirectory
{
    # The log goes where the deploying channel's admins look for it:
    #   ConfigMgr task sequence step -> _SMSTSLogPath, next to smsts.log (it moves with the TS logs)
    #   ConfigMgr client, no IME     -> %WINDIR%\CCM\Logs (e.g. an application install where the
    #                                   TS environment isn't readable)
    #   anything else                -> the IME Logs folder (Intune, the default; collected by Intune
    #                                   diagnostics)
    # The IME check keeps co-managed devices on the Intune folder outside a task sequence.
    if (Get-TaskSequenceStatus)
    {
        $TsLogPath = $null
        try
        {
            $TsLogPath = (New-Object -ComObject 'Microsoft.SMS.TSEnvironment').Value('_SMSTSLogPath')
        }
        catch
        {
            $TsLogPath = $null
        }
        if ($TsLogPath)
        {
            return $TsLogPath
        }
    }
    $CcmLogsDirectory = Join-Path -Path $env:WINDIR -ChildPath 'CCM\Logs'
    $HasIme = $null -ne (Get-Service -Name 'IntuneManagementExtension' -ErrorAction SilentlyContinue)
    if ((Test-Path -LiteralPath $CcmLogsDirectory) -and (-not $HasIme))
    {
        return $CcmLogsDirectory
    }
    return (Join-Path -Path $env:ALLUSERSPROFILE -ChildPath 'Microsoft\IntuneManagementExtension\Logs')
}

function Initialize-Logging
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $false)][ValidateNotNullOrEmpty()][string]$FileName = 'Set-WindowsCustomizations.log'
    )
    $LogsDirectory = Get-DeploymentLogDirectory
    if (-not (Test-Path -Path $LogsDirectory))
    {
        New-Item -Path $LogsDirectory -ItemType Directory -Force | Out-Null
    }
    $script:LogFilePath = Join-Path -Path $LogsDirectory -ChildPath $FileName
}

function Write-LogEntry
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()][string]$Message,
        [Parameter(Mandatory = $false)][ValidateSet('Info', 'Warning', 'Error')][string]$Level = 'Info',
        [Parameter(Mandatory = $false)][ValidateNotNullOrEmpty()][string]$Component = 'WindowsCustomizations'
    )
    if ($null -eq $script:LogFilePath)
    {
        Initialize-Logging
    }

    $SeverityMap = @{ 'Info' = 1; 'Warning' = 2; 'Error' = 3 }
    $ColorMap = @{ 'Info' = 'White'; 'Warning' = 'Yellow'; 'Error' = 'Red' }
    $Severity = $SeverityMap[$Level]

    if (-not (Test-Path -Path 'variable:script:TimezoneBias'))
    {
        [string]$script:TimezoneBias = [System.TimeZoneInfo]::Local.GetUtcOffset((Get-Date)).TotalMinutes
        if ($script:TimezoneBias -match '^-')
        {
            $script:TimezoneBias = $script:TimezoneBias.Replace('-', '+')
        }
        else
        {
            $script:TimezoneBias = '-' + $script:TimezoneBias
        }
    }

    $Time = -join @((Get-Date -Format 'HH:mm:ss.fff'), $script:TimezoneBias)
    $Date = (Get-Date -Format 'MM-dd-yyyy')
    $Context = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
    $LogText = "<![LOG[$Message]LOG]!><time=""$Time"" date=""$Date"" component=""$Component"" context=""$Context"" type=""$Severity"" thread=""$PID"" file="""">"

    try
    {
        Out-File -InputObject $LogText -Append -NoClobber -Encoding Default -FilePath $script:LogFilePath -ErrorAction Stop
    }
    catch [System.Exception]
    {
        Write-Warning -Message "Unable to append log entry. Error at line $($_.InvocationInfo.ScriptLineNumber): $($_.Exception.Message)"
    }

    Write-Host -ForegroundColor $ColorMap[$Level] -Object $Message
}

# =============================================================================================
# Registry & system helpers
# =============================================================================================

function Test-IsWindows11
{
    $Caption = (Get-CimInstance -ClassName Win32_OperatingSystem).Caption
    return ($Caption -match 'Windows 11')
}

function Test-IsWinPE
{
    # WinPE marks itself with the MiniNT control key; a full OS never has it.
    return (Test-Path -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\MiniNT')
}

# From Script Reference Functions\ConfigMgr.ps1 (2026-10-20)
function Get-TaskSequenceStatus
{
    # Is a task sequence ACTUALLY running right now? Two-stage on purpose: creating
    # Microsoft.SMS.TSEnvironment succeeds on any box with a CM client installed, so that alone
    # is a false positive - _SMSTSType is only readable while a task sequence is executing.
    $TsEnv = $null
    try
    {
        $TsEnv = New-Object -ComObject 'Microsoft.SMS.TSEnvironment'
    }
    catch
    {
        return $false
    }
    if ($null -eq $TsEnv)
    {
        return $false
    }
    $TsType = $null
    try
    {
        $TsType = $TsEnv.Value('_SMSTSType')
    }
    catch
    {
        return $false
    }
    return -not [string]::IsNullOrEmpty($TsType)
}

function Set-RegistryValue
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()][string]$RegKey,
        [Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()][string]$Name,
        [Parameter(Mandatory = $true)][ValidateSet('String', 'ExpandString', 'Binary', 'DWord', 'MultiString', 'QWord')][string]$PropertyType,
        [Parameter(Mandatory = $true)]$Value
    )
    if (-not (Test-Path -Path $RegKey))
    {
        New-Item -Path $RegKey -Force -ErrorAction Stop | Out-Null
    }
    New-ItemProperty -Path $RegKey -Name $Name -PropertyType $PropertyType -Value $Value -Force -ErrorAction Stop | Out-Null

    $Check = Get-ItemProperty -Path $RegKey -Name $Name -ErrorAction Stop
    if ($Check.$Name -ne $Value)
    {
        throw "Verification failed: $RegKey\$Name is '$($Check.$Name)', expected '$Value'"
    }
}

function Import-RegistryHive
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)][string]$File,
        [Parameter(Mandatory = $true)][ValidatePattern('^(HKLM\\|HKCU\\)[a-zA-Z0-9- _\\]+$')][string]$Key,
        [Parameter(Mandatory = $true)][ValidatePattern('^[^;~/\\\.\:]+$')][string]$Name
    )
    if ($null -ne (Get-PSDrive -Name $Name -ErrorAction SilentlyContinue))
    {
        throw "A PSDrive named '$Name' already exists."
    }
    # A previous interrupted run (e.g. an ESP or task sequence retry after a forced kill) can leave
    # this hive loaded, which makes 'reg load' fail. Best-effort unload of our own key first.
    $Query = Start-Process -FilePath "$env:WINDIR\system32\reg.exe" -ArgumentList "query $Key" -WindowStyle Hidden -PassThru -Wait
    if ($Query.ExitCode -eq 0)
    {
        Start-Process -FilePath "$env:WINDIR\system32\reg.exe" -ArgumentList "unload $Key" -WindowStyle Hidden -PassThru -Wait | Out-Null
    }
    $Process = Start-Process -FilePath "$env:WINDIR\system32\reg.exe" -ArgumentList "load $Key `"$File`"" -WindowStyle Hidden -PassThru -Wait
    if ($Process.ExitCode)
    {
        throw "Failed to load registry hive '$File' (reg.exe exit $($Process.ExitCode))."
    }
    New-PSDrive -Name $Name -PSProvider Registry -Root $Key -Scope Global -ErrorAction Stop | Out-Null
}

function Remove-RegistryHive
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)][ValidatePattern('^[^;~/\\\.\:]+$')][string]$Name
    )
    $Drive = Get-PSDrive -Name $Name -ErrorAction Stop
    $Key = $Drive.Root
    Remove-PSDrive -Name $Name -ErrorAction Stop

    $Process = Start-Process -FilePath "$env:WINDIR\system32\reg.exe" -ArgumentList "unload $Key" -WindowStyle Hidden -PassThru -Wait
    if ($Process.ExitCode)
    {
        New-PSDrive -Name $Name -PSProvider Registry -Root $Key -Scope Global -ErrorAction Stop | Out-Null
        throw "Failed to unload registry key '$Key' (still in use)."
    }
}

function Remove-RegistryHiveWithRetry
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $false)][int]$MaxAttempts = 3
    )
    $Attempt = 0
    while ($true)
    {
        try
        {
            $Attempt++
            Remove-RegistryHive -Name $Name
            return
        }
        catch
        {
            if ($Attempt -ge $MaxAttempts)
            {
                throw
            }
            Start-Sleep -Milliseconds 200
            [System.GC]::Collect()
        }
    }
}

function Write-VersionStamp
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()][string]$Organization,
        [Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()][string]$Version
    )
    $StampKey = "HKLM:\SOFTWARE\$Organization\WindowsCustomizations"
    Set-RegistryValue -RegKey $StampKey -Name 'Version' -PropertyType 'String' -Value $Version
    Set-RegistryValue -RegKey $StampKey -Name 'InstalledOn' -PropertyType 'String' -Value (Get-Date -Format 'o')
}

function Remove-VersionStamp
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()][string]$Organization
    )
    $StampKey = "HKLM:\SOFTWARE\$Organization\WindowsCustomizations"
    if (Test-Path -Path $StampKey)
    {
        Remove-Item -Path $StampKey -Recurse -Force -ErrorAction Stop
    }
}

# =============================================================================================
# Mechanism handlers
#
# Each catalog definition declares a Mechanism; Invoke-Customization dispatches to the matching
# handler and returns a uniform result object. Handlers throw on hard failure; Invoke-Customization
# converts a throw into a 'Failed' result so the engine can continue and honor the FailureMode.
# =============================================================================================

function Get-PackageRoot
{
    return (Split-Path -Path $WindowsCustomizationsEngineRoot -Parent)
}

function New-CustomizationResult
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][ValidateSet('Applied', 'Skipped', 'Failed')][string]$Status,
        [Parameter(Mandatory = $false)][string]$Message = ''
    )
    return [pscustomobject]@{
        Name    = $Name
        Status  = $Status
        Message = $Message
    }
}

function Invoke-RegistryHandler
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]$Definition,
        [Parameter(Mandatory = $true)]$Value,
        [Parameter(Mandatory = $true)][string]$RootPrefix
    )
    $RegKey = "$RootPrefix\$($Definition.Path)"
    Set-RegistryValue -RegKey $RegKey -Name $Definition.ValueName -PropertyType $Definition.Type -Value $Value
}

function Invoke-FileHandler
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]$Definition
    )
    $Source = Join-Path -Path (Get-PackageRoot) -ChildPath $Definition.Source
    if (-not (Test-Path -Path $Source))
    {
        throw "Asset not found: $Source (capture it per docs\Asset-Preparation.md)"
    }
    $Destination = [System.Environment]::ExpandEnvironmentVariables($Definition.Destination)
    $DestinationDirectory = Split-Path -Path $Destination -Parent
    if (-not (Test-Path -Path $DestinationDirectory))
    {
        New-Item -Path $DestinationDirectory -ItemType Directory -Force -ErrorAction Stop | Out-Null
    }
    Copy-Item -Path $Source -Destination $Destination -Force -ErrorAction Stop
}

function Invoke-AppRemovalHandler
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]$Definition,
        [Parameter(Mandatory = $true)]$Value
    )
    # The config may override the catalog's default list with an explicit array.
    if ($Value -is [System.Array])
    {
        $PackageNames = $Value
    }
    else
    {
        $PackageNames = $Definition.PackageNames
    }
    foreach ($PackageName in $PackageNames)
    {
        $Packages = Get-AppxProvisionedPackage -Online | Where-Object { $_.DisplayName -like $PackageName }
        if (-not $Packages)
        {
            Write-LogEntry -Message "No provisioned package matched '$PackageName'" -Level Warning
            continue
        }
        foreach ($Package in $Packages)
        {
            Remove-AppxProvisionedPackage -Online -PackageName $Package.PackageName -ErrorAction Stop | Out-Null
            Write-LogEntry -Message "Removed provisioned package $($Package.DisplayName)"
        }
    }
}

function Invoke-DismHandler
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]$Definition
    )
    $Source = Join-Path -Path (Get-PackageRoot) -ChildPath $Definition.Source
    if (-not (Test-Path -Path $Source))
    {
        throw "Asset not found: $Source (capture it per docs\Asset-Preparation.md)"
    }
    switch ($Definition.Operation)
    {
        'ImportDefaultAppAssociations'
        {
            $Arguments = "/Online /Import-DefaultAppAssociations:`"$Source`""
        }
        default
        {
            throw "Unknown DISM operation '$($Definition.Operation)'"
        }
    }
    $Process = Start-Process -FilePath "$env:WINDIR\System32\Dism.exe" -ArgumentList $Arguments -WindowStyle Hidden -PassThru -Wait
    if ($Process.ExitCode -ne 0)
    {
        throw "DISM terminated with exit code $($Process.ExitCode)"
    }
}

function Set-ProtectedFile
{
    # Replaces a system-owned file (e.g. default wallpaper / lock screen) by taking
    # ownership, granting full control, then overwriting.
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)][string]$Source,
        [Parameter(Mandatory = $true)][string]$Destination
    )
    if (-not (Test-Path -Path $Source))
    {
        throw "Asset not found: $Source (capture it per docs\Asset-Preparation.md)"
    }
    if (Test-Path -Path $Destination)
    {
        & "$env:WINDIR\System32\takeown.exe" /f $Destination | Out-Null
        # Grant full control to SYSTEM (the runtime context in the ESP or a task sequence) and
        # Administrators.
        # SIDs are locale-independent: S-1-5-18 = NT AUTHORITY\SYSTEM, S-1-5-32-544 = Administrators.
        & "$env:WINDIR\System32\icacls.exe" $Destination /grant '*S-1-5-18:(F)' '*S-1-5-32-544:(F)' | Out-Null
    }
    else
    {
        $DestinationDirectory = Split-Path -Path $Destination -Parent
        if (-not (Test-Path -Path $DestinationDirectory))
        {
            New-Item -Path $DestinationDirectory -ItemType Directory -Force -ErrorAction Stop | Out-Null
        }
    }
    Copy-Item -Path $Source -Destination $Destination -Force -ErrorAction Stop
}

function Invoke-CustomHandler
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]$Definition,
        [Parameter(Mandatory = $true)]$Value,
        [Parameter(Mandatory = $false)][string]$HiveDrive
    )
    switch ($Definition.Name)
    {
        'SearchBoxMode'
        {
            $SearchKey = "$($HiveDrive):\SOFTWARE\Microsoft\Windows\CurrentVersion\Search"
            if ($Value -eq 2)
            {
                # The search box is Windows' own first-logon default: with no seeded mode the shell writes
                # SearchboxTaskbarMode=2 + SearchboxTaskbarModeCache=1 itself. A PRE-SEEDED 2 is rewritten to
                # 1 (icon) at first logon (verified on 26H2 with the cache at 1 or 2), so seed nothing for 2 and
                # clear any mode an earlier run left in the hive.
                if (Test-Path -Path $SearchKey)
                {
                    Remove-ItemProperty -Path $SearchKey -Name 'SearchboxTaskbarMode', 'SearchboxTaskbarModeCache' -Force -ErrorAction SilentlyContinue
                }
            }
            else
            {
                Set-RegistryValue -RegKey $SearchKey -Name 'SearchboxTaskbarMode' -PropertyType 'DWord' -Value $Value
                # SearchboxTaskbarModeCache=1 is the "first-run done" marker the shell writes itself. Without it
                # the shell resets the mode to its default (the search box) at first logon.
                Set-RegistryValue -RegKey $SearchKey -Name 'SearchboxTaskbarModeCache' -PropertyType 'DWord' -Value 1
            }
        }
        'SuggestedContentSettings'
        {
            # The Settings toggle "Recommendations and offers in Settings" reads three ContentDeliveryManager
            # values and stays On while any of them is missing or 1, so seeding only 338393 leaves it On.
            $CdmKey = "$($HiveDrive):\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"
            foreach ($ContentId in '338393', '353694', '353696')
            {
                Set-RegistryValue -RegKey $CdmKey -Name "SubscribedContent-$($ContentId)Enabled" -PropertyType 'DWord' -Value $Value
            }
        }
        'RecycleBinDesktopIcon'
        {
            # Recycle Bin is read from two icon panels; set both so the change is honored.
            $Guid = '{645FF040-5081-101B-9F08-00AA002F954E}'
            Set-RegistryValue -RegKey "$($HiveDrive):\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" -Name $Guid -PropertyType 'DWord' -Value $Value
            Set-RegistryValue -RegKey "$($HiveDrive):\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu" -Name $Guid -PropertyType 'DWord' -Value $Value
        }
        'ColorMode'
        {
            # Color mode is driven by THREE values that must agree. On first logon the theme
            # engine applies the .theme file named by CurrentTheme, which RE-ASSERTS the two
            # Personalize DWORDs - so seeding the DWORDs alone does not stick (the default
            # aero.theme flips it back to Light). CurrentTheme is the durable switch; seed all
            # three together.
            #   0 = dark  -> dark.theme + both DWORDs 0
            #   1 = light -> aero.theme + both DWORDs 1
            $ThemeFile = if ($Value -eq 0) { 'C:\WINDOWS\resources\Themes\dark.theme' } else { 'C:\WINDOWS\resources\Themes\aero.theme' }
            $ThemesKey = "$($HiveDrive):\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes"
            Set-RegistryValue -RegKey $ThemesKey -Name 'CurrentTheme' -PropertyType 'String' -Value $ThemeFile
            # AppsUseLightTheme/SystemUsesLightTheme use the same 0=dark/1=light sense as ColorMode.
            $Personalize = "$ThemesKey\Personalize"
            Set-RegistryValue -RegKey $Personalize -Name 'AppsUseLightTheme' -PropertyType 'DWord' -Value $Value
            Set-RegistryValue -RegKey $Personalize -Name 'SystemUsesLightTheme' -PropertyType 'DWord' -Value $Value
        }
        'CombineTaskbarButtons'
        {
            # Primary (TaskbarGlomLevel) + secondary-monitor (MMTaskbarGlomLevel) kept in sync with
            # the same map: 0 = always combine/hide labels, 1 = when taskbar is full, 2 = never.
            # Seeding both keeps multi-monitor consistent.
            $Advanced = "$($HiveDrive):\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced"
            Set-RegistryValue -RegKey $Advanced -Name 'TaskbarGlomLevel' -PropertyType 'DWord' -Value $Value
            Set-RegistryValue -RegKey $Advanced -Name 'MMTaskbarGlomLevel' -PropertyType 'DWord' -Value $Value
        }
        'ClassicContextMenu'
        {
            # The classic full menu is the empty (Default) value of a CLSID key under
            # HKCU\Software\Classes - backed by UsrClass.dat, NOT NTUSER.DAT (so it can't be seeded into
            # the default hive; the Default profile ships no UsrClass.dat). It must also be set BEFORE
            # explorer starts, or it only takes effect on the next logon (a RunOnce is processed by
            # explorer and lands too late). Active Setup runs its per-user StubPath at
            # first logon BEFORE the shell launches, so the menu is correct on the very first logon. The
            # component is machine-level (HKLM); each user runs it once at their next logon and can still
            # change the menu afterward. cmd's reg.exe writes the empty default correctly with /ve /d ""
            # (the PowerShell arg-parsing breakage doesn't apply). 1 = install; 0 = remove the component.
            $ComponentKey = 'HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{B1E9F2A4-7C3D-4E5F-9A1B-0C7E5D3F2A18}'
            if ($Value -eq 1)
            {
                $StubPath = 'reg add "HKCU\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\InprocServer32" /ve /d "" /f'
                Set-RegistryValue -RegKey $ComponentKey -Name '(default)' -PropertyType 'String' -Value 'Windows Customizations - Classic context menu'
                # Bumping Version re-runs the StubPath for every user at their next logon.
                Set-RegistryValue -RegKey $ComponentKey -Name 'Version' -PropertyType 'String' -Value '1'
                Set-RegistryValue -RegKey $ComponentKey -Name 'StubPath' -PropertyType 'String' -Value $StubPath
            }
            elseif (Test-Path -Path $ComponentKey)
            {
                Remove-Item -Path $ComponentKey -Recurse -Force -ErrorAction Stop
            }
        }
        'StickyKeysShortcut'
        {
            # The Shift-x5 prompt is the 0x4 (SKF_HOTKEYACTIVE) bit of the composite REG_SZ Flags
            # string: "510" = on, "506" = off. Map 0/1 to the string and write it under the
            # Control Panel\ root of the hive.
            $Flags = if ($Value -eq 1) { '510' } else { '506' }
            Set-RegistryValue -RegKey "$($HiveDrive):\Control Panel\Accessibility\StickyKeys" -Name 'Flags' -PropertyType 'String' -Value $Flags
        }
        'DesktopBackground'
        {
            # Non-locking preference equivalent of the CloudContent Spotlight policy. BackgroundType
            # is the authoritative selector (0 = Picture, 3 = Windows Spotlight); EnabledState is the
            # Spotlight provider's own flag, kept in sync.
            Set-RegistryValue -RegKey "$($HiveDrive):\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Wallpapers" -Name 'BackgroundType' -PropertyType 'DWord' -Value $Value
            $SpotlightEnabled = if ($Value -eq 3) { 1 } else { 0 }
            Set-RegistryValue -RegKey "$($HiveDrive):\SOFTWARE\Microsoft\Windows\CurrentVersion\DesktopSpotlight\Settings" -Name 'EnabledState' -PropertyType 'DWord' -Value $SpotlightEnabled
        }
        'OutlookTaskbarPin'
        {
            # The new Outlook auto-pins at first logon (explorer sets Taskband\AuxilliaryPins\MailPin=1 and
            # pins it, ignoring any pre-seeded value). MailPin=0 is only honored on LATER logons, so seed a
            # first-logon RunOnce that forces MailPin=0 after the auto-pin runs - the pin shows on the first
            # logon, then is gone permanently. Value 1 = leave the default (pinned); remove our RunOnce.
            $RunOnceKey = "$($HiveDrive):\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"
            if ($Value -eq 0)
            {
                $Command = 'reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Taskband\AuxilliaryPins" /v MailPin /t REG_DWORD /d 0 /f'
                Set-RegistryValue -RegKey $RunOnceKey -Name 'WC_ResetOutlookPin' -PropertyType 'String' -Value $Command
            }
            elseif (Test-Path -Path $RunOnceKey)
            {
                Remove-ItemProperty -Path $RunOnceKey -Name 'WC_ResetOutlookPin' -Force -ErrorAction SilentlyContinue
            }
        }
        'EdgeDesktopShortcut'
        {
            $Shortcut = Join-Path -Path $env:PUBLIC -ChildPath 'Desktop\Microsoft Edge.lnk'
            if (Test-Path -Path $Shortcut)
            {
                Remove-Item -Path $Shortcut -Force -ErrorAction Stop
            }
            else
            {
                Write-LogEntry -Message "Edge desktop shortcut not present: $Shortcut" -Level Warning
            }
            # Deleting the public shortcut is not enough - each new user otherwise gets one
            # recreated. The EdgeUpdate policy stops Edge from creating the desktop shortcut.
            $EdgeUpdate = 'HKLM:\SOFTWARE\Policies\Microsoft\EdgeUpdate'
            Set-RegistryValue -RegKey $EdgeUpdate -Name 'CreateDesktopShortcutDefault' -PropertyType 'DWord' -Value 0
            Set-RegistryValue -RegKey $EdgeUpdate -Name 'RemoveDesktopShortcutDefault' -PropertyType 'DWord' -Value 1
        }
        'OneDriveSetup'
        {
            Remove-ItemProperty -Path "$($HiveDrive):\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name 'OneDriveSetup' -Force -ErrorAction Stop
        }
        'RemoveOfficeApps'
        {
            foreach ($DisplayName in @('Microsoft 365 -', 'Microsoft OneNote -'))
            {
                $UninstallStrings = Get-ItemProperty -Path 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*' -ErrorAction SilentlyContinue |
                    Where-Object { $_.DisplayName -like "$DisplayName*" } |
                    Select-Object -ExpandProperty UninstallString -ErrorAction SilentlyContinue
                foreach ($UninstallString in $UninstallStrings)
                {
                    $UninstallExe = ($UninstallString -split '"')[1]
                    $UninstallArg = ($UninstallString -split '"')[2] + ' DisplayLevel=False'
                    if ($UninstallExe)
                    {
                        $Process = Start-Process -FilePath $UninstallExe -ArgumentList $UninstallArg -Wait -PassThru
                        Write-LogEntry -Message "Office uninstall '$DisplayName' exit code $($Process.ExitCode)"
                    }
                }
            }
        }
        'NetworkNotification'
        {
            # The mere existence of this key suppresses the "new network" flyout.
            $RegKey = 'HKLM:\SYSTEM\CurrentControlSet\Control\Network\NewNetworkWindowOff'
            if (-not (Test-Path -Path $RegKey))
            {
                New-Item -Path $RegKey -Force -ErrorAction Stop | Out-Null
            }
        }
        'EnableLocationServices'
        {
            # Master location consent + sensor override + the geolocation service. This is what
            # 'Set time zone automatically' (DynamicTime) needs in place first.
            Set-RegistryValue -RegKey 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location' -Name 'Value' -PropertyType 'String' -Value 'Allow'
            Set-RegistryValue -RegKey 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Overrides\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}' -Name 'SensorPermissionState' -PropertyType 'DWord' -Value 1
            Set-Service -Name 'lfsvc' -StartupType 'Automatic' -ErrorAction SilentlyContinue
            Start-Service -Name 'lfsvc' -ErrorAction SilentlyContinue
        }
        'DynamicTime'
        {
            # Turn on automatic time zone. tzautoupdate Start = 3 (demand/on) / 4 (off), then make
            # sure the service is running so it takes effect this session. Only effective once
            # location services are enabled (see EnableLocationServices).
            Set-RegistryValue -RegKey 'HKLM:\SYSTEM\CurrentControlSet\Services\tzautoupdate' -Name 'Start' -PropertyType 'DWord' -Value 3
            Start-Service -Name 'tzautoupdate' -ErrorAction SilentlyContinue
        }
        'DesktopWallpaper'
        {
            # aero.theme (light) shows img0; dark.theme - which ColorMode=0 seeds - shows img19. Brand both so
            # the org wallpaper appears in either mode. An optional img19.jpg asset supplies a separate dark
            # render; without one, img0 (and each 4k\img0_<res>.jpg) is reused for the dark slot too.
            $BrandingRoot = Join-Path -Path (Get-PackageRoot) -ChildPath 'Assets\Branding'
            $LightImage = Join-Path -Path $BrandingRoot -ChildPath 'img0.jpg'
            $DarkImage = Join-Path -Path $BrandingRoot -ChildPath 'img19.jpg'
            $HasDarkAsset = Test-Path -Path $DarkImage
            if (-not $HasDarkAsset)
            {
                $DarkImage = $LightImage
            }
            Set-ProtectedFile -Source $LightImage -Destination "$env:WINDIR\Web\Wallpaper\Windows\img0.jpg"
            Set-ProtectedFile -Source $DarkImage -Destination "$env:WINDIR\Web\Wallpaper\Windows\img19.jpg"
            $FourKRoot = Join-Path -Path $BrandingRoot -ChildPath '4k'
            if (Test-Path -Path $FourKRoot)
            {
                foreach ($Image in (Get-ChildItem -Path $FourKRoot -File))
                {
                    Set-ProtectedFile -Source $Image.FullName -Destination "$env:WINDIR\Web\4K\Wallpaper\Windows\$($Image.Name)"
                    if (-not $HasDarkAsset -and $Image.Name -like 'img0_*')
                    {
                        $DarkName = 'img19_' + $Image.Name.Substring(5)
                        Set-ProtectedFile -Source $Image.FullName -Destination "$env:WINDIR\Web\4K\Wallpaper\Windows\$DarkName"
                    }
                }
            }
        }
        'LockScreenImage'
        {
            $BrandingRoot = Join-Path -Path (Get-PackageRoot) -ChildPath 'Assets\Branding'
            Set-ProtectedFile -Source (Join-Path -Path $BrandingRoot -ChildPath 'img100.jpg') -Destination "$env:WINDIR\Web\Screen\img100.jpg"
        }
        default
        {
            throw "No custom handler implemented for '$($Definition.Name)'"
        }
    }
}

function Invoke-Customization
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]$Definition,
        [Parameter(Mandatory = $true)]$Value,
        [Parameter(Mandatory = $false)][string]$HiveDrive
    )
    try
    {
        switch ($Definition.Mechanism)
        {
            'DefaultHive'
            {
                Invoke-RegistryHandler -Definition $Definition -Value $Value -RootPrefix "$($HiveDrive):"
            }
            'HKLM'
            {
                Invoke-RegistryHandler -Definition $Definition -Value $Value -RootPrefix 'HKLM:'
            }
            'Policy'
            {
                Invoke-RegistryHandler -Definition $Definition -Value $Value -RootPrefix 'HKLM:'
            }
            'File'
            {
                Invoke-FileHandler -Definition $Definition
            }
            'AppRemoval'
            {
                Invoke-AppRemovalHandler -Definition $Definition -Value $Value
            }
            'Dism'
            {
                Invoke-DismHandler -Definition $Definition
            }
            'Custom'
            {
                Invoke-CustomHandler -Definition $Definition -Value $Value -HiveDrive $HiveDrive
            }
            default
            {
                throw "Unknown mechanism '$($Definition.Mechanism)'"
            }
        }
        return (New-CustomizationResult -Name $Definition.Name -Status 'Applied')
    }
    catch
    {
        Write-LogEntry -Message "Failed to apply '$($Definition.Name)': $($_.Exception.Message)" -Level Error
        return (New-CustomizationResult -Name $Definition.Name -Status 'Failed' -Message $_.Exception.Message)
    }
}

function Test-NeedsHive
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]$Definition
    )
    if ($Definition.Mechanism -eq 'DefaultHive')
    {
        return $true
    }
    if ($Definition.Mechanism -eq 'Custom' -and $Definition.NeedsHive -eq $true)
    {
        return $true
    }
    return $false
}
