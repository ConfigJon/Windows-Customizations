<#
    .DESCRIPTION
        This script can be used to apply Windows 10 customizations.
	
    .PARAMETER File
        Path to the ini file that contains the customizaiton parameters
	
    .EXAMPLE
        Customize_Windows.ps1 -File C:\Temp\parameters.ini
	
    .NOTES
        Created by: Jon Anderson (@ConfigJon)
        Updated 6/25/19
        Reference: https://github.com/ConfigJon/Windows-Customizations/tree/master/Customization-Script
#>

#Create Parameters
param(
    [ValidateScript({
        if (!($_ | Test-Path))
        {
            throw "The specified file does not exist"
        }
        if (!($_ | Test-Path -PathType Leaf))
        {
            throw "The Path argument must be a file. Folder paths are not allowed."
        }
        if ($_ -notmatch "(\.ini)")
        {
            throw "The specified file must be a .ini file"
        }
        return $true 
    })]
    [System.IO.FileInfo]$File
)

#Create Functions===========================================================================================================
Function New-RegistryValue
{
    [CmdletBinding()]
    param(
        [String][parameter(Mandatory=$true)][ValidateNotNullOrEmpty()]$Customization,    
        [String][parameter(Mandatory=$true)][ValidateNotNullOrEmpty()]$RegKey,
        [String][parameter(Mandatory=$true)][ValidateNotNullOrEmpty()]$Name,
        [String][parameter(Mandatory=$true)][ValidateSet('String','ExpandString','Binary','DWord','MultiString','Qword','Unknown')]$PropertyType,
        [String][parameter(Mandatory=$true)][ValidateNotNullOrEmpty()]$Value
    )
    Write-Output "Running Customization - $Customization"
        
    #Create the registry key if it does not exist
    if (!(Test-Path $RegKey))
    {
        try
        {
            New-Item -Path $RegKey -Force | Out-Null
        }
        catch
        {
            throw "Failed to create $RegKey"
        }

    }

    #Create the registry value
    try
    {
        New-ItemProperty -Path $RegKey -Name $Name -PropertyType $PropertyType -Value $Value -Force | Out-Null
    }
    catch
    {
        throw "Failed to set $RegKey\$Name to $Value"
    }

    #Check if the registry value was successfully created
    $KeyCheck = Get-ItemProperty $RegKey
    if ($KeyCheck.$Name -eq $Value)
    {
        Write-Output "Successfully set $RegKey\$Name to $Value"
    }
    else
    {
        throw "Failed to set $RegKey\$Name to $Value"
    }
}

#Import-RegistryHive and Remove-RegistryHive sourced from
#http://blog.redit.name/posts/2015/powershell-loading-registry-hive-from-file.html
Function Import-RegistryHive
{
    [CmdletBinding()]
    param(
        [String][parameter(Mandatory=$true)]$File,
        #Check the registry key name is not an invalid format
        [String][parameter(Mandatory=$true)][ValidatePattern('^(HKLM\\|HKCU\\)[a-zA-Z0-9- _\\]+$')]$Key,
        #Check the PSDrive name does not include invalid characters
        [String][parameter(Mandatory=$true)][ValidatePattern('^[^;~/\\\.\:]+$')]$Name
    )

    #Check whether the drive name is available
    $TestDrive = Get-PSDrive -Name $Name -EA SilentlyContinue
    if ($NULL -ne $TestDrive)
    {
        throw [Management.Automation.SessionStateException] "A drive with the name '$Name' already exists."
    }

    $Process = Start-Process -FilePath "$env:WINDIR\system32\reg.exe" -ArgumentList "load $Key $File" -WindowStyle Hidden -PassThru -Wait

    if ($Process.ExitCode)
    {
        throw [Management.Automation.PSInvalidOperationException] "The registry hive '$File' failed to load. Verify the source path or target registry key."
    }

    try
    {
        #Validate patten on $Name in the params and the drive name check at the start make it very unlikely New-PSDrive will fail
        New-PSDrive -Name $Name -PSProvider Registry -Root $Key -Scope Global -EA Stop | Out-Null
    }
    catch
    {
        throw [Management.Automation.PSInvalidOperationException] "A critical error creating drive '$Name' has caused the registy key '$Key' to be left loaded, this must be unloaded manually."
    }
}

Function Remove-RegistryHive
{
    [CmdletBinding()]
    param(
        [String][parameter(Mandatory=$true)][ValidatePattern('^[^;~/\\\.\:]+$')]$Name
    )

    #Set -ErrorAction Stop as we never want to proceed if the drive doesnt exist
    $Drive = Get-PSDrive -Name $Name -EA Stop
    #$Drive.Root is the path to the registry key, save this before the drive is removed
    $Key = $Drive.Root

    #Remove the drive, the only reason this should fail is if the reasource is busy
    Remove-PSDrive $Name -EA Stop

    $Process = Start-Process -FilePath "$env:WINDIR\system32\reg.exe" -ArgumentList "unload $Key" -WindowStyle Hidden -PassThru -Wait
    if ($Process.ExitCode)
    {
        #if "reg unload" fails due to the resource being busy, the drive gets added back to keep the original state
        New-PSDrive -Name $Name -PSProvider Registry -Root $Key -Scope Global -EA Stop | Out-Null
        throw [Management.Automation.PSInvalidOperationException] "The registry key '$Key' could not be unloaded, the key may still be in use."
    }
}
#===========================================================================================================================


#Read data from the parameters file
$parameters = Get-Content $File

#Create variables for each line in the parameters file
foreach ($parameter in $parameters){
    if ($parameter.StartsWith("#"))
    {
    }
    else
    {
        try
        {
            $Variable = $parameter.Split('=')
            New-Variable -Name $Variable[0].Trim() -Value $Variable[1].Trim() -Force
        }
        catch
        {
            throw "Failed to import $parameter from $file"    
        }
    }
}

#Import Default Application Associations
if ($NULL -ne $DefaultApps)
{
    if ($DefaultApps -like "*.xml")
    {
        try
        {
            Write-Output "Running Customization - Import Default Application Associations"
            Dism.exe /Online /Import-DefaultAppAssociations:"$PSScriptRoot\$DefaultApps" | Out-Null
            Write-Output "Successfully imported default application associations."
        }
        catch
        {
            throw "Failed to import default application associations."
        }
    }
    else
    {
        throw "$DefaultApps is not an xml file. Please specify a file with a .xml extension."
    }
}

#Import Default Start Menu and Taskbar Layout
if ($NULL -ne $StartLayout)
{
    if ($StartLayout -like "*.xml")
    {
        try
        {
            Write-Output "Running Customizations - Import Default Start Menu and Taskbar layout"
            Import-StartLayout -LayoutPath "$PSScriptRoot\$StartLayout" -MountPath "$Env:SystemDrive\"
            Write-Output "Successfully imported Start layout."
        }
        catch
        {
            throw "Failed to import Start layout."
        }
    }
    else
    {
        throw "$StartLayout is not an xml file. Please specify a file with a .xml extension."
    }
}

#Run HKLM Registry Customizations
if ($NULL -ne $Cortana)
{
    New-RegistryValue -Customization "Cortana" -RegKey "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "AllowCortana" -PropertyType DWord -Value $Cortana
}
if ($NULL -ne $OOBECortana)
{
    New-RegistryValue -Customization "OOBE Cortana" -RegKey "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\OOBE" -Name "DisableVoice" -PropertyType DWord -Value $OOBECortana
}
if ($NULL -ne $OOBEPrivacy)
{
    New-RegistryValue -Customization "Privacy Settings Experience" -RegKey "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OOBE" -Name "DisablePrivacyExperience" -PropertyType DWord -Value $OOBEPrivacy
}
if ($NULL -ne $WifiSense)
{
    New-RegistryValue -Customization "Wi-fi Sense" -RegKey "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\Wifi\AllowAutoConnectToWifiSenseHotspots" -Name "Value" -PropertyType DWord -Value $WifiSense
}
if ($NULL -ne $EdgeFirstRun)
{
    New-RegistryValue -Customization "Edge First Run" -RegKey "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Main" -Name "PreventFirstRunPage" -PropertyType DWord -Value $EdgeFirstRun
}
if ($NULL -ne $FirstLogonAnimation)
{
    New-RegistryValue -Customization "First Logon Animation" -RegKey "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableFirstLogonAnimation" -PropertyType DWord -Value $FirstLogonAnimation
}
if ($NULL -ne $ConsumerFeatures)
{
    New-RegistryValue -Customization "Consumer Features" -RegKey "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableWindowsConsumerFeatures" -PropertyType DWord -Value $ConsumerFeatures
}
if ($NULL -ne $WindowsTips)
{
    New-RegistryValue -Customization "Windows Tips" -RegKey "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableSoftLanding" -PropertyType DWord -Value $WindowsTips
}
if ($NULL -ne $EdgeDesktopShortcut)
{
    New-RegistryValue -Customization "Edge Desktop Shortcut" -RegKey "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -Name "DisableEdgeDesktopShortcutCreation" -PropertyType DWord -Value $EdgeDesktopShortcut
}
if ($NULL -ne $FileExplorerView)
{
    New-RegistryValue -Customization "File Explorer View" -RegKey "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "LaunchTo" -PropertyType DWord -Value $FileExplorerView
}
if ($NULL -ne $RunAsUserStart)
{
    New-RegistryValue -Customization "Run As User Start Menu" -RegKey "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "ShowRunasDifferentuserinStart" -PropertyType DWord -Value $RunAsUserStart
}
if ($NULL -ne $FastStartup)
{
    New-RegistryValue -Customization "Fast Startup" -RegKey "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power" -Name "HiberbootEnabled" -PropertyType DWord -Value $FastStartup
}

#Load the Default User registry hive
$HiveName = "DefaultUserHive"
Import-RegistryHive -File 'C:\Users\Default\NTUSER.DAT' -Key 'HKLM\DefaultUser' -Name $HiveName

#Run Default User Registry Customizations
if ($NULL -ne $DefenderPrompt)
{
    New-RegistryValue -Customization "Defender Prompt" -RegKey "$($HiveName):\SOFTWARE\Microsoft\Windows Defender" -Name "UifirstRun" -PropertyType DWord -Value $DefenderPrompt
}
if ($OneDriveSetup = "Delete")
{
    try
    {
        Write-Output "Running Customization - OneDrive Setup"
        Remove-ItemProperty -Path "$($HiveName):\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "OneDriveSetup" -Force
        Write-Output "Successfully disabled the OneDrive setup task." 
    }
    catch
    {
        throw "Failed to delete OneDriveSetup from $($HiveName):\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
    }

}
if ($NULL -ne $InkWorkspaceIcon)
{
    New-RegistryValue -Customization "Ink Workspace Icon" -RegKey "$($HiveName):\SOFTWARE\Microsoft\Windows\CurrentVersion\PenWorkspace" -Name "PenWorkspaceButtonDesiredVisibility" -PropertyType DWord -Value $InkWorkspaceIcon
}
if ($NULL -ne $TouchKeyboardIcon)
{
    New-RegistryValue -Customization "Touch Keyboard Icon" -RegKey "$($HiveName):\SOFTWARE\Microsoft\TabletTip\1.7" -Name "TipbandDesiredVisibility" -PropertyType DWord -Value $TouchKeyboardIcon
}
if ($NULL -ne $SearchIcon)
{
    New-RegistryValue -Customization "Search Icon" -RegKey "$($HiveName):\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -Name "SearchboxTaskbarMode" -PropertyType DWord -Value $SearchIcon
}
if ($NULL -ne $PeopleIcon)
{
    New-RegistryValue -Customization "People Icon" -RegKey "$($HiveName):\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People" -Name "PeopleBand" -PropertyType DWord -Value $PeopleIcon
}
if ($NULL -ne $TaskViewIcon)
{
    New-RegistryValue -Customization "Task View Icon" -RegKey "$($HiveName):\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowTaskViewButton" -PropertyType DWord -Value $TaskViewIcon
}
if ($NULL -ne $ThisPCDesktop)
{
    New-RegistryValue -Customization "This PC Desktop Shortcut" -RegKey "$($HiveName):\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" -Name "{20D04FE0-3AEA-1069-A2D8-08002B30309D}" -PropertyType DWord -Value $ThisPCDesktop
}
if ($NULL -ne $UserFilesDesktop)
{
    New-RegistryValue -Customization "User Files Desktop Shortcut" -RegKey "$($HiveName):\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" -Name "{59031a47-3f72-44a7-89c5-5595fe6b30ee}" -PropertyType DWord -Value $UserFilesDesktop
}
if ($NULL -ne $NetworkDesktop)
{
    New-RegistryValue -Customization "Network Desktop Shortcut" -RegKey "$($HiveName):\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" -Name "{F02C1A0D-BE21-4350-88B0-7367FC96EF3C}" -PropertyType DWord -Value $NetworkDesktop
}
if ($NULL -ne $RecycleBinDesktop)
{
    New-RegistryValue -Customization "Recycle Bin Desktop Shortcut" -RegKey "$($HiveName):\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" -Name "{645FF040-5081-101B-9F08-00AA002F954E}" -PropertyType DWord -Value $RecycleBinDesktop
    New-RegistryValue -Customization "Recycle Bin Desktop Shortcut" -RegKey "$($HiveName):\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu" -Name "{645FF040-5081-101B-9F08-00AA002F954E}" -PropertyType DWord -Value $RecycleBinDesktop
}
if ($NULL -ne $ControlPanelDesktop)
{
    New-RegistryValue -Customization "Control Panel Desktop Shortcut" -RegKey "$($HiveName):\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" -Name "{5399E694-6CE5-4D6C-8FCE-1D8870FDCBA0}" -PropertyType DWord -Value $ControlPanelDesktop
}
if ($NULL -ne $WinXShell)
{
    New-RegistryValue -Customization "Win X Shell Option" -RegKey "$($HiveName):\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "DontUsePowerShellOnWinX" -PropertyType DWord -Value $WinXShell
}

#Unload the Default User registry hive
#http://blog.redit.name/posts/2015/powershell-loading-registry-hive-from-file.html
#Attempt Remove-RegistryHive a maximum of 3 times
$Count = 0
while($true)
{
    try
    {
        #When Remove-RegistryHive is successful break will stop the loop
        $Count++
        Remove-RegistryHive -Name $HiveName
        Write-Output 'Remove-RegistryHive succeeded. NTUSER.DAT updated successfully'
        break
    }
    catch
    {
        if ($Count -eq 3)
        {
            #Rethrow the exception, we gave up
            throw
        }

        Write-Output 'Registry hive still in use, trying again...'
        Write-Output "`n"

        #Wait for 100ms and trigger the garbage collector
        Start-Sleep -Milliseconds 100
        [gc]::Collect()
    }
}