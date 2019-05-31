<#
    .DESCRIPTION
        This script can be used to apply Windows 10 customizations.
	
    .PARAMETER File
        Path to the ini file that contains the customizaiton parameters
	
    .EXAMPLE
        Customize_Windows.ps1 -File C:\Temp\parameters.ini
	
    .NOTES
        Created by: Jon Anderson
        Reference: https://github.com/ConfigJon/Windows-Customizations/tree/master/Customization-Script
#>

#Create Parameters
param(
    [String][parameter(Mandatory=$true)][ValidateNotNullOrEmpty()]$File
)

#Create Functions===========================================================================================================
Function New-RegistryValue
{
    [CmdletBinding()]
    param(
        [String][parameter(Mandatory=$true)]$Customization,    
        [String][parameter(Mandatory=$true)]$RegKey,
        [String][parameter(Mandatory=$true)]$Name,
        [String][parameter(Mandatory=$true)]$PropertyType,
        [String][parameter(Mandatory=$true)]$Value
    )
    if (Test-Path Variable:$Customization)
    {
        Write-Host "Running Customization - $Customization"
        
        #Create the registry key if it does not exist
        if (!(Test-Path $RegKey))
        {
            New-Item -Path $RegKey -Force | Out-Null
        }

        #Create the registry value
        New-ItemProperty -Path $RegKey -Name $Name -PropertyType $PropertyType -Value $Value -Force | Out-Null

        #Check if the registry value was successfully created
        $KeyCheck = Get-ItemProperty $RegKey
        if ($KeyCheck.$Name -eq $Value)
        {
            Write-Host "Successfully set $RegKey\$Name to $Value"
            Write-Host "`n"
        }
        else
        {
            throw "Failed to set $RegKey\$Name to $Value"
        }
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

#Check that the specified parameters file exists
if (!(Test-Path $File))
{
    throw "Could not find $File Please enter a vaild path to the parameters file."
}

#Check that the specified parameters file is an ini file
$Extension = $File.Split('.')
if ($Extension[1] -ne "ini")
{
    throw "$File is not an ini file. Please specify a file with a .ini extension."
}

#Read data from the parameters file
$parameters = Get-Content $File

#Create variables for each line in the parameters file
foreach ($parameter in $parameters){
    if ($parameter.StartsWith("#"))
    {
    }
    else
    {
        $Variable = $parameter.Split('=')
        New-Variable -Name $Variable[0] -Value $Variable[1] -Force
    }
}

#Import Default Application Associations
if ($DefaultApps)
{
    if ($DefaultApps -like "*.xml")
    {
        Write-Host "Running Customization - Import Default Application Associations"
        Dism.exe /Online /Import-DefaultAppAssociations:"$PSScriptRoot\$DefaultApps" | Out-Null
        Write-Host "Done"
        Write-Host "`n"
    }
    else
    {
        throw "$DefaultApps is not an xml file. Please specify a file with a .xml extension."
    }
}

#Import Default Start Menu and Taskbar Layout
if ($StartLayout)
{
    if ($StartLayout -like "*.xml")
    {
        Write-Host "Running Customizations - Import Default Start Menu and Taskbar layout"
        Import-StartLayout -LayoutPath "$PSScriptRoot\$StartLayout" -MountPath "$Env:SystemDrive\"
        Write-Host "Done"
        Write-Host "`n"
    }
    else
    {
        throw "$StartLayout is not an xml file. Please specify a file with a .xml extension."
    }
}

#Run HKLM Registry Customizations
if ($Cortana)
{
    New-RegistryValue -Customization Cortana -RegKey "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "AllowCortana" -PropertyType DWord -Value $Cortana
}
if ($OOBECortana)
{
    New-RegistryValue -Customization OOBECortana -RegKey "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\OOBE" -Name "DisableVoice" -PropertyType DWord -Value $OOBECortana
}
if ($WifiSense)
{
    New-RegistryValue -Customization WifiSense -RegKey "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\Wifi\AllowAutoConnectToWifiSenseHotspots" -Name "Value" -PropertyType DWord -Value $WifiSense
}
if ($EdgeFirstRun)
{
    New-RegistryValue -Customization EdgeFirstRun -RegKey "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Main" -Name "PreventFirstRunPage" -PropertyType DWord -Value $EdgeFirstRun
}
if ($FirstLogonAnimation)
{
    New-RegistryValue -Customization FirstLogonAnimation -RegKey "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableFirstLogonAnimation" -PropertyType DWord -Value $FirstLogonAnimation
}
if ($ConsumerFeatures)
{
    New-RegistryValue -Customization ConsumerFeatures -RegKey "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableWindowsConsumerFeatures" -PropertyType DWord -Value $ConsumerFeatures
}
if ($WindowsTips)
{
    New-RegistryValue -Customization WindowsTips -RegKey "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableSoftLanding" -PropertyType DWord -Value $WindowsTips
}
if ($EdgeDesktopShortcut)
{
    New-RegistryValue -Customization EdgeDesktopShortcut -RegKey "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -Name "DisableEdgeDesktopShortcutCreation" -PropertyType DWord -Value $EdgeDesktopShortcut
}
if ($FileExplorerView)
{
    New-RegistryValue -Customization FileExplorerView -RegKey "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "LaunchTo" -PropertyType DWord -Value $FileExplorerView
}
if ($RunAsUserStart)
{
    New-RegistryValue -Customization RunAsUserStart -RegKey "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "ShowRunasDifferentuserinStart" -PropertyType DWord -Value $RunAsUserStart
}
if ($FastStartup)
{
    New-RegistryValue -Customization FastStartup -RegKey "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power" -Name "HiberbootEnabled" -PropertyType DWord -Value $FastStartup
}

#Load the Default User registry hive
$HiveName = "DefaultUserHive"
Import-RegistryHive -File 'C:\Users\Default\NTUSER.DAT' -Key 'HKLM\DefaultUser' -Name $HiveName

#Run Default User Registry Customizations
if ($DefenderPrompt)
{
    New-RegistryValue -Customization DefenderPrompt -RegKey "$($HiveName):\SOFTWARE\Microsoft\Windows Defender" -Name "UifirstRun" -PropertyType DWord -Value $DefenderPrompt
}
if ($InkWorkspaceIcon)
{
    New-RegistryValue -Customization InkWorkspaceIcon -RegKey "$($HiveName):\SOFTWARE\Microsoft\Windows\CurrentVersion\PenWorkspace" -Name "PenWorkspaceButtonDesiredVisibility" -PropertyType DWord -Value $InkWorkspaceIcon
}
if ($TouchKeyboardIcon)
{
    New-RegistryValue -Customization TouchKeyboardIcon -RegKey "$($HiveName):\SOFTWARE\Microsoft\TabletTip\1.7" -Name "TipbandDesiredVisibility" -PropertyType DWord -Value $TouchKeyboardIcon
}
if ($SerachIcon)
{
    New-RegistryValue -Customization SerachIcon -RegKey "$($HiveName):\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -Name "SearchboxTaskbarMode" -PropertyType DWord -Value $SerachIcon
}
if ($PeopleIcon)
{
    New-RegistryValue -Customization PeopleIcon -RegKey "$($HiveName):\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People" -Name "PeopleBand" -PropertyType DWord -Value $PeopleIcon
}
if ($TaskViewIcon)
{
    New-RegistryValue -Customization TaskViewIcon -RegKey "$($HiveName):\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowTaskViewButton" -PropertyType DWord -Value $TaskViewIcon
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
        Write-Host 'Remove-RegistryHive succeeded. NTUSER.DAT updated successfully'
        break
    }
    catch
    {
        if ($Count -eq 3)
        {
            #Rethrow the exception, we gave up
            throw
        }

        Write-Host 'Remove-RegistryHive failed, trying again...'
        Write-Host "`n"

        #Wait for 100ms and trigger the garbage collector
        Start-Sleep -Milliseconds 100
        [gc]::Collect()
    }
}