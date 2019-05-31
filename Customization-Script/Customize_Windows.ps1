<#
    .DESCRIPTION
        This script can be used to apply Windows 10 customizations.
	
    .PARAMETER File
        Path to the text file that contains the customizaiton parameters
	
    .EXAMPLE
        Customize_Windows.ps1 -File C:\Temp\Parameters.txt
	
    .NOTES
        Created by: Jon Anderson
        Reference: https://github.com/ConfigJon/Windows-Customizations/tree/master/Customization-Script
#>

#Create Parameters
Param(
    [String][Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()]$File
)

#Create Functions===========================================================================================================
Function New-RegistryValue
{
    [CmdletBinding()]
    Param(
        [String][Parameter(Mandatory=$true)]$Customization,    
        [String][Parameter(Mandatory=$true)]$RegKey,
        [String][Parameter(Mandatory=$true)]$Name,
        [String][Parameter(Mandatory=$true)]$PropertyType,
        [String][Parameter(Mandatory=$true)]$Value
    )
    If (Test-Path Variable:$Customization){
        Write-Host "Running Customization - $Customization"
        
        #Create the registry key if it does not exist
        If (!(Test-Path $RegKey)){
            New-Item -Path $RegKey -Force | Out-Null
        }

        #Create the registry value
        New-ItemProperty -Path $RegKey -Name $Name -PropertyType $PropertyType -Value $Value -Force | Out-Null

        #Check if the registry value was successfully created
        $KeyCheck = Get-ItemProperty $RegKey
        If ($KeyCheck.$Name -eq $Value){
            Write-Host "Successfully set $RegKey\$Name to $Value"
            Write-Host "`n"
        }Else{
            Throw "Failed to set $RegKey\$Name to $Value"
        }
    }
}

#Import-RegistryHive and Remove-RegistryHive sourced from
#http://blog.redit.name/posts/2015/powershell-loading-registry-hive-from-file.html
Function Import-RegistryHive
{
    [CmdletBinding()]
    Param(
        [String][Parameter(Mandatory=$true)]$File,
        #Check the registry key name is not an invalid format
        [String][Parameter(Mandatory=$true)][ValidatePattern('^(HKLM\\|HKCU\\)[a-zA-Z0-9- _\\]+$')]$Key,
        #Check the PSDrive name does not include invalid characters
        [String][Parameter(Mandatory=$true)][ValidatePattern('^[^;~/\\\.\:]+$')]$Name
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
        #Validate patten on $Name in the Params and the drive name check at the start make it very unlikely New-PSDrive will fail
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
    Param(
        [String][Parameter(Mandatory=$true)][ValidatePattern('^[^;~/\\\.\:]+$')]$Name
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
        #If "reg unload" fails due to the resource being busy, the drive gets added back to keep the original state
        New-PSDrive -Name $Name -PSProvider Registry -Root $Key -Scope Global -EA Stop | Out-Null
        throw [Management.Automation.PSInvalidOperationException] "The registry key '$Key' could not be unloaded, the key may still be in use."
    }
}
#===========================================================================================================================

#Check that the specified file exists
If (!(Test-Path $File)){
    Throw "Could not find $File Please enter a vaild path to the parameters file."
}

#Check that the specified file is an ini file
$Extension = $File.Split('.')
If ($Extension[1] -ne "ini"){
    Throw "$File is not an ini file. Please specify a file with a .ini extension."
}

#Read data from the parameters file
$Parameters = Get-Content $File

#Create variables for each line in the parameters file
Foreach ($Parameter in $Parameters){
    if ($Parameter.StartsWith("#")){}
    else{
        $Variable = $Parameter.Split('=')
        New-Variable -Name $Variable[0] -Value $Variable[1] -Force
    }
}

#Import Default Application Associations
If ($DefaultApps)
{
    If ($DefaultApps -like "*.xml"){
        Write-Host "Running Customization - Import Default Application Associations"
        Dism.exe /Online /Import-DefaultAppAssociations:"$PSScriptRoot\$DefaultApps" | Out-Null
        Write-Host "Done"
        Write-Host "`n"
    }    
}

#Import Default Start Menu and Taskbar Layout
If ($StartLayout)
{
    If ($StartLayout -like "*.xml"){
        Write-Host "Running Customizations - Import Default Start Menu and Taskbar layout"
        Import-StartLayout -LayoutPath "$PSScriptRoot\$StartLayout" -MountPath "$Env:SystemDrive\"
        Write-Host "Done"
        Write-Host "`n"
    }
}

#Run HKLM Registry Customizations
If ($Cortana)
{
    New-RegistryValue -Customization Cortana -RegKey "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "AllowCortana" -PropertyType DWord -Value $Cortana
}
If ($OOBECortana)
{
    New-RegistryValue -Customization OOBECortana -RegKey "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\OOBE" -Name "DisableVoice" -PropertyType DWord -Value $OOBECortana
}
If ($WiFiSense)
{
    New-RegistryValue -Customization WiFiSense -RegKey "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots" -Name "Value" -PropertyType DWord -Value $WiFiSense
}
If ($EdgeFirstRun)
{
    New-RegistryValue -Customization EdgeFirstRun -RegKey "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Main" -Name "PreventFirstRunPage" -PropertyType DWord -Value $EdgeFirstRun
}
If ($FirstLogonAnimation)
{
    New-RegistryValue -Customization FirstLogonAnimation -RegKey "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableFirstLogonAnimation" -PropertyType DWord -Value $FirstLogonAnimation
}
If ($ConsumerFeatures)
{
    New-RegistryValue -Customization ConsumerFeatures -RegKey "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableWindowsConsumerFeatures" -PropertyType DWord -Value $ConsumerFeatures
}
If ($WindowsTips)
{
    New-RegistryValue -Customization WindowsTips -RegKey "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableSoftLanding" -PropertyType DWord -Value $WindowsTips
}
If ($EdgeDesktopShortcut)
{
    New-RegistryValue -Customization EdgeDesktopShortcut -RegKey "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -Name "DisableEdgeDesktopShortcutCreation" -PropertyType DWord -Value $EdgeDesktopShortcut
}
If ($FileExplorerView)
{
    New-RegistryValue -Customization FileExplorerView -RegKey "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "LaunchTo" -PropertyType DWord -Value $FileExplorerView
}
If ($RunAsUserStart)
{
    New-RegistryValue -Customization RunAsUserStart -RegKey "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "ShowRunasDifferentuserinStart" -PropertyType DWord -Value $RunAsUserStart
}
If ($FastStartup)
{
    New-RegistryValue -Customization FastStartup -RegKey "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power" -Name "HiberbootEnabled" -PropertyType DWord -Value $FastStartup
}

#Load the Default User registry hive
$HiveName = "DefaultUserHive"
Import-RegistryHive -File 'C:\Users\Default\NTUSER.DAT' -Key 'HKLM\DefaultUser' -Name $HiveName

#Run Default User Registry Customizations
If ($DefenderPrompt)
{
    New-RegistryValue -Customization DefenderPrompt -RegKey "$($HiveName):\SOFTWARE\Microsoft\Windows Defender" -Name "UIFirstRun" -PropertyType DWord -Value $DefenderPrompt
}
If ($InkWorkspaceIcon)
{
    New-RegistryValue -Customization InkWorkspaceIcon -RegKey "$($HiveName):\SOFTWARE\Microsoft\Windows\CurrentVersion\PenWorkspace" -Name "PenWorkspaceButtonDesiredVisibility" -PropertyType DWord -Value $InkWorkspaceIcon
}
If ($TouchKeyboardIcon)
{
    New-RegistryValue -Customization TouchKeyboardIcon -RegKey "$($HiveName):\SOFTWARE\Microsoft\TabletTip\1.7" -Name "TipbandDesiredVisibility" -PropertyType DWord -Value $TouchKeyboardIcon
}
If ($SerachIcon)
{
    New-RegistryValue -Customization SerachIcon -RegKey "$($HiveName):\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -Name "SearchboxTaskbarMode" -PropertyType DWord -Value $SerachIcon
}
If ($PeopleIcon)
{
    New-RegistryValue -Customization PeopleIcon -RegKey "$($HiveName):\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People" -Name "PeopleBand" -PropertyType DWord -Value $PeopleIcon
}
If ($TaskViewIcon)
{
    New-RegistryValue -Customization TaskViewIcon -RegKey "$($HiveName):\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowTaskViewButton" -PropertyType DWord -Value $TaskViewIcon
}

#Unload the Default User registry hive
#http://blog.redit.name/posts/2015/powershell-loading-registry-hive-from-file.html
#Attempt Remove-RegistryHive a maximum of 3 times
$Count = 0
While($true)
{
    Try
    {
        #When Remove-RegistryHive is successful break will stop the loop
        $Count++
        Remove-RegistryHive -Name $HiveName
        Write-Host 'Remove-RegistryHive succeeded. NTUSER.DAT updated successfully'
        Break
    }
    Catch
    {
        If ($Count -eq 3)
        {
            #Rethrow the exception, we gave up
            Throw
        }

        Write-Host 'Remove-RegistryHive failed, trying again...'
        Write-Host "`n"

        #Wait for 100ms and trigger the garbage collector
        Start-Sleep -Milliseconds 100
        [gc]::Collect()
    }
}