#Create an array of apps to be removed ============================
$apps = (
    #"Microsoft.BingWeather",
    #"Microsoft.DesktopAppInstaller",
    "Microsoft.GetHelp",
    #"Microsoft.Getstarted",
    #"Microsoft.HEIFImageExtension",
    "Microsoft.Messaging",
    #"Microsoft.Microsoft3DViewer",
    #"Microsoft.MicrosoftOfficeHub",
    "Microsoft.MicrosoftSolitaireCollection",
    #"Microsoft.MicrosoftStickyNotes",
    #"Microsoft.MixedReality.Portal",
    #"Microsoft.MSPaint",
    "Microsoft.Office.OneNote",
    "Microsoft.OneConnect",
    #"Microsoft.People",
    #"Microsoft.Print3D",
    #"Microsoft.ScreenSketch",
    "Microsoft.SkypeApp",
    #"Microsoft.StorePurchaseApp",
    #"Microsoft.VP9VideoExtensions",
    #"Microsoft.Wallet",
    #"Microsoft.WebMediaExtensions",
    #"Microsoft.WebpImageExtension",
    #"Microsoft.Windows.Photos",
    #"Microsoft.WindowsAlarms",
    #"Microsoft.WindowsCalculator",
    #"Microsoft.WindowsCamera",
    "microsoft.windowscommunicationsapps",
    #"Microsoft.WindowsFeedbackHub",
    #"Microsoft.WindowsMaps",
    #"Microsoft.WindowsSoundRecorder",
    #"Microsoft.WindowsStore",
    #"Microsoft.Xbox.TCUI",
    "Microsoft.XboxApp",
    #"Microsoft.XboxGameOverlay",
    #"Microsoft.XboxGamingOverlay",
    #"Microsoft.XboxIdentityProvider",
    #"Microsoft.XboxSpeechToTextOverlay",
    "Microsoft.YourPhone")
    #"Microsoft.ZuneMusic",
    #"Microsoft.ZuneVideo"
#==================================================================

#Create a timeout function to prevent the script from hanging
#https://www.reddit.com/r/PowerShell/comments/3h1xoy/breaking_out_of_a_ps_command_after_a_certain/
function Start-Timeout {
    param(
        [scriptblock]$Command,
        [int]$Timeout
    )
   
    $ResultData = @{
        Success = $false
    }
    
    $Runspace = [runspacefactory]::CreateRunspace()
    $Runspace.Open()
    
    $PS = [powershell]::Create().AddScript($Command)
    $PS.Runspace = $Runspace
    
    $IAR = $PS.BeginInvoke()
    if($IAR.AsyncWaitHandle.WaitOne($timeout)){
        $ResultData.Success = $true
        $ResultData.Data = $PS.EndInvoke($IAR)
    }
    
    return New-Object psobject -Property $ResultData
}

#Set the command to remove the specified apps
$RemoveApps = $apps | ForEach-Object {$AppName = $PSItem; Get-AppxProvisionedPackage -Online | Where-Object {$PSItem.DisplayName -Like $AppName} | Remove-AppxProvisionedPackage -Online}

#Run the command and wait 2 minutes
$count = 0
while ($count -lt 1){
    $Output = Start-Timeout -Command {$RemoveApps} -Timeout 60000
    if($Output.Success){
        $count++
        Write-Host $Output.Data
    }
}