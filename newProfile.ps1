# NEWPROFILE.PS1
# This script is used to capture the SID of the destination user account after sign in.  The SID is then written to the registry.
# It is executed by the 'newProfile' scheduled task.
$settings = Get-Content -Path "$($PSScriptRoot)\settings.json" | ConvertFrom-Json

$localPath = $settings.localPath
if(!(Test-Path $localPath))
{
    mkdir $localPath
}

# Start Logging
$logPath = $settings.logPath
Start-Transcript -Path "$logPath\newProfile.log" -Verbose

# Disable newProfile task
Write-Host "Disabling newProfile task..."
try 
{
    Disable-ScheduledTask -TaskName "newProfile" -ErrorAction Stop
    Write-Host "newProfile task disabled"    
}
catch 
{
    $message = $_.Exception.Message
    Write-Host "newProfile task not disabled: $message"
}

# Get the SID of the destination user account
$newUser = Get-WmiObject -Class Win32_ComputerSystem | Select-Object -ExpandProperty UserName
Write-Host "New user: $newUser"
$newUserSID = (New-Object System.Security.Principal.NTAccount($newUser)).Translate([System.Security.Principal.SecurityIdentifier]).Value
Write-Host "New user SID: $newUserSID"

# Write the SID to the registry
$regPath = $settings.regPath
Write-Host "Writing New SID to registry..."
if($newUserSID -ne $null)
{
    try
    {
        reg.exe add $regPath /v "NewUserSID" /t REG_SZ /d $newUserSID /f | Out-Host
        Write-Host "SID written to registry"
    }
    catch
    {
        $message = $_.Exception.Message
        Write-Host "SID not written to registry: $message"
    }
}

# Set lock screen image
$lockImg1 = $settings.lockScreen1
$lockImgPath1 = "$($localPath)\$($lockImg1)"

$lockScreenPath = "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\PersonalizationCSP"
reg.exe add $lockScreenPath /v "LockScreenImagePath" /t REG_SZ /d $lockImgPath1 /f | Out-Host
reg.exe add $lockScreenPath /v "LockScreenImageUrl" /t REG_SZ /d $lockImgPath1 /f | Out-Host

# create finalBoot task
Write-Host "Creating finalBoot task..."
try
{
    schtasks.exe /Create /TN "finalBoot" /XML "$localPath\finalBoot.xml"
    Write-Host "finalBoot task created"
}
catch
{
    $message = $_.Exception.Message
    Write-Host "finalBoot task not created: $message"
}

Start-Sleep -Seconds 2
Stop-Transcript
shutdown -r -t 30
