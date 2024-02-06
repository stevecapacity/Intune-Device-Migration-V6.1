# FINALBOOT.PS1
# This script is used to change ownership of the original user profile to the destination user and then reboot the machine.
# It is executed by the 'finalBoot' scheduled task.

$settings = Get-Content -Path "$($PSScriptRoot)\settings.json" | ConvertFrom-Json
$localPath = $settings.localPath
if(!(Test-Path $localPath))
{
    mkdir $localPath
}

# Start Logging
Start-Transcript -Path "$localPath\finalBoot.log" -Verbose

# Disable finalBoot task
Write-Host "Disabling finalBoot task..."
try 
{
    Disable-ScheduledTask -TaskName "finalBoot" -ErrorAction Stop
    Write-Host "finalBoot task disabled"    
}
catch 
{
    $message = $_.Exception.Message
    Write-Host "finalBoot task not disabled: $message"
}

# reset lock screen image
$lockImg2 = $settings.lockScreen2
$lockImgPath2 = "$($localPath)\$($lockImg2)"

Write-Host "Resetting lock screen image..."
$lockScreenPath = "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\PersonalizationCSP"
reg.exe add $lockScreenPath /v "LockScreenImagePath" /t REG_SZ /d $lockImgPath2 /f | Out-Host
reg.exe add $lockScreenPath /v "LockScreenImageUrl" /t REG_SZ /d $lockImgPath2 /f | Out-Host

# get original user info from registry
$regPath = $settings.regPath
$key = "Registry::$regPath"

Write-Host "Getting original user info from registry..."
try 
{
    $originalUserSID = Get-ItemPropertyValue -Path $key -Name "OriginalUserSID"
    Write-Host "Original user SID: $originalUserSID"   
}
catch 
{
    $message = $_.Exception.Message
    Write-Host "Original user SID not found: $message"
}
try {
    $originalUserName = Get-ItemPropertyValue -Path $key -Name "OriginalUserName"
    Write-Host "Original user name: $originalUserName"
}
catch {
    $errorMessage = $_.Exception.Message
    Write-Host "Error retrieving original user name: $errorMessage"
}
try 
{
    $originalProfilePath = Get-ItemPropertyValue -Path $key -Name "OriginalProfilePath"
    Write-Host "Original profile path: $originalProfilePath"    
}
catch 
{
    $message = $_.Exception.Message
    Write-Host "Original profile path not found: $message"
}


# get new user info from registry
Write-Host "Getting new user info from registry..."
try
{
    $newUserSID = Get-ItemPropertyValue -Path $key -Name "NewUserSID"
    Write-Host "New user SID: $newUserSID"
}
catch
{
    $message = $_.Exception.Message
    Write-Host "New user SID not found: $message"
}

# Delete aadBroker plugin folder in old profile
Write-Host "Deleting AAD.Broker plugin folder in old profile..."
$aadBrokerFolder = Get-ChildItem -Path "$($originalProfilePath)\AppData\Local\Packages" -ErrorAction SilentlyContinue | Where-Object {$_.Name -match "Microsoft.AAD.BrokerPlugin_*"} | Select-Object -ExpandProperty Name
$aadBrokerPath = "$($originalProfilePath)\AppData\Local\Packages\$($aadBrokerFolder)"
Write-Host "AAD.BrokerPlugin folder: $aadBrokerPath"
try 
{
    Remove-Item -Path $aadBrokerPath -Recurse -Force -ErrorAction SilentlyContinue
    Write-Host "AAD.BrokerPlugin folder deleted"
}
catch 
{
    $message = $_.Exception.Message
    Write-Host "AAD.BrokerPlugin folder not deleted: $message"    
}

# delete new user profile
Write-Host "Deleting new user profile..."
$newProfile = Get-CimInstance -ClassName Win32_UserProfile | Where-Object {$_.SID -eq $newUserSID}
Remove-CimInstance -InputObject $newProfile -Verbose | Out-Null

Start-Sleep -Seconds 2

# change ownership of old profile to new user
Write-Host "Changing ownership of old profile to new user..."
$originalProfile = Get-CimInstance -ClassName Win32_UserProfile | Where-Object {$_.SID -eq $originalUserSID}
$changeArguments = @{
    NewOwnerSID = $newUserSID
    Flags = 0
}
$originalProfile | Invoke-CimMethod -MethodName "ChangeOwner" -Arguments $changeArguments

Start-Sleep -Seconds 1

# cleanup registry
Write-Host "Cleaning up registry..."
$logonCache = "HKLM:\SOFTWARE\Microsoft\IdentityStore\LogonCache"
$logonCacheGUID = (Get-ChildItem -Path $logonCache | Select-Object Name | Split-Path -Leaf).trim('{}')
$oldUserName = $originalUserName

foreach($guid in $logonCacheGUID)
{
    $subKeys = Get-ChildItem -Path "$logonCache\$guid" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name | Split-Path -Leaf
    if(!($subKeys))
    {
        Write-Host "No subkeys found for $guid"
        continue
    }
    else
    {
        $subKeys = $subKeys.trim('{}')
        foreach($subKey in $subKeys)
        {
            if($subKey -eq "Name2Sid" -or $subKey -eq "SAM_Name" -or $subKey -eq "Sid2Name")
            {
                $subFolders = Get-ChildItem -Path "$logonCache\$guid\$subKey" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name | Split-Path -Leaf
                if(!($subFolders))
                {
                    Write-Host "Error - no sub folders found for $subKey"
                    continue
                }
                else
                {
                    $subFolders = $subFolders.trim('{}')
                    foreach($subFolder in $subFolders)
                    {
                        $cacheUsername = Get-ItemPropertyValue -Path "$logonCache\$guid\$subKey\$subFolder" -Name "IdentityName" -ErrorAction SilentlyContinue
                        if($cacheUsername -eq $oldUserName)
                        {
                            Write-Host "Deleting registry key $logonCache\$guid\$subKey\$subFolder..."
                            Remove-Item -Path "$logonCache\$guid\$subKey\$subFolder" -Recurse -Force
                            Continue
                        }
                    }
                }
            }
        }
    }
}

$idCache = "HKLM:\Software\Microsoft\IdentityStore\Cache"
$idCacheKeys = (Get-ChildItem -Path $idCache | Select-Object Name | Split-Path -Leaf).trim('{}')

foreach($key in $idCacheKeys)
{
    $subKeys = Get-ChildItem -Path "$idCache\$key" -ErrorAction SilentlyContinue | Select-Object Name | Split-Path -Leaf
    if(!($subKeys))
    {
        Write-Host "No keys listed under '$idCache\$guid' - skipping..."
        continue
    }
    else
    {
        $subKeys = $subKeys.trim('{}')
        foreach($subKey in $subKeys)
        {
            $subFolders = Get-ChildItem -Path "$idCache\$key\$subKey" -ErrorAction SilentlyContinue | Select-Object Name | Split-Path -Leaf
            if(!($subFolders))
            {
                Write-Host "Error - no sub folders detected for $subKey. Skipping subKey '$subKey'..." -ForegroundColor Yellow
                continue
            }
            else
            {
                $subFolders = $subFolders.trim('{}')
                foreach($subFolder in $subFolders)
                {
                    $idCacheUsername = Get-ItemPropertyValue -Path "$idCache\$key\$subKey\$subFolder" -Name "UserName" -ErrorAction SilentlyContinue
                    if($idCacheUsername -eq $oldUsername)
                    {
                        Write-Host "Deleting registry path '$idCache\$key\$subKey\$subFolder'..." -ForegroundColor Yellow
                        Remove-Item -Path "$idCache\$key\$subKey\$subFolder" -Recurse -Force
                        Continue
                    }
                }
            }
        }
    }
}

# Renable the GPO so the user can see the last signed-in user on logon screen
try {
	Set-ItemProperty -Path "HKLM:Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name dontdisplaylastusername -Value 0 -Type DWORD
	Write-Host "$(Get-TimeStamp) - Disable Interactive Logon GPO"
} 
catch {
	Write-Host "$(Get-TimeStamp) - Failed to disable GPO"
}

# Set post migrate task to run at next login
Write-Host "Setting post migrate task to run at next login..."
try
{
    schtasks.exe /Create /TN "postMigrate" /XML "$($localPath)\postMigrate.xml"
    Write-Host "postMigrate task created"
}
catch
{
    $message = $_.Exception.Message
    Write-Host "postMigrate task not created: $message"
}
# Set AutopilotRegistration task to run at next login
Write-Host "Setting AutopilotRegistration task to run at next login..."
try
{
    schtasks.exe /Create /TN "AutopilotRegistration" /XML "$($localPath)\AutopilotRegistration.xml"
    Write-Host "AutopilotRegistration task created"
}
catch
{
    $message = $_.Exception.Message
    Write-Host "AutopilotRegistration task not created: $message"
}

Stop-Transcript
shutdown -r -t 00