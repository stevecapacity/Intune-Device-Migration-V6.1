<# FINALBOOT.PS1
Synopsis
Finalboot.ps1 is the last script that automatically reboots the PC.
DESCRIPTION
This script is used to change ownership of the original user profile to the destination user and then reboot the machine.  It is executed by the 'finalBoot' scheduled task.
USE
.\finalBoot.ps1
.OWNER
Steve Weiner
.CONTRIBUTORS
Logan Lautt
Jesse Weimer
#>

$ErrorActionPreference = "SilentlyContinue"
# CMDLET FUNCTIONS

# set log function
function log()
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [string]$message
    )
    $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss tt"
    Write-Output "$ts $message"
}

function exitScript()
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [int]$exitCode,
        [string]$functionName,
        [string]$localpath = $localPath
    )
    if($exitCode -eq 1)
    {
        log "Function $($functionName) failed with critical error.  Exiting script with exit code $($exitCode)."
        log "Will remove $($localpath) and reboot device.  Please log in with local admin credentials on next boot to troubleshoot."
        Remove-Item -Path $localpath -Recurse -Force -Verbose
        log "Removed $($localpath)."
        # enable password logon provider
        reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers\{60b78e88-ead8-445c-9cfd-0b87f74ea6cd}" /v "Disabled" /t REG_DWORD /d 0 /f | Out-Host
        log "Enabled logon provider."
        log "rebooting device..."
        shutdown -r -t 30
        Stop-Transcript
        Exit -1
    }
    elseif($exitCode -eq 4)
    {
        log "Function $($functionName) failed with non-critical error.  Exiting script with exit code $($exitCode)."
        Remove-Item -Path $localpath -Recurse -Force -Verbose
        log "Removed $($localpath)."
        Stop-Transcript
        Exit 1
    }
    else
    {
        log "Function $($functionName) failed with unknown error.  Exiting script with exit code $($exitCode)."
        Stop-Transcript
        Exit 1
    }
}   

# CMDLET FUNCTIONS

# START SCRIPT FUNCTIONS

# get json settings
function getSettingsJSON()
{
    param(
        [string]$json = "settings.json"
    )
    $global:settings = Get-Content -Path "$($PSScriptRoot)\$($json)" | ConvertFrom-Json
    return $settings
}

# initialize script
function initializeScript()
{
    Param(
        [string]$logPath = $settings.logPath,
        [string]$logName = "finalBoot.log",
        [string]$localPath = $settings.localPath
    )
    Start-Transcript -Path "$logPath\$logName" -Verbose
    log "Initializing script..."
    if(!(Test-Path $localPath))
    {
        mkdir $localPath
        log "Local path created: $localPath"
    }
    else
    {
        log "Local path already exists: $localPath"
    }
    $global:localPath = $localPath
    $context = whoami
    log "Running as $($context)"
    log "Script initialized"
    return $localPath
}

# disable finalBoot task
function disableFinalBootTask()
{
    Param(
        [string]$taskName = "finalBoot"
    )
    Write-Host "Disabling finalBoot task..."
    try 
    {
        Disable-ScheduledTask -TaskName $taskName
        Write-Host "finalBoot task disabled"    
    }
    catch 
    {
        $message = $_.Exception.Message
        Write-Host "finalBoot task not disabled: $message"
    }
}

# enable auto logon
function disableAutoLogon()
{
    Param(
        [string]$autoLogonPath = "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
        [string]$autoAdminLogon = "AutoAdminLogon",
        [int]$autoAdminLogonValue = 0
    )
    log "Disabling auto logon..."
    reg.exe add $autoLogonPath /v $autoAdminLogon /t REG_SZ /d $autoAdminLogonValue /f | Out-Host
    log "Auto logon disabled"
}

# get user info from registry
function getUserInfo()
{
    Param(
        [string]$regPath = $settings.regPath,
        [string]$regKey = "Registry::$regPath",
        [array]$userArray = @("OriginalUserSID", "OriginalUserName", "OriginalProfilePath", "OriginalSAMName", "NewSAMName", "NewUserSID")
    )
    log "Getting user info from registry..."
    foreach($user in $userArray)
    {
        $value = Get-ItemPropertyValue -Path $regKey -Name $user
        if(![string]::IsNullOrEmpty($value))
        {
            New-Variable -Name $user -Value $value -Scope Global -Force
            log "$($user): $value"
        }
    }
}

# remove AAD.Broker.Plugin from original profile
function removeAADBrokerPlugin()
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [string]$originalProfilePath,
        [string]$aadBrokerPlugin = "Microsoft.AAD.BrokerPlugin_*"
    )
    log "Removing AAD.Broker.Plugin from original profile..."
    $aadBrokerPath = (Get-ChildItem -Path "$($originalProfilePath)\AppData\Local\Packages" -Recurse | Where-Object {$_.Name -match $aadBrokerPlugin} | Select-Object FullName).FullName
    if([string]::IsNullOrEmpty($aadBrokerPath))
    {
        log "AAD.Broker.Plugin not found"
    }
    else
    {
        Remove-Item -Path $aadBrokerPath -Recurse -Force -ErrorAction SilentlyContinue
        log "AAD.Broker.Plugin removed" 
    }
}

# delete new user profile
function deleteNewUserProfile()
{
    Param(
        [string]$newUserSID = $NewUserSID
    )
    log "Deleting new user profile..."
    $newProfile = Get-CimInstance -ClassName Win32_UserProfile | Where-Object {$_.SID -eq $newUserSID}
    Remove-CimInstance -InputObject $newProfile -Verbose | Out-Null
    log "New user profile deleted"
}

# change ownership of original profile
function changeOriginalProfileOwner()
{
    Param(
        [string]$originalUserSID = $OriginalUserSID,
        [string]$newUserSID = $NewUserSID
    )
    log "Changing ownership of original profile..."
    $originalProfile = Get-CimInstance -ClassName Win32_UserProfile | Where-Object {$_.SID -eq $originalUserSID}
    $changeArguments = @{
        NewOwnerSID = $newUserSID
        Flags = 0
    }
    $originalProfile | Invoke-CimMethod -MethodName ChangeOwner -Arguments $changeArguments
    Start-Sleep -Seconds 1
}

# cleanup identity store cache
function cleanupLogonCache()
{
    Param(
        [string]$logonCache = "HKLM:\SOFTWARE\Microsoft\IdentityStore\LogonCache",
        [string]$oldUserName = $OriginalUserName
    )
    log "Cleaning up identity store cache..."
    $logonCacheGUID = (Get-ChildItem -Path $logonCache | Select-Object Name | Split-Path -Leaf).trim('{}')
    foreach($GUID in $logonCacheGUID)
    {
        $subKeys = Get-ChildItem -Path "$logonCache\$GUID" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name | Split-Path -Leaf
        if(!($subKeys))
        {
            log "No subkeys found for $GUID"
            continue
        }
        else
        {
            $subKeys = $subKeys.trim('{}')
            foreach($subKey in $subKeys)
            {
                if($subKey -eq "Name2Sid" -or $subKey -eq "SAM_Name" -or $subKey -eq "Sid2Name")
                {
                    $subFolders = Get-ChildItem -Path "$logonCache\$GUID\$subKey" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name | Split-Path -Leaf
                    if(!($subFolders))
                    {
                        log "Error - no sub folders found for $subKey"
                        continue
                    }
                    else
                    {
                        $subFolders = $subFolders.trim('{}')
                        foreach($subFolder in $subFolders)
                        {
                            $cacheUsername = Get-ItemPropertyValue -Path "$logonCache\$GUID\$subKey\$subFolder" -Name "IdentityName" -ErrorAction SilentlyContinue
                            if($cacheUsername -eq $oldUserName)
                            {
                                Remove-Item -Path "$logonCache\$GUID\$subKey\$subFolder" -Recurse -Force
                                log "Registry key deleted: $logonCache\$GUID\$subKey\$subFolder"
                                continue                                       
                            }
                        }
                    }
                }
            }
        }
    }
}

# cleanup identity store cache
function cleanupIdentityStore()
{
    Param(
        [string]$idCache = "HKLM:\Software\Microsoft\IdentityStore\Cache",
        [string]$oldUserName = $OriginalUserName
    )
    log "Cleaning up identity store cache..."
    $idCacheKeys = (Get-ChildItem -Path $idCache | Select-Object Name | Split-Path -Leaf).trim('{}')
    foreach($key in $idCacheKeys)
    {
        $subKeys = Get-ChildItem -Path "$idCache\$key" -ErrorAction SilentlyContinue | Select-Object Name | Split-Path -Leaf
        if(!($subKeys))
        {
            log "No keys listed under '$idCache\$key' - skipping..."
            continue
        }
        else
        {
            $subKeys = $subKeys.trim('{}')
            foreach($subKey in $subKeys)
            {
                $subFolders = Get-ChildItem -Path "$idCache\$key\$subKey" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name | Split-Path -Leaf
                if(!($subFolders))
                {
                    log "No subfolders detected for $subkey- skipping..."
                    continue
                }
                else
                {
                    $subFolders = $subFolders.trim('{}')
                    foreach($subFolder in $subFolders)
                    {
                        $idCacheUsername = Get-ItemPropertyValue -Path "$idCache\$key\$subKey\$subFolder" -Name "UserName" -ErrorAction SilentlyContinue
                        if($idCacheUsername -eq $oldUserName)
                        {
                            Remove-Item -Path "$idCache\$key\$subKey\$subFolder" -Recurse -Force
                            log "Registry path deleted: $idCache\$key\$subKey\$subFolder"
                            continue
                        }
                    }
                }
            }
        }
    }
}

Start-Sleep -Seconds 1

# update samname in identityStore LogonCache (this is required when displaynames are the same in both tenants, and new samname gets random characters added at the end)
function updateSamNameLogonCache()
{
    Param(
        [string]$logonCache = "HKLM:\SOFTWARE\Microsoft\IdentityStore\LogonCache",
        [string]$newUserSID = $NewUserSID,
        [string]$originalUser = $originalSAMName,
        [string]$newUser = $newSAMName
    )

    if($newUser -like "$($originalUser)_*")
    {
        log "New user is $newUser, which is the same as $originalUser with _##### appended to the end. Removing appended characters on SamName in LogonCache registry..."

        $logonCacheGUID = (Get-ChildItem -Path $logonCache | Select-Object Name | Split-Path -Leaf).trim('{}')
        foreach($GUID in $logonCacheGUID)
        {
            $subKeys = Get-ChildItem -Path "$logonCache\$GUID" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name | Split-Path -Leaf
            if(!($subKeys))
            {
                log "No subkeys found for $GUID"
                continue
            }
            else
            {
                $subKeys = $subKeys.trim('{}')
                foreach($subKey in $subKeys)
                {
                    if($subKey -eq "Name2Sid")
                    {
                        $subFolders = Get-ChildItem -Path "$logonCache\$GUID\$subKey" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name | Split-Path -Leaf
                        if(!($subFolders))
                        {
                            log "Error - no sub folders found for $subKey"
                            continue
                        }
                        else
                        {
                            $subFolders = $subFolders.trim('{}')
                            foreach($subFolder in $subFolders)
                            {
                                $detectedUserSID = Get-ItemProperty -Path "$logonCache\$GUID\$subKey\$subFolder" | Select-Object -ExpandProperty "Sid" -ErrorAction SilentlyContinue
                                if($detectedUserSID -eq $newUserSID)
                                {
                                    Set-ItemProperty -Path "$logonCache\$GUID\$subKey\$subFolder" -Name "SAMName" -Value $originalUser -Force
                                    log "Attempted to update SAMName value (in Name2Sid registry folder) to '$($originalUser)'."
                                    continue                                       
                                }
                                else
                                {
                                    log "Detected Sid '$detectedUserSID' is for different user - skipping Sid in Name2Sid registry folder..."
                                }
                            }
                        }
                    }
                    elseif($subKey -eq "SAM_Name")
                    {
                        $subFolders = Get-ChildItem -Path "$logonCache\$GUID\$subKey" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name | Split-Path -Leaf
                        if(!($subFolders))
                        {
                            log "Error - no sub folders found for $subKey"
                            continue
                        }
                        else
                        {
                            $subFolders = $subFolders.trim('{}')
                            foreach($subFolder in $subFolders)
                            {
                                $detectedUserSID = Get-ItemProperty -Path "$logonCache\$GUID\$subKey\$subFolder" | Select-Object -ExpandProperty "Sid" -ErrorAction SilentlyContinue
                                if($detectedUserSID -eq $newUserSID)
                                {
                                    Rename-Item "$logonCache\$GUID\$subKey\$subFolder" -NewName $originalUser -Force
                                    log "Attempted to update SAM_Name key name (in SAM_Name registry folder) to '$($originalUser)'."
                                    continue                                       
                                }
                                else
                                {
                                    log "Skipping different user in SAM_Name registry folder (User: $subFolder, SID: $detectedUserSID)..."
                                }
                            }
                        }
                    }
                    elseif($subKey -eq "Sid2Name")
                    {
                        $subFolders = Get-ChildItem -Path "$logonCache\$GUID\$subKey" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name | Split-Path -Leaf
                        if(!($subFolders))
                        {
                            log "Error - no sub folders found for $subKey"
                            continue
                        }
                        else
                        {
                            $subFolders = $subFolders.trim('{}')
                            foreach($subFolder in $subFolders)
                            {
                                if($subFolder -eq $newUserSID)
                                {
                                    Set-ItemProperty -Path "$logonCache\$GUID\$subKey\$subFolder" -Name "SAMName" -Value $originalUser -Force
                                    log "Attempted to update SAM_Name value (in Sid2Name registry folder) to '$($originalUser)'."
                                    continue                                       
                                }
                                else
                                {
                                    log "Skipping different user SID ($subFolder) in Sid2Name registry folder..."
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    else
    {
        log "New username is $newUser, which does not match older username ($originalUser) with _##### appended to end. SamName LogonCache registry will not be updated."
    }
}


# update samname in identityStore Cache (this is required when displaynames are the same in both tenants, and new samname gets random characters added at the end)
function updateSamNameIdentityStore()
{
    Param(
        [string]$idCache = "HKLM:\Software\Microsoft\IdentityStore\Cache",
        [string]$targetSAMName = $originalSAMName,
        [string]$newUserSID = $NewUserSID
    )
    log "Cleaning up identity store cache..."
    $idCacheKeys = (Get-ChildItem -Path $idCache | Select-Object Name | Split-Path -Leaf).trim('{}')
    foreach($key in $idCacheKeys)
    {
        $subKeys = Get-ChildItem -Path "$idCache\$key" -ErrorAction SilentlyContinue | Select-Object Name | Split-Path -Leaf
        if(!($subKeys))
        {
            log "No keys listed under '$idCache\$key' - skipping..."
            continue
        }
        else
        {
            $subKeys = $subKeys.trim('{}')
            foreach($subKey in $subKeys)
            {
                $subFolders = Get-ChildItem -Path "$idCache\$key\$subKey" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name | Split-Path -Leaf
                if(!($subFolders))
                {
                    log "No subfolders detected for $subkey- skipping..."
                    continue
                }
                else
                {
                    $subFolders = $subFolders.trim('{}')
                    foreach($subFolder in $subFolders)
                    {
                        if($subFolder -eq $newUserSID)
                        {
                            Set-ItemProperty -Path "$idCache\$key\$subKey\$subFolder" -Name "SAMName" -Value $targetSAMName -Force
                            log "Attempted to update SAMName value to $targetSAMName."
                        }
                    }
                }
            }
        }
    }
}


# set display last user name policy
function displayLastUsername()
{
    Param(
        [string]$regPath = "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
        [string]$regKey = "Registry::$regPath",
        [string]$regName = "DontDisplayLastUserName",
        [int]$regValue = 0
    )
    $currentRegValue = Get-ItemPropertyValue -Path $regKey -Name $regName
    if($currentRegValue -eq $regValue)
    {
        log "$($regName) is already set to $($regValue)."
    }
    else
    {
        reg.exe add $regPath /v $regName /t REG_DWORD /d $regValue /f | Out-Host
        log "Set $($regName) to $($regValue) at $regPath."
    }
}

# set post migrate tasks
function setPostMigrateTasks()
{
    Param(
        [array]$tasks = @("postMigrate","AutopilotRegistration"),
        [string]$localPath = $localPath
    )
    log "Setting post migrate tasks..."
    foreach($task in $tasks)
    {
        $taskPath = "$($localPath)\$($task).xml"
        if($taskPath)
        {
            schtasks.exe /Create /TN $task /XML $taskPath
            log "$($task) task set."
        }
        else
        {
            log "Failed to set $($task) task: $taskPath not found"
        }
    }
}

# restore logon credential provider
function restoreLogonProvider()
{
    Param(
        [string]$logonProviderPath = "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers\{60b78e88-ead8-445c-9cfd-0b87f74ea6cd}",
        [string]$logonProviderName = "Disabled",
        [int]$logonProviderValue = 0
    )
    reg.exe add $logonProviderPath /v $logonProviderName /t REG_DWORD /d $logonProviderValue /f | Out-Host
    log "Logon credential provider restored"
}

# set lock screen caption
function setLockScreenCaption()
{
    Param(
        [string]$targetTenantName = $settings.targetTenant.tenantName,
        [string]$legalNoticeRegPath = "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
        [string]$legalNoticeCaption = "legalnoticecaption",
        [string]$legalNoticeCaptionValue = "Welcome to $($targetTenantName)!",
        [string]$legalNoticeText = "legalnoticetext",
        [string]$legalNoticeTextValue = "Your PC is now part of $($targetTenantName).  Please sign in."
    )
    log "Setting lock screen caption..."
    reg.exe add $legalNoticeRegPath /v $legalNoticeCaption /t REG_SZ /d $legalNoticeCaptionValue /f | Out-Host
    reg.exe add $legalNoticeRegPath /v $legalNoticeText /t REG_SZ /d $legalNoticeTextValue /f | Out-Host
    log "Set lock screen caption."
}

# END SCRIPT FUNCTIONS

# START SCRIPT

# run get settings
log "Running FUNCTION: getSettingsJSON..."
try
{
    getSettingsJSON
    log "FUNCTION: getSettingsJSON ran successfully"
}
catch
{
    $message = $_.Exception.Message
    log "FUNCTION: getSettingsJSON failed: $message"
    log "Exiting script"
    exitScript -exitCode 1 -functionName "getSettingsJSON"
}

# run initialize script
log "Running FUNCTION: initializeScript..."
try
{
    initializeScript
    log "FUNCTION: initializeScript ran successfully"
}
catch
{
    $message = $_.Exception.Message
    log "FUNCTION: initializeScript failed: $message"
    log "Exiting script"
    exitScript -exitCode 1 -functionName "initializeScript"
}

# run disable finalBoot task
log "Running FUNCTION: disableFinalBootTask..."
try
{
    disableFinalBootTask
    log "FUNCTION: disableFinalBootTask ran successfully"
}
catch
{
    $message = $_.Exception.Message
    log "FUNCTION: disableFinalBootTask failed: $message"
    log "Exiting script"
    exitScript -exitCode 1 -functionName "disableFinalBootTask"
}

# run disable auto logon
log "Running FUNCTION: disableAutoLogon..."
try
{
    disableAutoLogon
    log "FUNCTION: disableAutoLogon ran successfully"
}
catch
{
    $message = $_.Exception.Message
    log "FUNCTION: disableAutoLogon failed: $message"
    log "Exiting script"
    exitScript -exitCode 1 -functionName "disableAutoLogon"
}

# run get user info
log "Running FUNCTION: getUserInfo..."
try
{
    getUserInfo
    log "FUNCTION: getUserInfo ran successfully"
}
catch
{
    $message = $_.Exception.Message
    log "FUNCTION: getUserInfo failed: $message"
    log "Exiting script"
    exitScript -exitCode 1 -functionName "getUserInfo"
}

# run remove AAD.Broker.Plugin
log "Running FUNCTION: removeAADBrokerPlugin..."
try
{
    removeAADBrokerPlugin
    log "FUNCTION: removeAADBrokerPlugin ran successfully"
}
catch
{
    $message = $_.Exception.Message
    log "FUNCTION: removeAADBrokerPlugin failed: $message"
    log "WARNING: Remove AAD.Broker.Plugin manually"
}

# run delete new user profile
log "Running FUNCTION: deleteNewUserProfile..."
try
{
    deleteNewUserProfile
    log "FUNCTION: deleteNewUserProfile ran successfully"
}
catch
{
    $message = $_.Exception.Message
    log "FUNCTION: deleteNewUserProfile failed: $message"
    log "Exiting script"
    exitScript -exitCode 1 -functionName "deleteNewUserProfile"
}

# run change original profile owner
log "Running FUNCTION: changeOriginalProfileOwner..."
try
{
    changeOriginalProfileOwner
    log "FUNCTION: changeOriginalProfileOwner ran successfully"
}
catch
{
    $message = $_.Exception.Message
    log "FUNCTION: changeOriginalProfileOwner failed: $message"
    log "Exiting script"
    exitScript -exitCode 1 -functionName "changeOriginalProfileOwner"
}

# run cleanup logon cache
log "Running FUNCTION: cleanupLogonCache..."
try
{
    cleanupLogonCache
    log "FUNCTION: cleanupLogonCache ran successfully"
}
catch
{
    $message = $_.Exception.Message
    log "FUNCTION: cleanupLogonCache failed: $message"
    log "Exiting script"
    exitScript -exitCode 1 -functionName "cleanupLogonCache"
}

# run cleanup identity store
log "Running FUNCTION: cleanupIdentityStore..."
try
{
    cleanupIdentityStore
    log "FUNCTION: cleanupIdentityStore ran successfully"
}
catch
{
    $message = $_.Exception.Message
    log "FUNCTION: cleanupIdentityStore failed: $message"
    log "Exiting script"
    exitScript -exitCode 1 -functionName "cleanupIdentityStore"
}

# run update samname in logon cache
log "Running FUNCTION: updateSamNameLogonCache..."
try
{
    updateSamNameLogonCache
    log "FUNCTION: updateSamNameLogonCache ran successfully"
}
catch
{
    $message = $_.Exception.Message
    log "FUNCTION: updateSamNameLogonCache failed: $message"
    log "Exiting script"
    exitScript -exitCode 1 -functionName "updateSamNameLogonCache"
}

# run update samname in identity store cache
log "Running FUNCTION: updateSamNameIdentityStore..."
try
{
    updateSamNameIdentityStore
    log "FUNCTION: updateSamNameIdentityStore ran successfully"
}
catch
{
    $message = $_.Exception.Message
    log "FUNCTION: updateSamNameIdentityStore failed: $message"
    log "Exiting script"
    exitScript -exitCode 1 -functionName "updateSamNameIdentityStore"
}

# run display last username
log "Running FUNCTION: displayLastUsername..."
try
{
    displayLastUsername
    log "FUNCTION: displayLastUsername ran successfully"
}
catch
{
    $message = $_.Exception.Message
    log "FUNCTION: displayLastUsername failed: $message"
    log "Exiting script"
    exitScript -exitCode 1 -functionName "displayLastUsername"
}

# run set post migrate tasks
log "Running FUNCTION: setPostMigrateTasks..."
try
{
    setPostMigrateTasks
    log "FUNCTION: setPostMigrateTasks ran successfully"
}
catch
{
    $message = $_.Exception.Message
    log "FUNCTION: setPostMigrateTasks failed: $message"
    log "WARNING: Post migrate tasks not set.  Run manually"
}

# run restore logon provider
log "Running FUNCTION: restoreLogonProvider..."
try
{
    restoreLogonProvider
    log "FUNCTION: restoreLogonProvider ran successfully"
}
catch
{
    $message = $_.Exception.Message
    log "FUNCTION: restoreLogonProvider failed: $message"   
    log "Exiting script"
    exitScript -exitCode 1 -functionName "restoreLogonProvider"
}

# run set lock screen caption
log "Running FUNCTION: setLockScreenCaption..."
try
{
    setLockScreenCaption
    log "FUNCTION: setLockScreenCaption ran successfully"
}
catch
{
    $message = $_.Exception.Message
    log "FUNCTION: setLockScreenCaption failed: $message"
    log "WARNING: Lock screen caption not set.  Fix manually"
}

# END SCRIPT
log "Script completed"
log "Rebooting machine..."

shutdown -r -t 2

Stop-Transcript