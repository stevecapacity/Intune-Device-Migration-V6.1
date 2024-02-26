<# NEWPROFILE.PS1
Synopsis
Newprofile.ps1 runs after the user signs in with their target account.
DESCRIPTION
This script is used to capture the SID of the destination user account after sign in.  The SID is then written to the registry.
USE
This script is intended to be run as a scheduled task.  The task is created by the startMigrate.ps1 script and is disabled by this script.
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

# exit script function
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

# initialize script
function initializeScript()
{
    Param(
        [string]$logPath = $settings.logPath,
        [string]$logName = "newProfile.log",
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

# get new user SID
function getNewUserInfo()
{
    Param(
        [string]$regPath = $settings.regPath,
        [string]$newUser = (Get-WmiObject -Class Win32_ComputerSystem | Select-Object -ExpandProperty UserName),
        [string]$newUserSID = (New-Object System.Security.Principal.NTAccount($newUser)).Translate([System.Security.Principal.SecurityIdentifier]).Value,
        [string]$newSAMName = ($newUser).Split("\")[1]
    )
    log "New user: $newUser"
    if(![string]::IsNullOrEmpty($newUserSID))
    {
        reg.exe add $regPath /v "NewUserSID" /t REG_SZ /d $newUserSID /f | Out-Host
        log "SID written to registry"
    
    }
    else
    {
        log "New user SID not found"
    }
    if(![string]::IsNullOrEmpty($newSAMName))
    {
        reg.exe add $regPath /v "NewSAMName" /t REG_SZ /d $newSAMName /f | Out-Host
        log "SAMName written to registry"
    }
    else
    {
        log "New SAMName not found"
    }
}

# disable newProfile task
function disableNewProfileTask()
{
    Param(
        [string]$taskName = "newProfile"
    )
    Disable-ScheduledTask -TaskName $taskName -ErrorAction Stop
    log "newProfile task disabled"    
}

# revoke logon provider
function revokeLogonProvider()
{
    Param(
        [string]$logonProviderPath = "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers\{60b78e88-ead8-445c-9cfd-0b87f74ea6cd}",
        [string]$logonProviderName = "Disabled",
        [int]$logonProviderValue = 1
    )
    reg.exe add $logonProviderPath /v $logonProviderName /t REG_DWORD /d $logonProviderValue /f | Out-Host
    log "Revoked logon provider."
}

# set lock screen caption
function setLockScreenCaption()
{
    Param(
        [string]$targetTenantName = $settings.targetTenant.tenantName,
        [string]$legalNoticeRegPath = "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
        [string]$legalNoticeCaption = "legalnoticecaption",
        [string]$legalNoticeCaptionValue = "Almost there...",
        [string]$legalNoticeText = "legalnoticetext",
        [string]$legalNoticeTextValue = "Your PC will restart one more time to join the $($targetTenantName) environment."
    )
    log "Setting lock screen caption..."
    reg.exe add $legalNoticeRegPath /v $legalNoticeCaption /t REG_SZ /d $legalNoticeCaptionValue /f | Out-Host
    reg.exe add $legalNoticeRegPath /v $legalNoticeText /t REG_SZ /d $legalNoticeTextValue /f | Out-Host
    log "Set lock screen caption."
}

# enable auto logon
function enableAutoLogon()
{
    Param(
        [string]$autoLogonPath = "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
        [string]$autoLogonName = "AutoAdminLogon",
        [string]$autoLogonValue = 1
    )
    log "Enabling auto logon..."
    reg.exe add $autoLogonPath /v $autoLogonName /t REG_SZ /d $autoLogonValue /f | Out-Host
    log "Auto logon enabled."
}

# set finalBoot task
function setFinalBootTask()
{
    Param(
        [string]$taskName = "finalBoot",
        [string]$taskXML = "$($localPath)\$($taskName).xml"
    )
    log "Setting $($taskName) task..."
    if($taskXML)
    {
        schtasks.exe /Create /TN $taskName /XML $taskXML
        log "$($taskName) task set."
    }
    else
    {
        log "Failed to set $($taskName) task: $taskXML not found"
    }
}

# END SCRIPT FUNCTIONS

# START SCRIPT

# get settings
log "Running FUNCTION: getSettingsJSON..."
try
{
    getSettingsJSON
    log "FUNCTION: getSettingsJSON completed successfully"
}
catch
{
    $message = $_.Exception.Message
    log "FUNCTION: getSettingsJSON failed: $message"
    log "Exiting script"
    exitScript -exitCode 1 -functionName "getSettingsJSON"
}

# initialize script
log "Running FUNCTION: initializeScript..."
try
{
    initializeScript
    log "FUNCTION: initializeScript completed successfully"
}
catch
{
    $message = $_.Exception.Message
    log "FUNCTION: initializeScript failed: $message"
    log "Exiting script"
    exitScript -exitCode 1 -functionName "initializeScript"
}

# get new user info
log "Running FUNCTION: getNewUserInfo..."
try
{
    getNewUserInfo
    log "FUNCTION: getNewUserInfo completed successfully"
}
catch
{
    $message = $_.Exception.Message
    log "FUNCTION: getNewUserInfo failed: $message"
    log "Exiting script"
    exitScript -exitCode 1 -functionName "getNewUserInfo"
}

# disable newProfile task
log "Running FUNCTION: disableNewProfileTask..."
try
{
    disableNewProfileTask
    log "FUNCTION: disableNewProfileTask completed successfully"
}
catch
{
    $message = $_.Exception.Message
    log "FUNCTION: disableNewProfileTask failed: $message"
    log "Exiting script"
    exitScript -exitCode 1 -functionName "disableNewProfileTask"
}

# revoke logon provider
log "Running FUNCTION: revokeLogonProvider..."
try
{
    revokeLogonProvider
    log "FUNCTION: revokeLogonProvider completed successfully"
}
catch
{
    $message = $_.Exception.Message
    log "FUNCTION: revokeLogonProvider failed: $message"
    log "WARNING: Logon provider not revoked"
}

# set lock screen caption
log "Running FUNCTION: setLockScreenCaption..."
try
{
    setLockScreenCaption
    log "FUNCTION: setLockScreenCaption completed successfully"
}
catch
{
    $message = $_.Exception.Message
    log "FUNCTION: setLockScreenCaption failed: $message"
    log "WARNING: Lock screen caption not set"
}

# enable auto logon
log "Running FUNCTION: enableAutoLogon..."
try
{
    enableAutoLogon
    log "FUNCTION: enableAutoLogon completed successfully"
}
catch
{
    $message = $_.Exception.Message
    log "FUNCTION: enableAutoLogon failed: $message"
    log "WARNING: Auto logon not enabled"
}

# set finalBoot task
log "Running FUNCTION: setFinalBootTask..."
try
{
    setFinalBootTask
    log "FUNCTION: setFinalBootTask completed successfully"
}
catch
{
    $message = $_.Exception.Message
    log "FUNCTION: setFinalBootTask failed: $message"
    log "Exiting script"
    exitScript -exitCode 1 -functionName "setFinalBootTask"
}

Start-Sleep -Seconds 2
log "rebooting computer"

shutdown -r -t 00
Stop-Transcript
