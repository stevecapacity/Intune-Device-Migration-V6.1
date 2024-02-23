<# MIDDLEBOOT.PS1
Synopsis
Middleboot.ps1 is the second script in the migration process.
DESCRIPTION
This script is used to automatically restart the computer immediately after the installation of the startMigrate.ps1 script and change the lock screen text.  The password logon credential provider is also enabled to allow the user to log in with their new credentials.
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
        [string]$logName = "middleBoot.log",
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

# set legal notice
function setLockScreenCaption()
{
    Param(
        [string]$targetTenantName = $settings.targetTenant.tenantName,
        [string]$legalPath = "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
        [string]$legalCaptionName = "legalnoticecaption",
        [string]$legalCaptionValue = "Join $($targetTenantName)",
        [string]$legalTextName = "legalnoticetext",
        [string]$text = "Sign in with your new $($targetTenantName) email address and password to start migrating your data."
    )
    log "Setting lock screen caption..."
    reg.exe add $legalPath /v $legalCaptionName /t REG_SZ /d $legalCaptionValue /f | Out-Host
    reg.exe add $legalPath /v $legalTextName /t REG_SZ /d $text /f | Out-Host
    log "Lock screen caption set"
}

# disable auto logon
function disableAutoLogon()
{
    Param(
        [string]$autoLogonPath = "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
        [string]$autoLogonName = "AutoAdminLogon",
        [string]$autoLogonValue = 0
    )
    log "Disabling auto logon..."
    reg.exe add $autoLogonPath /v $autoLogonName /t REG_SZ /d $autoLogonValue /f | Out-Host
    log "Auto logon disabled"
}

# disable middleBoot task
function disableTask()
{
    Param(
        [string]$taskName = "middleBoot"
    )
    log "Disabling middleBoot task..."
    Disable-ScheduledTask -TaskName $taskName
    log "middleBoot task disabled"    
}

# END SCRIPT FUNCTIONS

# START SCRIPT

# run get settings function
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

# run initialize script function
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

# run restore logon credential provider function
log "Running FUNCTION: restoreLogonProvider..."
try
{
    restoreLogonProvider
    log "FUNCTION: restoreLogonProvider completed successfully"
}
catch
{
    $message = $_.Exception.Message
    log "FUNCTION: restoreLogonProvider failed: $message"
    log "Exiting script"
    exitScript -exitCode 1 -functionName "restoreLogonProvider"
}

# run set lock screen caption function
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

# run disable auto logon function
log "Running FUNCTION: disableAutoLogon..."
try
{
    disableAutoLogon
    log "FUNCTION: disableAutoLogon completed successfully"
}
catch
{
    $message = $_.Exception.Message
    log "FUNCTION: disableAutoLogon failed: $message"
    log "Exiting script"
    exitScript -exitCode 1 -functionName "disableAutoLogon"
}

# run disable task function
log "Running FUNCTION: disableTask..."
try
{
    disableTask
    log "FUNCTION: disableTask completed successfully"
}
catch
{
    $message = $_.Exception.Message
    log "FUNCTION: disableTask failed: $message"
    log "Exiting script"
    exitScript -exitCode 1 -functionName "disableTask"
}

# END SCRIPT
log "Restarting computer..."
shutdown -r -t 5

Stop-Transcript