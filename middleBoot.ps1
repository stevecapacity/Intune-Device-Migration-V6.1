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
Import-Module "$($PSScriptRoot)\migrateFunctions.psm1"

# Run getSettingsJSON function to get the settings.json file
log "Running FUNCTION: getSettingsJson..."
try
{
    getSettingsJSON
    log "FUNCTION: getSettingsJson completed successfully."
}
catch
{
    $message = $_.Exception.Message
    log "FUNCTION: getSettingsJson failed - $message."
    log "Existing script with non critial error.  Please review the log file and attempt to run the script again."
    exitScript -exitCode 1 -functionName "getSettingsJson"
}

# Run initializeScript to start transcript, create local path, and log file
log "Running FUNCTION: initializeScript..."
try
{
    initializeScript -logName "middleBoot"
    log "FUNCTION: initializeScript completed successfully."
}
catch
{
    $message = $_.Exception.Message
    log "FUNCTION: initializeScript failed - $message."
    log "Existing script with non critial error.  Please review the log file and attempt to run the script again."
    exitScript -exitCode 1 -functionName "initializeScript"
}

# Disable middleBoot scheduled task
log "Running FUNCTION: disableMiddleBootTask..."
try 
{
    stopTask -taskName "middleBoot"
    log "FUNCTION: disableMiddleBootTask completed successfully."    
}
catch
{
    $message = $_.Exception.Message
    log "FUNCTION: disableMiddleBootTask failed - $message."
    log "Existing script with non critial error.  Please review the log file and attempt to run the script again."
    exitScript -exitCode 1 -functionName "disableMiddleBootTask"
}

# Restore logon provider
log "Running FUNCTION: restoreLogonProvider..."
try
{
    setReg -path "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers\{60b78e88-ead8-445c-9cfd-0b87f74ea6cd}" -name "Disabled" -dValue 0
    log "FUNCTION: restoreLogonProvider completed successfully."
}
catch
{
    $message = $_.Exception.Message
    log "FUNCTION: restoreLogonProvider failed - $message."
    log "Existing script with non critial error.  Please review the log file and attempt to run the script again."
    exitScript -exitCode 1 -functionName "restoreLogonProvider"
}

# Set lock screen text
log "Running FUNCTION: setLockScreenCaption..."
try
{
    setReg -path "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -name "legalnoticecaption" -sValue "Join $($settings.targetTenant.tenantName)"
    setReg -path "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -name "legalnoticetext" -sValue "Sign in with your $($settings.targetTenant.tenantName) email address and password to start migrating your data."
    log "FUNCTION: setLockScreenCaption completed successfully."
}
catch
{
    $message = $_.Exception.Message
    log "FUNCTION: setLockScreenCaption failed - $message."
    log "Existing script with non critial error.  Please review the log file and attempt to run the script again."
    exitScript -exitCode 1 -functionName "setLockScreenCaption"
}

# disable auto logon policy
log "Running FUNCTION: setAutoLogonPolicy..."
try
{
    setReg -path "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -name "AutoAdminLogon" -dValue 0
    log "FUNCTION: setAutoLogonPolicy completed successfully."
}
catch
{
    $message = $_.Exception.Message
    log "FUNCTION: setAutoLogonPolicy failed - $message."
    log "Existing script with non critial error.  Please review the log file and attempt to run the script again."
    exitScript -exitCode 1 -functionName "setAutoLogonPolicy"
}

log "MiddleBoot.ps1 completed successfully. Exiting script."
log "Rebooting computer..."

shutdown -r -t 5

Stop-Transcript