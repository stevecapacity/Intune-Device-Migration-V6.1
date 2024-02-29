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
    initializeScript -logName "finalBoot"
    log "FUNCTION: initializeScript completed successfully."
}
catch
{
    $message = $_.Exception.Message
    log "FUNCTION: initializeScript failed - $message."
    log "Existing script with non critial error.  Please review the log file and attempt to run the script again."
    exitScript -exitCode 1 -functionName "initializeScript"
}

# disable finalBoot scheduled task
log "Disabling finalBoot scheduled task..."
try
{
    stopTask -taskName "finalBoot"
    log "finalBoot scheduled task disabled."
}
catch
{
    $message = $_.Exception.Message
    log "Failed to disable finalBoot scheduled task - $message."
    log "Existing script with non critial error.  Please review the log file and attempt to run the script again."
    exitScript -exitCode 1 -functionName "disableScheduledTask"
}

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

# retrieve the user and device info from registry
log "Running FUNCTION: getMigrateData..."
try
{
    getMigrateData
    log "FUNCTION: getMigrateData completed successfully."
}
catch
{
    $message = $_.Exception.Message
    log "FUNCTION: getMigrateData failed - $message."
    log "Existing script with non critial error.  Please review the log file and attempt to run the script again."
    exitScript -exitCode 1 -functionName "getMigrateData"
}

# remove AAD.BrokerPlugin from original user profile
log "Running FUNCTION: removeAADBrokerPlugin..."
try
{
    removeAADBrokerPlugin -originalProfilePath $migrateData.OG_profilePath
    log "FUNCTION: removeAADBrokerPlugin completed successfully."
}
catch
{
    $message = $_.Exception.Message
    log "FUNCTION: removeAADBrokerPlugin failed - $message."
    log "Existing script with non critial error.  Please review the log file and attempt to run the script again."
    exitScript -exitCode 1 -functionName "removeAADBrokerPlugin"
}

# delete new user profile
log "Running FUNCTION: deleteUserProfile..."
try
{
    deleteUserProfile -userSID $migrateData.NEW_SID
    log "FUNCTION: deleteUserProfile completed successfully."
}
catch
{
    $message = $_.Exception.Message
    log "FUNCTION: deleteUserProfile failed - $message."
    log "Existing script with non critial error.  Please review the log file and attempt to run the script again."
    exitScript -exitCode 1 -functionName "deleteUserProfile"
}

# change ownership of original user profile to new user
log "Running FUNCTION: changeProfileOwner..."
try
{
    changeProfileOwner -originalUserSID $migrateData.OG_SID -newUserSID $migrateData.NEW_SID
    log "FUNCTION: changeProfileOwner completed successfully."
}
catch
{
    $message = $_.Exception.Message
    log "FUNCTION: changeProfileOwner failed - $message."
    log "Existing script with non critial error.  Please review the log file and attempt to run the script again."
    exitScript -exitCode 1 -functionName "changeProfileOwner"
}




















######################################################
# Set lock screen text
log "Running FUNCTION: setLockScreenCaption..."
try
{
    setReg -path "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -name "legalnoticecaption" -sValue "Welcome to $($settings.targetTenant.tenantName)"
    setReg -path "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -name "legalnoticetext" -sValue "Your PC is now part of $($settings.targetTenant.tenantName).  Please sign in."
    log "FUNCTION: setLockScreenCaption completed successfully."
}
catch
{
    $message = $_.Exception.Message
    log "FUNCTION: setLockScreenCaption failed - $message."
    log "Existing script with non critial error.  Please review the log file and attempt to run the script again."
    exitScript -exitCode 1 -functionName "setLockScreenCaption"
}