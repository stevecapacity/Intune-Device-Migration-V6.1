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
    exitScript -exitCode 4 -functionName "getSettingsJson"
}

# Run initializeScript to start transcript, create local path, and log file
log "Running FUNCTION: initializeScript..."
try
{
    initializeScript -logName "newProfile"
    log "FUNCTION: initializeScript completed successfully."
}
catch
{
    $message = $_.Exception.Message
    log "FUNCTION: initializeScript failed - $message."
    log "Existing script with non critial error.  Please review the log file and attempt to run the script again."
    exitScript -exitCode 4 -functionName "initializeScript"
}

# Run msGraphAuthenticate to authenticate to the Microsoft Graph API in destination tenant
log "Running FUNCTION: msGraphAuthenticate..."
try
{
    msGraphAuthenticate -tenant $settings.targetTenant.tenantName -clientId $settings.targetTenant.clientID -clientSecret $settings.targetTenant.clientSecret
    log "FUNCTION: msGraphAuthenticate completed successfully."
}
catch
{
    $message = $_.Exception.Message
    log "FUNCTION: msGraphAuthenticate failed - $message."
    log "Existing script with non critial error.  Please review the log file and attempt to run the script again."
    exitScript -exitCode 4 -functionName "msGraphAuthenticate"
}


# Disable newProfile scheduled task
log "Running FUNCTION: disableNewProfileTask..."
try 
{
    stopTask -taskName "newProfile"
    log "FUNCTION: disableNewProfileTask completed successfully."    
}
catch
{
    $message = $_.Exception.Message
    log "FUNCTION: disableNewProfileTask failed - $message."
    log "Existing script with non critial error.  Please review the log file and attempt to run the script again."
    exitScript -exitCode 4 -functionName "disableNewProfileTask"
}

# Construct new user object
# Run newUserObject to construct the current user object
log "Running FUNCTION: newUserObject..."
try
{
    $newUser = newUserObject -domainJoin "NO" -aadJoin "YES"
    log "FUNCTION: newUserObject completed successfully"
}
catch
{
    $message = $_.Exception.Message
    log "FUNCTION: newUserObject failed - $message."
    log "Existing script with non critial error.  Please review the log file and attempt to run the script again."
    exitScript -exitCode 4 -functionName "newUserObject"
}

# Write new user object to registry
log "Writing new user object to registry..."
foreach($x in $newUser.Keys)
{
    $name = $x
    $value = $($newUser[$x])
    try
    {
        log "Writing $name to the registry with value $value..."
        setRegObject -name $name -value $value -state "NEW"
        log "$name written to the registry with value $value."
    }
    catch
    {
        $message = $_.Exception.Message
        log "Writing $name to the registry failed - $message."
        log "Existing script with non critial error.  Please review the log file and attempt to run the script again."
        exitScript -exitCode 4 -functionName "setRegObject"
    }
}

# set finalBoot task
log "Running FUNCTION: setTask for finalBoot task..."
try
{
    setTask -taskName "finalBoot"
    log "FUNCTION: setTask for finalBoot task completed successfully."
}
catch
{
    $message = $_.Exception.Message
    log "FUNCTION: setTask for finalBoot tasks failed - $message."
    log "Existing script with non critial error.  Please review the log file and attempt to run the script again."
    exitScript -exitCode 4 -functionName "setTask"
}

# Revoke logon provider
log "Revoking logon provider..."
try 
{
    setReg -path "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers\{60b78e88-ead8-445c-9cfd-0b87f74ea6cd}" -name "Disabled" -dValue 1
    log "Logon provider revoked."    
}
catch 
{
    $message = $_.Exception.Message
    log "Failed to revoke logon provider - $message."
    log "Existing script with non critial error.  Please review the log file and attempt to run the script again."
    exitScript -exitCode 4 -functionName "setReg"
}

# enable auto logon
log "Enabling auto logon..."
try
{
    setReg -path "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -name "AutoAdminLogon" -dValue 1
    log "FUNCTION: setAutoLogonPolicy completed successfully."
}
catch
{
    $message = $_.Exception.Message
    log "FUNCTION: setAutoLogonPolicy failed - $message."
    log "Existing script with non critial error.  Please review the log file and attempt to run the script again."
    exitScript -exitCode 4 -functionName "setAutoLogonPolicy"
}


# Set lock screen text
log "Running FUNCTION: setLockScreenCaption..."
try
{
    setReg -path "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -name "legalnoticecaption" -sValue "Almost there..."
    setReg -path "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -name "legalnoticetext" -sValue "Your PC will restart one more time to join the $($settings.targetTenant.tenantName) environment."
    log "FUNCTION: setLockScreenCaption completed successfully."
}
catch
{
    $message = $_.Exception.Message
    log "FUNCTION: setLockScreenCaption failed - $message."
    log "Existing script with non critial error.  Please review the log file and attempt to run the script again."
    exitScript -exitCode 1 -functionName "setLockScreenCaption"
}

log "New profile script completed successfully."
log "rebooting..."

stop-transcript
shutdown -r -t 00