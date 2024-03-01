<# AUTOPILOTREGISTRATION.PS1
Synopsis
AutopilotRegistration.ps1 is the last script in the device migration process.
DESCRIPTION
This script is used to register the PC in the destination tenant Autopilot environment.  Will use a group tag if available.
USE
.\AutopilotRegistration.ps1
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
    initializeScript -logName "AutopilotRegistration"
    log "FUNCTION: initializeScript completed successfully."
}
catch
{
    $message = $_.Exception.Message
    log "FUNCTION: initializeScript failed - $message."
    log "Existing script with non critial error.  Please review the log file and attempt to run the script again."
    exitScript -exitCode 4 -functionName "initializeScript"
}

# disable AutopilotRegistration scheduled task
log "Disabling AutopilotRegistration scheduled task..."
try
{
    stopTask -taskName "AutopilotRegistration"
    log "AutopilotRegistration scheduled task disabled."
}
catch
{
    $message = $_.Exception.Message
    log "Failed to disable AutopilotRegistration scheduled task - $message."
    log "Existing script with non critial error.  Please review the log file and attempt to run the script again."
    exitScript -exitCode 4 -functionName "disableScheduledTask"
}

# Run FUNCTION: installModules for Autopilot
log "Running FUNCTION: installModules..."
try
{
    installModules -modules "WindowsAutoPilotIntune","Microsoft.Graph.Intune"
    log "FUNCTION: installModules completed successfully."
}
catch
{
    $message = $_.Exception.Message
    log "FUNCTION: installModules failed - $message."
    log "Existing script with non critial error.  Please review the log file and attempt to run the script again."
    exitScript -exitCode 4 -functionName "installModules"
}

# authenticate ms graph for Autopilot in target tenant
Log "Running FUNCTION: autopilotAuthenticate..."
try
{
    autopilotAuthenticate -tenantName $settings.targetTenant.tenantName -clientId $settings.targetTenant.clientId -clientSecret $settings.targetTenant.clientSecret -tenantId $settings.targetTenant.tenantId
    log "FUNCTION: autopilotAuthenticate completed successfully."
}
catch
{
    $message = $_.Exception.Message
    log "FUNCTION: autopilotAuthenticate failed - $message."
    log "Existing script with non critial error.  Please review the log file and attempt to run the script again."
    exitScript -exitCode 4 -functionName "autopilotAuthenticate"
}

# Register device in Autopilot
log "Running FUNCTION: registerDevice..."
try
{
    registerDevice -regPath $settings.regPath
    log "FUNCTION: registerDevice completed successfully."
}
catch
{
    $message = $_.Exception.Message
    log "FUNCTION: registerDevice failed - $message."
    log "Existing script with non critial error.  Please review the log file and attempt to run the script again."
    exitScript -exitCode 4 -functionName "registerDevice"
}

log "AutopilotRegistration.ps1 completed successfully."

Stop-Transcript