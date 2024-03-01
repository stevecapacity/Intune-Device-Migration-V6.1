<# POSTMIGRATE.PS1
Synopsis
PostMigrate.ps1 is run after the migration reboots have completed and the user signs into the PC.
DESCRIPTION
This script is used to update the device group tag in Entra ID and set the primary user in Intune and migrate the bitlocker recovery key.
USE
.\postMigrate.ps1
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
    initializeScript -logName "postMigrate"
    log "FUNCTION: initializeScript completed successfully."
}
catch
{
    $message = $_.Exception.Message
    log "FUNCTION: initializeScript failed - $message."
    log "Existing script with non critial error.  Please review the log file and attempt to run the script again."
    exitScript -exitCode 4 -functionName "initializeScript"
}

# Run msGraphAuthenticate to auth to target tenant
log "Running FUNCTION: msGraphAuthenticate..."
try
{
    msGraphAuthenticate -tenant $settings.targetTenant.tenantName -clientId $settings.targetTenant.clientId -clientSecret $settings.targetTenant.clientSecret
    log "FUNCTION: msGraphAuthenticate completed successfully."
}
catch
{
    $message = $_.Exception.Message
    log "FUNCTION: msGraphAuthenticate failed - $message."
    log "Existing script with non critial error.  Please review the log file and attempt to run the script again."
    exitScript -exitCode 4 -functionName "msGraphAuthenticate"
}

# disable postMigrate scheduled task
log "Disabling postMigrate scheduled task..."
try
{
    stopTask -taskName "postMigrate"
    log "postMigrate scheduled task disabled."
}
catch
{
    $message = $_.Exception.Message
    log "Failed to disable postMigrate scheduled task - $message."
    log "Existing script with non critial error.  Please review the log file and attempt to run the script again."
    exitScript -exitCode 4 -functionName "disableScheduledTask"
}

# Run newDeviceObject function to construct the new device object
log "Running FUNCTION: newDeviceObject..."
try
{
    $pc = newDeviceObject
    log "FUNCTION: newDeviceObject completed successfully."
}
catch
{
    $message = $_.Exception.Message
    log "FUNCTION: newDeviceObject failed - $message."
    log "Existing script with non critial error.  Please review the log file and attempt to run the script again."
    exitScript -exitCode 4 -functionName "newDeviceObject"
}

# Write new PC object to registry
log "Writing new PC object to registry..."
foreach($x in $pc.Keys)
{
    $name = $x
    $value = $($pc[$x])
    try
    {
        log "Setting registry key: $name with value: $value"
        setRegObject -name $name -value $value -state "NEW"
        log "Registry key: $name set with value: $value"
    }
    catch
    {
        $message = $_.Exception.Message
        log "Failed to set registry key: $name with value: $value - $message"
        log "Existing script with non critial error.  Please review the log file and attempt to run the script again."
        exitScript -exitCode 4 -functionName "setRegObject"
    }
}

# Get user aadID from the registry
log "Getting user aadID from the registry..."
try
{
    $aadId = getReg -name "NEW_aadId" -path $settings.regPath
    log "User aadID: $aadId"
}
catch
{
    $message = $_.Exception.Message
    log "Failed to get user aadID from the registry - $message"
    log "Existing script with non critial error.  Please review the log file and attempt to run the script again."
    exitScript -exitCode 4 -functionName "getRegObject"
}

# Set primary user in Intune
log "Running FUNCTION: setPrimaryUser..."
try
{
    setPrimaryUser -aadId $aadId -intuneID $pc.intuneID
    log "FUNCTION: setPrimaryUser completed successfully."
}
catch
{
    $message = $_.Exception.Message
    log "FUNCTION: setPrimaryUser failed - $message."
    log "Existing script with non critial error.  Please review the log file and attempt to run the script again."
    exitScript -exitCode 4 -functionName "setPrimaryUser"
}

# check if group tag is being used
$useGroupTag = $false
$groupTag = getReg -name "OG_groupTag" -path $settings.regPath
if([string]::IsNullOrEmpty($groupTag))
{
    log "Group tag is not being used."
}
else
{
    $useGroupTag = $true
    log "Group tag is being used."
}

# if group tag is being used, set the device group tag in Entra ID
if($useGroupTag)
{
    log "Running FUNCTION: setDeviceGroupTag..."
    try
    {
        setGroupTag -groupTag $groupTag -azureAdDeviceId $pc.azureAdDeviceId
        log "FUNCTION: setDeviceGroupTag completed successfully."
    }
    catch
    {
        $message = $_.Exception.Message
        log "FUNCTION: setDeviceGroupTag failed - $message."
        log "Existing script with non critial error.  Please review the log file and attempt to run the script again."
        exitScript -exitCode 4 -functionName "setDeviceGroupTag"
    }
}
else 
{
    log "Group tag is not being used. Skipping setDeviceGroupTag function."
}

# if bitlockerMethod is MIGRATE, run migrateBitlocker function
if($settings.bitlockerMethod -eq "migrate")
{
    log "Running FUNCTION: migrateBitlocker..."
    try
    {
        migrateBitlocker
        log "FUNCTION: migrateBitlocker completed successfully."
    }
    catch
    {
        $message = $_.Exception.Message
        log "FUNCTION: migrateBitlocker failed - $message."
        log "Existing script with non critial error.  Please review the log file and attempt to run the script again."
        exitScript -exitCode 4 -functionName "migrateBitlocker"
    }
}
else 
{
    log "Bitlocker method is not MIGRATE. Skipping migrateBitlocker function."
}

# if bitlockerMethod is DECRYPT, run decryptDrive function
if($settings.bitlockerMethod -eq "decrypt")
{
    log "Running FUNCTION: decryptDrive..."
    try
    {
        decryptDrive
        log "FUNCTION: decryptDrive completed successfully."
    }
    catch
    {
        $message = $_.Exception.Message
        log "FUNCTION: decryptDrive failed - $message."
        log "Existing script with non critial error.  Please review the log file and attempt to run the script again."
        exitScript -exitCode 4 -functionName "decryptDrive"
    }
}
else 
{
    log "Bitlocker method is not DECRYPT. Skipping decryptDrive function."
}

# running FUNCTION: resetLockScreenCaption
log "Running FUNCTION: resetLockScreenCaption..."
try
{
    resetLockScreenCaption
    log "FUNCTION: resetLockScreenCaption completed successfully."
}
catch
{
    $message = $_.Exception.Message
    log "FUNCTION: resetLockScreenCaption failed - $message."
    log "Existing script with non critial error.  Please review the log file and attempt to run the script again."
    exitScript -exitCode 4 -functionName "resetLockScreenCaption"
}

# remove migration user
log "removing migration user..."
try
{
    Remove-LocalUser -Name "MigrationInProgress"
    log "Migration user removed."
}
catch
{
    $message = $_.Exception.Message
    log "Failed to remove migration user - $message"
    log "Existing script with non critial error.  Please review the log file and attempt to run the script again."
    exitScript -exitCode 4 -functionName "removeMigrationUser"
}

log "Post migration completed successfully. Exiting script."
Stop-Transcript

