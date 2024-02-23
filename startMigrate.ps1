<# INTUNE TENANT-TO-TENANT DEVICE MIGRATION V6.0
Synopsis
This solution will automate the migration of devices from one Intune tenant to another Intune tenant.  Devices can be hybrid AD Joined or Azure AD Joined.
DESCRIPTION
Intune Tenant-to-Tenant Migration Solution leverages the Microsoft Graph API to automate the migration of devices from one Intune tenant to another Intune tenant.  Devices can be hybrid AD Joined or Azure AD Joined.  The solution will also migrate the device's primary user profile data and files.  The solution leverages Windows Configuration Designer to create a provisioning package containing a Bulk Primary Refresh Token (BPRT).  Tasks are set to run after the user signs into the PC with destination tenant credentials to update Intune attributes including primary user, Entra ID device group tag, and device category.  In the last step, the device is registered to the destination tenant Autopilot service.  
USE
This script is packaged along with the other files into an intunewin file.  The intunewin file is then uploaded to Intune and assigned to a group of devices.  The script is then run on the device to start the migration process.

NOTES
When deploying with Microsoft Intune, the install command must be "%WinDir%\Sysnative\WindowsPowerShell\v1.0\powershell.exe -ExecutionPolicy Bypass -File startMigrate.ps1" to ensure the script runs in 64-bit mode.
.OWNER
Steve Weiner
.CONTRIBUTORS
Logan Lautt
Jesse Weimer
#>
$ErrorActionPreference = "SilentlyContinue"
Import-Module "$($PSScriptRoot)\migrateFunctions.psm1"

# Run getSettingsJson to get the settings.json file
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
    initializeScript -installTag:$true -logName "startMigrate"
    log "FUNCTION: initializeScript completed successfully."
}
catch
{
    $message = $_.Exception.Message
    log "FUNCTION: initializeScript failed - $message."
    log "Existing script with non critial error.  Please review the log file and attempt to run the script again."
    exitScript -exitCode 4 -functionName "initializeScript"
}

# Run copyPackageFiles to copy the files from the intunewin package to the local path
log "Running FUNCTION: copyPackageFiles..."
try
{
    copyPackageFiles -Destination $localPath
    log "FUNCTION: copyPackageFiles completed successfully."
}
catch
{
    $message = $_.Exception.Message
    log "FUNCTION: copyPackageFiles failed - $message."
    log "Existing script with non critial error.  Please review the log file and attempt to run the script again."
    exitScript -exitCode 4 -functionName "copyPackageFiles"
}

# Run msGraphAuthenticate to authenticate to the Microsoft Graph API in source tenant
log "Running FUNCTION: msGraphAuthenticate..."
try
{
    msGraphAuthenticate -tenant $settings.sourceTenant.tenantName -clientId $settings.sourceTenant.clientID -clientSecret $settings.sourceTenant.clientSecret
    log "FUNCTION: msGraphAuthenticate completed successfully."
}
catch
{
    $message = $_.Exception.Message
    log "FUNCTION: msGraphAuthenticate failed - $message."
    log "Existing script with non critial error.  Please review the log file and attempt to run the script again."
    exitScript -exitCode 4 -functionName "msGraphAuthenticate"
}

# Run newDeviceObject to construct the current device object
log "Running FUNCTION: newDeviceObject..."
try
{
    $pc = newDeviceObject
    log "FUNCTION: newDeviceObject completed successfully"
}
catch
{
    $message = $_.Exception.Message
    log "FUNCTION: newDeviceObject failed - $message."
    log "Existing script with non critial error.  Please review the log file and attempt to run the script again."
    exitScript -exitCode 4 -functionName "newDeviceObject"
}

# Run newUserObject to construct the current user object
log "Running FUNCTION: newUserObject..."
try
{
    $user = newUserObject -domainJoin $pc.domainJoined -aadJoin $pc.azureAdJoined
    log "FUNCTION: newUserObject completed successfully"
}
catch
{
    $message = $_.Exception.Message
    log "FUNCTION: newUserObject failed - $message."
    log "Existing script with non critial error.  Please review the log file and attempt to run the script again."
    exitScript -exitCode 4 -functionName "newUserObject"
}

# Set AccountConnection policy to allow the user to sign in with the destination tenant account
log "Setting AccountConnection policy to allow the user to sign in with the destination tenant account..."
try
{
    setReg -path "HKLM\SOFTWARE\Microsoft\PolicyManager\current\device\Accounts" -name "AllowMicrosoftAccountConnection" -dValue 1
    log "AccountConnection policy set to allow the user to sign in with the destination tenant account."
}
catch
{
    $message = $_.Exception.Message
    log "Failed to set AccountConnection policy - $message."
    log "Existing script with non critial error.  Please review the log file and attempt to run the script again."
    exitScript -exitCode 4 -functionName "setReg"
}

# Set DontDisplayLastUserName policy for migration
log "Setting DontDisplayLastUserName policy for migration..."
try
{
    setReg -path "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -name "DontDisplayLastUserName" -dValue 1
    log "DontDisplayLastUserName policy set for migration."
}
catch
{
    $message = $_.Exception.Message
    log "Failed to set DontDisplayLastUserName policy - $message."
    log "Existing script with non critial error.  Please review the log file and attempt to run the script again."
    exitScript -exitCode 4 -functionName "setReg"
}

# Write OG PC properties to the registry
log "Writing OG PC properties to the registry..."
foreach($x in $pc.Keys)
{
    $name = $x
    $value = $($pc[$x])
    try
    {
        log "Writing $name to the registry with value $value..."
        setRegObject -name $name -value $value -state "OG"
        log "$name written to registry with value $value."
    }
    catch
    {
        $message = $_.Exception.Message
        log "Failed to write $name to the registry - $message."
        log "Existing script with non critial error.  Please review the log file and attempt to run the script again."
        exitScript -exitCode 4 -functionName "setRegObject"
    }
}

# Write OG User properties to the registry
log "Writing OG User properties to the registry..."
foreach($x in $user.Keys)
{
    $name = $x
    $value = $($user[$x])
    try
    {
        log "Writing $name to the registry with value $value..."
        setRegObject -name $name -value $value -state "OG"
        log "$name written to registry with value $value."
    }
    catch
    {
        $message = $_.Exception.Message
        log "Failed to write $name to the registry - $message."
        log "Existing script with non critial error.  Please review the log file and attempt to run the script again."
        exitScript -exitCode 4 -functionName "setRegObject"
    }
}

# Run removeMDMCertificate to remove the MDM certificate
log "Running FUNCTION: removeMDMCertificate..."
try
{
    removeMDMCertificate
    log "FUNCTION: removeMDMCertificate completed successfully."
}
catch
{
    $message = $_.Exception.Message
    log "FUNCTION: removeMDMCertificate failed - $message."
    log "Existing script with non critial error.  Please review the log file and attempt to run the script again."
    exitScript -exitCode 4 -functionName "removeMDMCertificate"
}

# Run removeMDMEnrollment to remove the MDM enrollment
log "Running FUNCTION: removeMDMEnrollment..."
try
{
    removeMDMEnrollment
    log "FUNCTION: removeMDMEnrollment completed successfully."
}
catch
{
    $message = $_.Exception.Message
    log "FUNCTION: removeMDMEnrollment failed - $message."
    log "Existing script with non critial error.  Please review the log file and attempt to run the script again."
    exitScript -exitCode 4 -functionName "removeMDMEnrollment"
}

# set post migration tasks
log "Running FUNCTION: setTask for post migration tasks..."
try
{
    setTask -taskName "middleBoot","newProfile"
    log "FUNCTION: setTask for post migration tasks completed successfully."
}
catch
{
    $message = $_.Exception.Message
    log "FUNCTION: setTask for post migration tasks failed - $message."
    log "Existing script with non critial error.  Please review the log file and attempt to run the script again."
    exitScript -exitCode 4 -functionName "setTask"
}

# If the device is Azure AD Joined, run leaveAzureAdJoin function
log "Checking if the device is Azure AD Joined..."
if($pc.azureAdJoined -eq "YES")
{
    log "Device is Azure AD Joined.  Running FUNCTION: leaveAzureAdJoin..."
    try
    {
        leaveAzureAdJoin
        log "FUNCTION: leaveAzureAdJoin completed successfully."
    }
    catch
    {
        $message = $_.Exception.Message
        log "FUNCTION: leaveAzureAdJoin failed - $message."
        log "Existing script with non critial error.  Please review the log file and attempt to run the script again."
        exitScript -exitCode 4 -functionName "leaveAzureAdJoin"
    }
}
else
{
    log "Device is not Azure AD Joined."
}

# If the device is domain joined, run leaveDomainJoin function
log "Checking if the device is domain joined..."
if($pc.domainJoined -eq "YES")
{
    log "Device is domain joined.  Running FUNCTION: leaveDomainJoin..."
    try
    {
        leaveDomainJoin -unjoinAccount "Administrator" -hostname $pc.hostname
        log "FUNCTION: leaveDomainJoin completed successfully."
    }
    catch
    {
        $message = $_.Exception.Message
        log "FUNCTION: leaveDomainJoin failed - $message."
        log "Existing script with non critial error.  Please review the log file and attempt to run the script again."
        exitScript -exitCode 4 -functionName "leaveDomainJoin"
    }
}
else
{
    log "Device is not domain joined."
}

# Run installPPKGPackage to install provisioning package
log "Running FUNCTION: installPPKGPackage..."
try
{
    installPPKGPackage
    log "FUNCTION: installPPKGPackage completed successfully."
}
catch
{
    $message = $_.Exception.Message
    log "FUNCTION: installPPKGPackage failed - $message."
    log "Existing script with non critial error.  Please review the log file and attempt to run the script again."
    exitScript -exitCode 4 -functionName "installPPKGPackage"
}

# Run deleteGraphObjects to remove Intune and AutoPilot objects from source tenant if device is registered
log "Running FUNCTION: deleteGraphObjects..."
try
{
    deleteGraphObjects -intuneId $pc.intuneId -autopilotId $pc.autopilotId
    log "FUNCTION: deleteGraphObjects completed successfully."
}
catch
{
    $message = $_.Exception.Message
    log "FUNCTION: deleteGraphObjects failed - $message."
    log "Existing script with non critial error.  Please review the log file and attempt to run the script again."
    exitScript -exitCode 4 -functionName "deleteGraphObjects"
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

# Set auto logon policy
log "Running FUNCTION: setAutoLogon..."
try
{
    setAutoLogon -username $user.username -password $user.password
    log "FUNCTION: setAutoLogon completed successfully."
}
catch
{
    $message = $_.Exception.Message
    log "FUNCTION: setAutoLogon failed - $message."
    log "Existing script with non critial error.  Please review the log file and attempt to run the script again."
    exitScript -exitCode 4 -functionName "setAutoLogon"
}

# set lock screen caption
log "Settings lock screen caption..."
try
{
    regSet -path "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -name "legalnoticecaption" -sValue "Migration in progress..."
    regSet -path "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -name "legalnoticetext" -sValue "Your PC is being migrated to $($settings.targetTenant.tenantName) and will reboot in 30 seconds.  Please do not turn off your PC."
    log "Lock screen caption set."
}
catch
{
    $message = $_.Exception.Message
    log "Failed to set lock screen caption - $message."
    log "Existing script with non critial error.  Please review the log file and attempt to run the script again."
    exitScript -exitCode 4 -functionName "setLockScreenCaption"
}

log "startMigrate script completed successfully"
log "Rebooting device..."
shutdown -r -t 30

Stop-Transcript
