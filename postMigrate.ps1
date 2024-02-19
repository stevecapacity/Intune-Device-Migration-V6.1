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
        [string]$logName = "postMigrate.log",
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

# disable post migrate task
function disablePostMigrateTask()
{
    Param(
        [string]$taskName = "postMigrate"
    )
    log "Disabling postMigrate task..."
    Disable-ScheduledTask -TaskName $taskName -ErrorAction Stop
    log "postMigrate task disabled"
}

# get device info
function getDeviceInfo()
{
    Param(
        [string]$hostname = $env:COMPUTERNAME,
        [string]$serialNumber = (Get-WmiObject -Class Win32_BIOS | Select-Object SerialNumber).SerialNumber
    )
    $global:deviceInfo = @{
        "hostname" = $hostname
        "serialNumber" = $serialNumber
    }
    foreach($key in $deviceInfo.Keys)
    {
        log "$($key): $($deviceInfo[$key])"
    }
}

# authenticate to MS Graph
function msGraphAuthenticate()
{
    Param(
        [string]$tenant = $settings.targetTenant.tenantName,
        [string]$clientId = $settings.targetTenant.clientId,
        [string]$clientSecret = $settings.targetTenant.clientSecret
    )
    $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
    $headers.Add("Content-Type", "application/x-www-form-urlencoded")

    $body = "grant_type=client_credentials&scope=https://graph.microsoft.com/.default"
    $body += -join ("&client_id=" , $clientId, "&client_secret=", $clientSecret)

    $response = Invoke-RestMethod "https://login.microsoftonline.com/$tenant/oauth2/v2.0/token" -Method 'POST' -Headers $headers -Body $body

    #Get Token form OAuth.
    $token = -join ("Bearer ", $response.access_token)

    #Reinstantiate headers.
    $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
    $headers.Add("Authorization", $token)
    $headers.Add("Content-Type", "application/json")
    log "MS Graph Authenticated"
    $global:headers = $headers
}

# get user graph info
function getGraphInfo()
{
    Param(
        [string]$regPath = $settings.regPath,
        [string]$regKey = "Registry::$regPath",
        [string]$serialNumber = $deviceInfo.serialNumber,
        [string]$intuneUri = "https://graph.microsoft.com/beta/deviceManagement/managedDevices",
        [string]$newUserSID = (Get-ItemPropertyValue -Path $regKey -Name "NewUserSID"),
        [string]$userUri = "https://graph.microsoft.com/beta/users",
        [string]$upn = (Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Microsoft\IdentityStore\Cache\$($newUserSID)\IdentityCache\$($newUserSID)" -Name "UserName")
    )
    log "Getting graph info..."
    $intuneObject = Invoke-RestMethod -Uri "$($intuneUri)?`$filter=contains(serialNumber,'$($serialNumber)')" -Headers $headers -Method Get
    if(($intuneObject.'@odata.count') -eq 1)
    {
        $global:intuneID = $intuneObject.value.id
        $global:aadDeviceID = $intuneObject.value.azureADDeviceId
        log "Intune Device ID: $intuneID, Azure AD Device ID: $aadDeviceID, User ID: $userID"
    }
    else
    {
        log "Intune object not found"
    }
    $userObject = Invoke-RestMethod -Uri "$userUri/$upn" -Headers $headers -Method Get
    if(![string]::IsNullOrEmpty($userObject.id))
    {
        $global:userID = $userObject.id
        log "User ID: $userID"
    }
    else
    {
        log "User object not found"
    }
}

# set primary user
function setPrimaryUser()
{
    Param(
        [string]$intuneID = $intuneID,
        [string]$userID = $userID,
        [string]$userUri = "https://graph.microsoft.com/beta/users/$userID",
        [string]$intuneDeviceRefUri = "https://graph.microsoft.com/beta/deviceManagement/managedDevices/$intuneID/users/`$ref"
    )
    log "Setting primary user..."
    $id = "@odata.id"
    $JSON = @{ $id="$userUri" } | ConvertTo-Json

    Invoke-RestMethod -Uri $intuneDeviceRefUri -Headers $headers -Method Post -Body $JSON
    log "Primary user for $intuneID set to $userID"
}

# update device group tag
function updateGroupTag()
{
    Param(
        [string]$regPath = $settings.regPath,
        [string]$regKey = "Registry::$regPath",
        [string]$groupTag = (Get-ItemPropertyValue -Path $regKey -Name "GroupTag"),
        [string]$aadDeviceID = $aadDeviceID,
        [string]$deviceUri = "https://graph.microsoft.com/beta/devices"
    )
    log "Updating device group tag..."
    if([string]::IsNullOrEmpty($groupTag))
    {
        log "Group tag not found- will not be used."
    }
    else
    {
        $aadObject = Invoke-RestMethod -Method Get -Uri "$($deviceUri)?`$filter=deviceId eq '$($aadDeviceId)'" -Headers $headers
        $physicalIds = $aadObject.value.physicalIds
        $deviceId = $aadObject.value.id
        $groupTag = "[OrderID]:$($groupTag)"
        $physicalIds += $groupTag

        $body = @{
            physicalIds = $physicalIds
        } | ConvertTo-Json
        Invoke-RestMethod -Uri "$deviceUri/$deviceId" -Method Patch -Headers $headers -Body $body
        log "Device group tag updated to $groupTag"      
    }
}

# migrate bitlocker function
function migrateBitlockerKey()
{
    Param(
        [string]$mountPoint = "C:",
        [PSCustomObject]$bitLockerVolume = (Get-BitLockerVolume -MountPoint $mountPoint),
        [string]$keyProtectorId = ($bitLockerVolume.KeyProtector | Where-Object {$_.KeyProtectorType -eq "RecoveryPassword"}).KeyProtectorId
    )
    log "Migrating Bitlocker key..."
    if($bitLockerVolume.KeyProtector.count -gt 0)
    {
        BackupToAAD-BitLockerKeyProtector -MountPoint $mountPoint -KeyProtectorId $keyProtectorId
        log "Bitlocker key migrated"
    }
    else
    {
        log "Bitlocker key not migrated"
    }
}

# decrypt drive
function decryptDrive()
{
    Param(
        [string]$mountPoint = "C:"
    )
    Disable-BitLocker -MountPoint $mountPoint
    log "Drive $mountPoint decrypted"
}

# manage bitlocker
function manageBitlocker()
{
    Param(
        [string]$bitlockerMethod = $settings.bitlockerMethod
    )
    log "Getting bitlocker action..."
    if($bitlockerMethod -eq "Migrate")
    {
        migrateBitlockerKey
    }
    elseif($bitlockerMethod -eq "Decrypt")
    {
        decryptDrive
    }
    else
    {
        log "Bitlocker method not set. Skipping..."
    }
}

# reset legal notice policy
function resetLockScreenCaption()
{
    Param(
        [string]$lockScreenRegPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
        [string]$lockScreenCaption = "legalnoticecaption",
        [string]$lockScreenText = "legalnoticetext"
    )
    log "Resetting lock screen caption..."
    Remove-ItemProperty -Path $lockScreenRegPath -Name $lockScreenCaption -ErrorAction SilentlyContinue
    Remove-ItemProperty -Path $lockScreenRegPath -Name $lockScreenText -ErrorAction SilentlyContinue
    log "Lock screen caption reset"
}

# remove migration user
function removeMigrationUser()
{
    Param(
        [string]$migrationUser = "MigrationInProgress"
    )
    Remove-LocalUser -Name $migrationUser -ErrorAction Stop
    log "Migration user removed"
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
    exitScript -exitCode 4 -functionName "getSettingsJSON"
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
    exitScript -exitCode 4 -functionName "initializeScript"
}

# disable post migrate task
log "Running FUNCTION: disablePostMigrateTask..."
try
{
    disablePostMigrateTask
    log "FUNCTION: disablePostMigrateTask completed successfully"
}
catch
{
    $message = $_.Exception.Message
    log "FUNCTION: disablePostMigrateTask failed: $message"
    log "Exiting script"
    exitScript -exitCode 4 -functionName "disablePostMigrateTask"
}

# get device info
log "Running FUNCTION: getDeviceInfo..."
try
{
    getDeviceInfo
    log "FUNCTION: getDeviceInfo completed successfully"
}
catch
{
    $message = $_.Exception.Message
    log "FUNCTION: getDeviceInfo failed: $message"
    log "Exiting script"
    exitScript -exitCode 4 -functionName "getDeviceInfo"
}

# authenticate to MS Graph
log "Running FUNCTION: msGraphAuthenticate..."
try
{
    msGraphAuthenticate
    log "FUNCTION: msGraphAuthenticate completed successfully"
}
catch
{
    $message = $_.Exception.Message
    log "FUNCTION: msGraphAuthenticate failed: $message"
    log "Exiting script"
    exitScript -exitCode 4 -functionName "msGraphAuthenticate"
}

# get graph info
log "Running FUNCTION: getGraphInfo..."
try
{
    getGraphInfo
    log "FUNCTION: getGraphInfo completed successfully"
}
catch
{
    $message = $_.Exception.Message
    log "FUNCTION: getGraphInfo failed: $message"
    log "Exiting script"
    exitScript -exitCode 4 -functionName "getGraphInfo"
}

# set primary user
log "Running FUNCTION: setPrimaryUser..."
try
{
    setPrimaryUser
    log "FUNCTION: setPrimaryUser completed successfully"
}
catch
{
    $message = $_.Exception.Message
    log "FUNCTION: setPrimaryUser failed: $message"
    log "WARNING: Primary user not set- try manually setting in Intune"
}

# update device group tag
log "Running FUNCTION: updateGroupTag..."
try
{
    updateGroupTag
    log "FUNCTION: updateGroupTag completed successfully"
}
catch
{
    $message = $_.Exception.Message
    log "FUNCTION: updateGroupTag failed: $message"
    log "WARNING: Device group tag not updated- try manually updating in Intune"
}

# manage bitlocker
log "Running FUNCTION: manageBitlocker..."
try
{
    manageBitlocker
    log "FUNCTION: manageBitlocker completed successfully"
}
catch
{
    $message = $_.Exception.Message
    log "FUNCTION: manageBitlocker failed: $message"
    log "WARNING: Bitlocker not managed- try setting policy manually in Intune"
}

# reset lock screen caption
log "Running FUNCTION: resetLockScreenCaption..."
try
{
    resetLockScreenCaption
    log "FUNCTION: resetLockScreenCaption completed successfully"
}
catch
{
    $message = $_.Exception.Message
    log "FUNCTION: resetLockScreenCaption failed: $message"
    log "WARNING: Lock screen caption not reset- try setting manually"
}

# remove migration user
log "Running FUNCTION: removeMigrationUser..."
try
{
    removeMigrationUser
    log "FUNCTION: removeMigrationUser completed successfully"
}
catch
{
    $message = $_.Exception.Message
    log "FUNCTION: removeMigrationUser failed: $message"
    log "WARNING: Migration user not removed- try removing manually"
}

# END SCRIPT


Stop-Transcript