# POSTMIGRATE.PS1
# This script is used to update the device group tag in Entra ID and set the primary user in Intune and migrate the bitlocker recovery key.
# It is executed by the 'postMigrate' scheduled task.
$ErrorActionPreference = "SilentlyContinue"

$settings = Get-Content -Path "$($PSScriptRoot)\settings.json" | ConvertFrom-Json

$localPath = $settings.localPath
if(!(Test-Path $localPath))
{
    mkdir $localPath
}

# Start Logging
$logPath = $settings.logPath
Start-Transcript -Path "$logPath\postMigrate.log" -Verbose

# Get registry values
$regPath = $settings.regPath
$key = "Registry::$regPath"


# Disable postMigrate task
Write-Host "Disabling postMigrate task..."
try 
{
    Disable-ScheduledTask -TaskName "postMigrate" -ErrorAction Stop
    Write-Host "postMigrate task disabled"
}
catch 
{
    $message = $_.Exception.Message
    Write-Host "postMigrate task not disabled: $message"
}

$hostname = $env:COMPUTERNAME
Write-Host "Hostname: $hostname"
# Update device group tag in Entra ID

# connect to destination tenant 
$clientId = $settings.targetTenant.clientId
$clientSecret = $settings.targetTenant.clientSecret
$tenant = $settings.targetTenant.tenantName

$headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
$headers.Add("Content-Type", "application/x-www-form-urlencoded")

$body = "grant_type=client_credentials&scope=https://graph.microsoft.com/.default"
$body += -join("&client_id=" , $clientId, "&client_secret=", $clientSecret)

$response = Invoke-RestMethod "https://login.microsoftonline.com/$tenant/oauth2/v2.0/token" -Method 'POST' -Headers $headers -Body $body

#Get Token form OAuth.
$token = -join("Bearer ", $response.access_token)

#Reinstantiate headers.
$headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
$headers.Add("Authorization", $token)
$headers.Add("Content-Type", "application/json")
Write-Host "MS Graph Authenticated"

# Retrieve Group tag from registry
[boolean]$useGroupTag = $false

Write-Host "Getting Group tag from registry..."
try 
{
    $groupTag = Get-ItemPropertyValue -Path $key -Name "GroupTag"
    $useGroupTag = $true
    Write-Host "Group tag: $groupTag"
}
catch 
{
    $message = $_.Exception.Message
    Write-Host "Group tag not found: $message"
}

# Get device ID
Write-Host "Getting device ID..."
$serialNumber = Get-WmiObject -Class Win32_BIOS | Select-Object -ExpandProperty SerialNumber
Write-Host "Serial number: $serialNumber"
try
{
    $intuneObject = Invoke-RestMethod -Uri "https://graph.microsoft.com/beta/deviceManagement/managedDevices?`$filter=contains(serialNumber,'$($serialNumber)')" -Headers $headers -Method Get
    $intuneDeviceId = $intuneObject.value.id
    Write-Host "Intune Device ID: $intuneDeviceId"
    if($intuneDeviceId -ne $null)
    {
        $azureADDeviceId = $intuneObject.value.azureADDeviceId
        Write-Host "Azure AD Device ID: $azureADDeviceId"
    }
    else
    {
        Write-Host "AAD Device ID not found"
    }
}
catch
{
    $message = $_.Exception.Message
    Write-Host "Intune device ID not found: $message"
}

# Update device group tag
if($useGroupTag -eq $true)
{
    Write-Host "Updating device group tag..."
    $physicalIds = $aadDeviceId.value.$physicalIds
    $groupTag = "[OrderID]:$($groupTag)"
    $physicalIds += $groupTag

    $body = @{
        physicalIds = $physicalIds
    } | ConvertTo-Json

    try
    {
        Invoke-RestMethod -Uri "https://graph.microsoft.com/beta/devices/$($aadDeviceId)" -Method Patch -Headers $headers -Body $body
        Write-Host "Successfully updated device group tag to $groupTag"
    }
    catch
    {
        $message = $_.Exception.Message
        Write-Host "Error updating device group tag: $message"
    }
}
else
{
    Write-Host "Group tag not found. Skipping update."
}


# Set primary user in Intune
$currentUser = Get-WmiObject -Class Win32_ComputerSystem | Select-Object -ExpandProperty UserName
Write-Host "Current user: $currentUser"
$user = $currentUser.Split("\")[1]
$sid = (New-Object System.Security.Principal.NTAccount($currentUser)).Translate([System.Security.Principal.SecurityIdentifier]).Value
Write-Host "Current User SID: $sid"

$upn = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Microsoft\IdentityStore\Cache\$($sid)\IdentityCache\$($sid)" -Name "UserName"

try
{
    $userObject = Invoke-RestMethod -Uri "https://graph.microsoft.com/beta/users/$($upn)" -Method Get -Headers $headers
    $userId = $userObject.id
    Write-Host "User ID: $userId"
}
catch
{
    $message = $_.Exception.Message
    Write-Host "User ID not found: $message"
}

$deviceUserUri = "https://graph.microsoft.com/beta/deviceManagement/managedDevices/$($intuneDeviceId)/users/`$ref"
$userUri = "https://graph.microsoft.com/beta/users/" + $userId

$id = "@odata.id"
$JSON = @{ $id="$userUri" } | ConvertTo-Json -Compress

Write-Host "Setting primary user $($user) on $($hostname)..."
try 
{
    Invoke-RestMethod -Uri $deviceUserUri -Method Post -Headers $headers -Body $JSON -ContentType "application/json"
    Write-Host "Successfully set primary user to $($user)"
}
catch 
{
    $message = $_.Exception.Message
    Write-Host "Error setting primary user: $message"    
}

# Migrate Bitlocker recovery key or decrypt volume
$bitlockerMethod = $settings.bitlockerMethod
Write-Host "Bitlocker Method: $bitlockerMethod"
if($bitlockerMethod -eq "Migrate")
{
    $BLV = Get-BitLockerVolume -MountPoint "C:"
    Write-Host "Retrieving BitLocker Volume $($BLV)"

    Write-Host "Backing up BitLocker Key to AAD..."
    try 
    {
        BackupToAAD-BitLockerKeyProtector -MountPoint "C:" -KeyProtectorId $BLV.KeyProtector[1].KeyProtectorId
        Start-Sleep -Seconds 2
        Write-Host "Successfully backed up BitLocker Key to $($tenant) AAD"    
    }
    catch 
    {
        $message = $_
        Write-Host "Error backing up BitLocker key to $($tenant) AAD: $message"
    }
}
elseif($bitlockerMethod -eq "Decrypt")
{
    Write-Host "Decrypting volume..."
    try 
    {
        Disable-BitLocker -MountPoint "C:" -ErrorAction Stop
        Write-Host "Successfully decrypted volume"
    }
    catch 
    {
        $message = $_.Exception.Message
        Write-Host "Error decrypting volume: $message"
    }
}
else
{
    Write-Host "Bitlocker method not set. Skipping..."
}

Stop-Transcript
