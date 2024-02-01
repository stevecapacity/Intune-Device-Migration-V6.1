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
Start-Transcript -Path "$localPath\postMigrate.log" -Verbose

# Create log object 
$logObject = @()

# Get registry values
$regPath = $settings.regPath
$key = "Registry::$regPath"

# Check for log analytics
$LogAnalytics = $settings.LogAnalytics

# Disable postMigrate task
Write-Host "Disabling postMigrate task..."
try 
{
    Disable-ScheduledTask -TaskName "postMigrate" -ErrorAction Stop
    Write-Host "postMigrate task disabled"
    $logObject += @{Name="postMigrate Task";Status="Disabled"}     
}
catch 
{
    $message = $_.Exception.Message
    Write-Host "postMigrate task not disabled: $message"
    $logObject += @{Name="postMigrate Task";Status="Not Disabled";Message=$message}
}

$hostname = $env:COMPUTERNAME
Write-Host "Hostname: $hostname"
$logObject += @{Name="Hostname";Value=$hostname}
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
    $logObject += @{Name="Group Tag";Value=$groupTag}   
}
catch 
{
    $message = $_.Exception.Message
    Write-Host "Group tag not found: $message"
    $logObject += @{Name="Group Tag";Value="Not Found: $message"}
}

# Get device ID
Write-Host "Getting device ID..."
$serialNumber = Get-WmiObject -Class Win32_BIOS | Select-Object -ExpandProperty SerialNumber
Write-Host "Serial number: $serialNumber"
$logObject += @{Name="Serial Number";Value=$serialNumber}

try
{
    $intuneObject = Invoke-RestMethod -Uri "https://graph.microsoft.com/beta/deviceManagement/managedDevices?`$filter=contains(serialNumber,'$($serialNumber)')" -Headers $headers -Method Get
    $intuneDeviceId = $intuneObject.value.id
    Write-Host "Intune Device ID: $intuneDeviceId"
    $logObject += @{Name="Intune Device ID";Value=$intuneDeviceId}
    if($intuneDeviceId -ne $null)
    {
        $azureADDeviceId = $intuneObject.value.azureADDeviceId
        Write-Host "Azure AD Device ID: $azureADDeviceId"
        $logObject += @{Name="Azure AD Device ID";Value=$azureADDeviceId}
    }
    else
    {
        Write-Host "AAD Device ID not found"
        $logObject += @{Name="AAD Device ID";Value="Not Found"}
    }
}
catch
{
    $message = $_.Exception.Message
    Write-Host "Intune device ID not found: $message"
    $logObject += @{Name="Intune Device ID";Value="Not Found: $message"}
}

# Update device group tag
if($useGroupTag -eq $true)
{
    Write-Host "Updating device group tag..."
    $logObject += @{Name="Use Group Tag:";Value=$useGroupTag}
    $physicalIds = $aadDeviceId.value.$physicalIds
    $groupTag = "[Order]:$($groupTag)"
    $physicalIds += $groupTag

    $body = @{
        physicalIds = $physicalIds
    } | ConvertTo-Json

    try
    {
        Invoke-RestMethod -Uri "https://graph.microsoft.com/beta/devices/$($aadDeviceId)" -Method Patch -Headers $headers -Body $body
        Write-Host "Successfully updated device group tag to $groupTag"
        $logObject += @{Name="Update Group Tag:";Value="Success"}
    }
    catch
    {
        $message = $_.Exception.Message
        Write-Host "Error updating device group tag: $message"
        $logObject += @{Name="Update Group Tag:";Value="Error: $message"}
    }
}
else
{
    Write-Host "Group tag not found. Skipping update."
    $logObject += @{Name="Use Group Tag:";Value=$useGroupTag}
}


# Set primary user in Intune
$currentUser = Get-WmiObject -Class Win32_ComputerSystem | Select-Object -ExpandProperty UserName
Write-Host "Current user: $currentUser"
$logObject += @{Name="Current User";Value=$currentUser}
$user = $currentUser.Split("\")[1]
$sid = (New-Object System.Security.Principal.NTAccount($currentUser)).Translate([System.Security.Principal.SecurityIdentifier]).Value
Write-Host "Current User SID: $sid"
$logObject += @{Name="Current User SID";Value=$sid}

$upn = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Microsoft\IdentityStore\Cache\$($sid)\IdentityCache\$($sid)" -Name "UserName"

try
{
    $userObject = Invoke-RestMethod -Uri "https://graph.microsoft.com/beta/users/$($upn)" -Method Get -Headers $headers
    $userId = $userObject.id
    Write-Host "User ID: $userId"
    $logObject += @{Name="User ID";Value=$userId}
}
catch
{
    $message = $_.Exception.Message
    Write-Host "User ID not found: $message"
    $logObject += @{Name="User ID";Value="Not Found: $message"}
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
    $logObject += @{Name="Set Primary User";Value=$user}
}
catch 
{
    $message = $_.Exception.Message
    Write-Host "Error setting primary user: $message"    
    $logObject += @{Name="Set Primary User";Value="Error: $message"}
}

# Migrate Bitlocker recovery key or decrypt volume
$bitlockerMethod = $settings.bitlockerMethod
Write-Host "Bitlocker Method: $bitlockerMethod"
$logObject += @{Name="Bitlocker Method";Value=$bitlockerMethod}
if($bitlockerMethod -eq "Migrate")
{
    $BLV = Get-BitLockerVolume -MountPoint "C:"
    Write-Host "Retrieving BitLocker Volume $($BLV)"
    $logObject += @{Name="Bitlocker Volume";Value=$BLV}
    
    Write-Host "Backing up BitLocker Key to AAD..."
    try 
    {
        BackupToAAD-BitLockerKeyProtector -MountPoint "C:" -KeyProtectorId $BLV.KeyProtector[1].KeyProtectorId
        Start-Sleep -Seconds 2
        Write-Host "Successfully backed up BitLocker Key to $($tenant) AAD"    
        $logObject += @{Name="Backup Bitlocker Key";Value="Success"}
    }
    catch 
    {
        $message = $_
        Write-Host "Error backing up BitLocker key to $($tenant) AAD: $message"
        $logObject += @{Name="Backup Bitlocker Key";Value="Error: $message"}
    }
}
elseif($bitlockerMethod -eq "Decrypt")
{
    Write-Host "Decrypting volume..."
    $logObject += @{Name="Decrypt Volume";Value="In Progress"}
    try 
    {
        Disable-BitLocker -MountPoint "C:" -ErrorAction Stop
        Write-Host "Successfully decrypted volume"
        $logObject += @{Name="Decrypt Volume";Value="Success"}
    }
    catch 
    {
        $message = $_.Exception.Message
        Write-Host "Error decrypting volume: $message"
        $logObject += @{Name="Decrypt Volume";Value="Error: $message"}
    }
}
else
{
    Write-Host "Bitlocker method not set. Skipping..."
    $logObject += @{Name="Bitlocker Method";Value="Not Set"}
}

Stop-Transcript

# Post to log analytics if enabled
if($LogAnalytics)
{
    $logInfo = New-Object System.Object
    $CustomerId = $settings.workspaceID  
    $SharedKey = $settings.primaryKey
    $LogType = "startMigrate"
    $TimeStampField = ""
    foreach($object in $logObject)
    {
        $logInfo | Add-Member -MemberType NoteProperty -Name $object.Name -Value $object.Value
    }
    $json = $logInfo | ConvertTo-Json

    Function Build-Signature ($customerId, $sharedKey, $date, $contentLength, $method, $contentType, $resource)
    {
        $xHeaders = "x-ms-date:" + $date
        $stringToHash = $method + "`n" + $contentLength + "`n" + $contentType + "`n" + $xHeaders + "`n" + $resource

        $bytesToHash = [Text.Encoding]::UTF8.GetBytes($stringToHash)
        $keyBytes = [Convert]::FromBase64String($sharedKey)

        $sha256 = New-Object System.Security.Cryptography.HMACSHA256
        $sha256.Key = $keyBytes
        $calculatedHash = $sha256.ComputeHash($bytesToHash)
        $encodedHash = [Convert]::ToBase64String($calculatedHash)
        $authorization = 'SharedKey {0}:{1}' -f $customerId,$encodedHash
        return $authorization
    }
    Function Post-LogAnalyticsData($customerId, $sharedKey, $body, $logType)
    {
        $method = "POST"
        $contentType = "application/json"
        $resource = "/api/logs"
        $rfc1123date = [DateTime]::UtcNow.ToString("r")
        $contentLength = $body.Length
        $signature = Build-Signature `
            -customerId $customerId `
            -sharedKey $sharedKey `
            -date $rfc1123date `
            -contentLength $contentLength `
            -method $method `
            -contentType $contentType `
            -resource $resource
        $uri = "https://" + $customerId + ".ods.opinsights.azure.com" + $resource + "?api-version=2016-04-01"

        $headers = @{
            "Authorization" = $signature;
            "Log-Type" = $logType;
            "x-ms-date" = $rfc1123date;
            "time-generated-field" = $TimeStampField;
        }

        $response = Invoke-WebRequest -Uri $uri -Method $method -ContentType $contentType -Headers $headers -Body $body -UseBasicParsing
        return $response.StatusCode

    }
    # Submit the data to the API endpoint
    Post-LogAnalyticsData -customerId $customerId -sharedKey $sharedKey -body ([System.Text.Encoding]::UTF8.GetBytes($json)) -logType $logType
}

