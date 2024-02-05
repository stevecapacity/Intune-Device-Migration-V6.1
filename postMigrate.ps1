# POSTMIGRATE.PS1
# This script is used to update the device group tag in Entra ID and set the primary user in Intune and migrate the bitlocker recovery key.
# It is executed by the 'postMigrate' scheduled task.
$ErrorActionPreference = "SilentlyContinue"
$logObject = @()

# Import settings from settings.json
$settings = Get-Content -Path "$($PSScriptRoot)\settings.json" | ConvertFrom-Json

# Create local path and start transcript
function initializeScript()
{
    Param(
        [string]$localPath = $settings.localPath,
        [string]$logPath = $settings.logPath
    )
    if(!(Test-Path -Path $localPath))
    {
        mkdir $localPath
    }
    $postMigrateLog = "$logPath\postMigrate.log"
    Start-Transaction -Path $postMigrateLog -Verbose
}

# run initializeScript
try 
{
    initializeScript
    Write-Host "Script initialized"
    $logObject += @{Name="Script Initialized"; Status="TRUE"}
}
catch 
{
    $message = $_.Exception.Message
    Write-Host "Error initializing script: $message"
    $logObject += @{Name="Script Initialized"; Status="FALSE: $message"}
    Write-Host "Stopping script"
    Exit 1
}

# Disable postMigrate task
function disablePostMigrateTask()
{
    Param(
        [string]$taskName = "postMigrate"
    )
    Write-Host "Disabling postMigrate task..."
    try 
    {
        Disable-ScheduledTask -TaskName $taskName
        Write-Host "postMigrate task disabled"    
        $logObject += @{Name="postMigrate Task Disabled"; Status="TRUE"}
    }
    catch 
    {
        $message = $_.Exception.Message
        Write-Host "postMigrate task not disabled: $message"
        $logObject += @{Name="postMigrate Task Disabled"; Status="FALSE: $message"}
    }    
}

# run disablePostMigrateTask
try 
{
    disablePostMigrateTask
    Write-Host "postMigrate task disabled"
    $logObject += @{Name="postMigrate Task Disabled"; Status="TRUE"}
}
catch 
{
    $message = $_.Exception.Message
    Write-Host "Error disabling postMigrate task: $message"
    $logObject += @{Name="postMigrate Task Disabled"; Status="FALSE: $message"}
    Write-Host "Stopping script"
    Exit 1
}

# Authenticate to Graph (target tenant)
function msGraphAuthenticate()
{
    Param(
    [string]$clientId = $settings.targetTenant.clientID,
    [string]$clientSecret = $settings.targetTenant.clientSecret,
    [string]$tenant = $settings.targetTenant.tenantName
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
}

# run msGraphAuthenticate
try 
{
    msGraphAuthenticate
    Write-Host "Authenticated to Graph"
    $logObject += @{Name="Authenticated to Graph"; Status="TRUE"}
}
catch 
{
    $message = $_.Exception.Message
    Write-Host "Error authenticating to Graph: $message"
    $logObject += @{Name="Authenticated to Graph"; Status="FALSE: $message"}
    Write-Host "Stopping script"
    Exit 1
}

# update group tag status
function groupTagStatus()
{
    Param(
        [string]$regPath = $settings.regPath,
        [string]$regKey = "Registry::$regPath"
    )
    Write-Host "Getting GroupTag from registry..."
    $grouptag = Get-ItemPropertyValue -Path $regPath -Name "GroupTag" -ErrorAction SilentlyContinue
    $useGroupTag = $false
    if([string]::IsNullOrEmpty($grouptag))
    {
        Write-Host "GroupTag not found in registry"
        $logObject += @{Name="GroupTag"; Status="FALSE: GroupTag will not be used"}
    }
    else
    {
        Write-Host "GroupTag found in registry: $grouptag"
        $useGroupTag = $true
        $logObject += @{Name="GroupTag"; Status="TRUE: GroupTag $($groupTag) will be used"}
    }
    return $useGroupTag
}

# run groupTagStatus
try 
{
    groupTagStatus
    Write-Host "GroupTag status updated"
    $logObject += @{Name="GroupTag Status Updated"; Status="TRUE"}
}
catch 
{
    $message = $_.Exception.Message
    Write-Host "Error updating GroupTag status: $message"
    $logObject += @{Name="GroupTag Status Updated"; Status="FALSE: $message"}
}

# get graph info
function getGraphInfo()
{
    Param(
        [string]$serialNumber = (Get-WmiObject -Class Win32_Bios).SerialNumber,
        [string]$intuneUri = "https://graph.microsoft.com/beta/deviceManagement/managedDevices",
        [string]$deviceUri = "https://graph.microsoft.com/beta/devices"
    )
    Write-Host "Getting device info from Graph..."
    try
    {
        $intuneObject = Invoke-RestMethod -Method Get -Uri "$intuneUri?`$filter=contains(serialNumber,'$serialNumber')" -Headers $headers
        if($null -ne $intuneObject)
        {
            Write-Host "Intune object found"
            $logObject += @{Name="Intune object"; Status="TRUE"}
            
            $aadDeviceId = $intuneObject.value.azureADDeviceId
            if (![string]::IsNullOrEmpty($aadDeviceId))
            {
                try
                {
                    $aadObject = Invoke-RestMethod -Method Get -Uri "$deviceUri/$aadDeviceId" -Headers $headers
                    Write-Host "AAD object found"
                    $logObject += @{Name="AAD object"; Status="TRUE"}
                    
                    if ($null -ne $aadObject)
                    {
                        $physicalIds = $aadObject.value.physicalIds
                        Write-Host "Physical IDs found"
                        $logObject += @{Name="Physical IDs"; Status="TRUE"}    
                    }
                    else
                    {
                        Write-Host "Physical IDs not found"
                        $logObject += @{Name="Physical IDs"; Status="FALSE: Physical IDs not found"}
                    }
                }
                catch
                {
                    $message = $_.Exception.Message
                    Write-Host "Error getting AAD object: $message"
                    $logObject += @{Name="AAD object"; Status="FALSE: $message"}
                }
            }
            $intuneDeviceId = $intuneObject.value.id
            if (![string]::IsNullOrEmpty($intuneDeviceId))
            {
                Write-Host "Intune device ID found"
                $logObject += @{Name="Intune Device ID"; Status="TRUE: $intuneDeviceId"}
            }
            else
            {
                Write-Host "Intune device ID not found"
                $logObject += @{Name="Intune Device ID"; Status="FALSE: Intune device ID not found"}
            }
        }
    }
    catch
    {
        $message = $_.Exception.Message
        Write-Host "Error getting Intune object from Graph: $message"
        $logObject += @{Name="Intune object"; Status="FALSE: $message"}
    }
    return $physicalIds
}

# run getGraphInfo
try 
{
    getGraphInfo
    Write-Host "Graph info updated"
    $logObject += @{Name="Graph Info Updated"; Status="TRUE"}
}
catch 
{
    $message = $_.Exception.Message
    Write-Host "Error updating Graph info: $message"
    $logObject += @{Name="Graph Info Updated"; Status="FALSE: $message"}
    Write-Host "Stopping script"
    Exit 1
}

# update device group tag
function updateDeviceGroupTag()
{
    Param(
        [string]$groupTag = $grouptag,
        [string]$aadDeviceId = $aadDeviceId,
        [string]$deviceUri = $deviceUri,
        [array]$physicalIds = $physicalIds,
        [boolean]$useGroupTag = $useGroupTag
    )
    if($useGroupTag -eq $true)
    {
        Write-Host "Updating device group tag..."
        $groupTag = "[OrderID]:$($groupTag)"
        $physicalIds += $groupTag
        $body = @{
            physicalIds = $physicalIds
        } | ConvertTo-Json
        try 
        {
            Invoke-RestMethod -Uri $deviceUri/$aadDeviceId -Method Patch -Headers $headers -Body $body
            Write-Host "Device group tag updated"
            $logObject += @{Name="Device Group Tag Updated"; Status="TRUE"}
        }
        catch 
        {
            $message = $_.Exception.Message
            Write-Host "Error updating device group tag: $message"
            $logObject += @{Name="Device Group Tag Updated"; Status="FALSE: $message"}
        }
    }
    else
    {
        Write-Host "GroupTag not found in registry. Device group tag will not be updated"
        $logObject += @{Name="Device Group Tag Updated"; Status="FALSE: GroupTag not found in registry"}
    }
}

# run updateDeviceGroupTag
try 
{
    updateDeviceGroupTag
    Write-Host "Device group tag updated"
    $logObject += @{Name="Device Group Tag Updated"; Status="TRUE"}
}
catch 
{
    $message = $_.Exception.Message
    Write-Host "Error updating device group tag: $message"
    $logObject += @{Name="Device Group Tag Updated"; Status="FALSE: $message"}
}

# set primary user
function setPrimaryUser()
{
    Param(
        [string]$user = (Get-WmiObject -Class Win32_ComputerSystem | Select-Object -ExpandProperty UserName),
        [string]$userSID = (new-Object System.Security.Principal.NTAccount($user)).Translate([System.Security.Principal.SecurityIdentifier]).Value,
        [string]$upn = (Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Microsoft\IdentityStore\Cache\$($userSID)\IdentityCache\$($userSID)" -Name "UserName"),
        [string]$userUri = "https://graph.microsoft.com/beta/users",
        [string]$intuneDeviceUri = "$intuneUri/$intuneDeviceId"
    )
    Write-Host "Getting user info from Graph..."
    try
    {
        $userObject = Invoke-RestMethod -Method Get -Uri "$userUri/$upn" -Headers $headers
        if($null -ne $userObject)
        {
            Write-Host "User object found"
            $logObject += @{Name="User object"; Status="TRUE"}
            $userId = $userObject.id
            if (![string]::IsNullOrEmpty($userId))
            {
                Write-Host "User ID found"
                $logObject += @{Name="User ID"; Status="TRUE: $userId"}
                $userIdUri = "$userUri/$userId"
                $odataId = "@odata.id"
                $body = @{
                    $odataId = "$userIdUri"
                } | ConvertTo-Json
                try 
                {
                    Invoke-RestMethod -Uri "$intuneDeviceUri/users/`$ref" -Method Post -Headers $headers -Body $body
                    Write-Host "Primary user updated"
                    $logObject += @{Name="Primary User Updated"; Status="TRUE"}
                }
                catch 
                {
                    $message = $_.Exception.Message
                    Write-Host "Error updating primary user: $message"
                    $logObject += @{Name="Primary User Updated"; Status="FALSE: $message"}
                }
            }
            else
            {
                Write-Host "User ID not found"
                $logObject += @{Name="User ID"; Status="FALSE: User ID not found"}
            }
        }
    }
    catch
    {
        $message = $_.Exception.Message
        Write-Host "Error getting user object from Graph: $message"
        $logObject += @{Name="User object"; Status="FALSE: $message"}
    }
}

# run setPrimaryUser
try 
{
    setPrimaryUser
    Write-Host "Primary user updated"
    $logObject += @{Name="Primary User set"; Status="TRUE"}
}
catch 
{
    $message = $_.Exception.Message
    Write-Host "Error setting primary user: $message"
    $logObject += @{Name="Primary User set"; Status="FALSE: $message"}
}

# configure bitlocker
function configureBitlocker()
{
    Param(
        [string]$bitlockerMethod = $settings.bitlockerMethod,
        [string]$driveLetter = "C:",
        [string]$encryptionStatus = (Get-BitLockerVolume -MountPoint $driveLetter).EncryptionPercentage
    )
    Write-Host "BitLocker method: $bitlockerMethod"
    if($bitlockerMethod -eq "migrate")
    {
        Write-Host "Migrating BitLocker recovery key..."
        if($encryptionStatus -eq 0)
        {
            Write-Host "BitLocker is not enabled on drive $driveLetter"
            $logObject += @{Name="BitLocker Recovery Key Migrated"; Status="FALSE: BitLocker is not enabled on drive $driveLetter"}
        }
        else
        {
            Write-Host "BitLocker is enabled on drive $driveLetter- migrating..."
            try
            {
                $BLV = Get-BitLockerVolume -MountPoint $driveLetter
                BackupToAAD-BitLockerKeyProtector -MountPoint $driveLetter -KeyProtectorId $BLV.KeyProtector[1].KeyProtectorId
                Write-Host "BitLocker recovery key migrated"
                $logObject += @{Name="BitLocker Recovery Key Migrated"; Status="TRUE"}
            }
            catch
            {
                $message = $_.Exception.Message
                Write-Host "Error migrating BitLocker recovery key: $message"
                $logObject += @{Name="BitLocker Recovery Key Migrated"; Status="FALSE: $message"}
            }
        }
    }
    elseif($bitlockerMethod -eq "decrypt")
    {
        Write-Host "Decrypting BitLocker..."
        if($encryptionStatus -eq 0)
        {
            Write-Host "BitLocker is not enabled on drive $driveLetter"
            $logObject += @{Name="BitLocker Decryption"; Status="FALSE: BitLocker is not enabled on drive $driveLetter"}
        }
        else
        {
            Write-Host "BitLocker is enabled on drive $driveLetter- decrypting..."
            try 
            {
                Disable-BitLocker -MountPoint $driveLetter 
                Write-Host "BitLocker decrypted"
                $logObject += @{Name="BitLocker Decryption"; Status="TRUE"}
            }
            catch
            {
                $message = $_.Exception.Message
                Write-Host "Error decrypting BitLocker: $message"
                $logObject += @{Name="BitLocker Decryption"; Status="FALSE: $message"}
            }
        }
    }
    else
    {
        Write-Host "BitLocker method not recognized"
        $logObject += @{Name="BitLocker Method"; Status="FALSE: BitLocker method not recognized"}
    }
}

# run configureBitlocker
try 
{
    configureBitlocker
    Write-Host "BitLocker configured"
    $logObject += @{Name="BitLocker Configured"; Status="TRUE"}
}
catch 
{
    $message = $_.Exception.Message
    Write-Host "Error configuring BitLocker: $message"
    $logObject += @{Name="BitLocker Configured"; Status="FALSE: $message"}
}

# log to Log Analytics
function logAnalytics()
{
    Param(
        [boolean]$logAnalyticsEnabled = $settings.logAnalytics.enabled,
        [string]$customerId = $settings.logAnalytics.workspaceID,
        [string]$sharedKey = $settings.logAnalytics.sharedKey,
        [string]$logType = "postMigrate"
    )
    if($logAnalyticsEnabled -eq $true)
    {
        $logInfo = New-Object System.Object
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
        Function PostLogAnalyticsData($customerId, $sharedKey, $body, $logType)
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
        PostLogAnalyticsData -customerId $customerId -sharedKey $sharedKey -body ([System.Text.Encoding]::UTF8.GetBytes($json)) -logType $logType
    }
    else
    {
        Write-Host "Log Analytics not enabled"
    }
}

# run logAnalytics
try 
{
    logAnalytics
    Write-Host "Logged to Log Analytics"
    $logObject += @{Name="Logged to Log Analytics"; Status="TRUE"}
}
catch 
{
    $message = $_.Exception.Message
    Write-Host "Error logging to Log Analytics: $message"
    $logObject += @{Name="Logged to Log Analytics"; Status="FALSE: $message"}
}

# stop transcript
Stop-Transcript