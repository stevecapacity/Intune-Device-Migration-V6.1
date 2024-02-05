# FINALBOOT.PS1
# This script is used to change ownership of the original user profile to the destination user and then reboot the machine.
# It is executed by the 'finalBoot' scheduled task.
$ErrorActionPreference = "silentlycontinue"
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
    $finalBootLog = "$logPath\finalBoot.log"
    Start-Transaction -Path $finalBootLog -Verbose
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

# disable finalBoot task
function disableFinalBoot()
{
    Param(
        [string]$finalBootTask = "finalBoot"
    )
    Write-Host "Disabling finalBoot task..."
    try 
    {
        Disable-ScheduledTask -TaskName $finalBootTask -ErrorAction Ignore
        Write-Host "finalBoot task disabled"    
        $logObject += @{Name="finalBoot Task Disabled"; Status="TRUE"}
    }
    catch 
    {
        $message = $_.Exception.Message
        Write-Host "finalBoot task not disabled: $message"
        $logObject += @{Name="finalBoot Task Disabled"; Status="FALSE: $message"}
    }
}

# run disableFinalBoot
try 
{
    disableFinalBoot
    Write-Host "finalBoot task disabled"
    $logObject += @{Name="finalBoot Task Disabled"; Status="TRUE"}
}
catch 
{
    $message = $_.Exception.Message
    Write-Host "Error disabling finalBoot task: $message"
    $logObject += @{Name="finalBoot Task Disabled"; Status="FALSE: $message"}
    Write-Host "Stopping script"
    Exit 1
}

# reset lock screen
function resetLockScreen()
{
    Param(
        [string]$lockScreenImg2 = $settings.lockScreen2,
        [string]$lockScreenImg2Path = "$($localPath)\$lockScreenImg2",
        [string]$lockScreenRegPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\PersonalizationCSP"
    )
    if(Test-Path $lockScreenImg1Path)
    {
        try
        {
            reg.exe add $lockScreenRegPath /v LockScreenImagePath /t REG_SZ /d $lockScreenImg2Path /f | Out-Host
            reg.exe add $lockScreenRegPath /v LockScreenImageUrl /t REG_SZ /d $lockScreenImg2Path /f | Out-Host
            Write-Host "Lock screen image reset"
            $logObject += @{Name="Lock screen image reset";Value="TRUE"}
        }
        catch
        {
            $message = $_.Exception.Message
            Write-Host "Error resetting lock screen image: $message"
            $logObject += @{Name="Lock screen image reset";Value="FALSE: $message"}
        }
    }
    else
    {
        Write-Host "Lock screen image not found"
        $logObject += @{Name="Lock screen image found:";Value="FALSE"}
    }
}

# run resetLockScreen
try 
{
    resetLockScreen
    Write-Host "Lock screen image reset"
    $logObject += @{Name="Lock screen image reset";Value="TRUE"}
}
catch 
{
    $message = $_.Exception.Message
    Write-Host "Error resetting lock screen image: $message"
    $logObject += @{Name="Lock screen image reset";Value="FALSE: $message"}
}

# get user registry values
function getRegValues()
{
    Param(
        [array]$values = @("OriginalUserSID","OriginalUserName","OriginalUserProfilePath","NewUserSID"),
        [string]$regPath = $settings.regPath,
        [string]$regKey = "Registry::$regPath"
    )
    foreach($value in $values)
    {
        Write-Host "Getting $value..."
        try 
        {
            $regValue = Get-ItemPropertyValue -Path $regKey -Name $value
            Set-Variable -Name $value -Value $regValue
            Write-Host "$($value): $($regValue)"
            $logObject += @{Name=$value;Value=$regValue}
        }
        catch 
        {
            $message = $_.Exception.Message
            Write-Host "Error getting $($value): $message"
            $logObject += @{Name=$value;Value="ERROR: $message"}
        }
    }
}

# run getRegValues
try 
{
    getRegValues
    Write-Host "User registry values retrieved"
    $logObject += @{Name="User Registry Values Retrieved";Status="TRUE"}
}
catch 
{
    $message = $_.Exception.Message
    Write-Host "Error retrieving user registry values: $message"
    $logObject += @{Name="User Registry Values Retrieved";Status="FALSE: $message"}
}

# Delete AADBroker Plugin Folder
function deleteAadBrokerPlugin()
{
    Param(
        [string]$originalProfilePath = $OriginalUserProfilePath,
        [string]$aadBrokerFolder = (Get-ChildItem -Path "$($originalProfilePath)\AppData\Local\Packages" -ErrorAction SilentlyContinue | Where-Object {$_.Name -like "Microsoft.AAD.BrokerPlugin_cw5n1h2txyewy"}).FullName
    )
    if($aadBrokerFolder -ne $null)
    {
        Write-Host "Deleting AADBroker Plugin folder..."
        try 
        {
            Remove-Item -Path $aadBrokerFolder -Recurse -Force -ErrorAction Ignore
            Write-Host "AADBroker Plugin folder deleted"
            $logObject += @{Name="AADBroker Plugin Folder Deleted";Status="TRUE"}
        }
        catch 
        {
            $message = $_.Exception.Message
            Write-Host "Error deleting AADBroker Plugin folder: $message"
            $logObject += @{Name="AADBroker Plugin Folder Deleted";Status="FALSE: $message"}
        }
    }
    else
    {
        Write-Host "AADBroker Plugin folder not found"
        $logObject += @{Name="AADBroker Plugin Folder Found";Status="FALSE"}
    }
}

# run deleteAadBrokerPlugin
try 
{
    deleteAadBrokerPlugin
    Write-Host "AADBroker Plugin folder deleted"
    $logObject += @{Name="AADBroker Plugin Folder Deleted";Status="TRUE"}
}
catch 
{
    $message = $_.Exception.Message
    Write-Host "Error deleting AADBroker Plugin folder: $message"
    $logObject += @{Name="AADBroker Plugin Folder Deleted";Status="FALSE: $message"}
    Write-Host "WARNING: Check PC integrity after migration..."
}

# delete new user profile
function deleteNewUserProfile()
{
    Param(
        [string]$newUserSID = $NewUserSID
    )
    $newUserProfile = Get-CimInstance -ClassName Win32_UserProfile | Where-Object {$_.SID -eq $newUserSID}
    try 
    {
        Remove-CimInstance -InputObject $newUserProfile -Verbose | Out-Null
        Write-Host "New user profile deleted"
        $logObject += @{Name="New User Profile Deleted";Status="TRUE"}    
    }
    catch 
    {
        $message = $_.Exception.Message
        Write-Host "Error deleting new user profile: $message"
        $logObject += @{Name="New User Profile Deleted";Status="FALSE: $message"}
    }
}

# run deleteNewUserProfile
try 
{
    deleteNewUserProfile
    Write-Host "New user profile deleted"
    $logObject += @{Name="New User Profile Deleted";Status="TRUE"}
}
catch 
{
    $message = $_.Exception.Message
    Write-Host "Error deleting new user profile: $message"
    $logObject += @{Name="New User Profile Deleted";Status="FALSE: $message"}
    Write-Host "Stopping script"
    Exit 1
}

# change ownership of original user profile
function changeOwnership()
{
    Param(
        [string]$originalUserSID = $OriginalUserSID,
        [string]$newUserSID = $NewUserSID
    )
    $originalUserProfile = Get-CimInstance -ClassName Win32_UserProfile | Where-Object {$_.SID -eq $originalUserSID}
    $changeArguments = @{
        NewOwnerSID = $newUserSID
        Flags = 0
    }
    Write-Host "Changing ownership of original profile..."
    try 
    {
        $originalUserProfile | Invoke-CimMethod -MethodName ChangeOwner -Arguments $changeArguments
        Write-Host "Ownership changed"
        $logObject += @{Name="Ownership Changed";Status="TRUE"}
    }
    catch 
    {
        $message = $_.Exception.Message
        Write-Host "Error changing ownership: $message"
        $logObject += @{Name="Ownership Changed";Status="FALSE: $message"}
    }
}

# run changeOwnership
try 
{
    changeOwnership
    Write-Host "Ownership changed"
    $logObject += @{Name="Ownership Changed";Status="TRUE"}
}
catch 
{
    $message = $_.Exception.Message
    Write-Host "Error changing ownership: $message"
    $logObject += @{Name="Ownership Changed";Status="FALSE: $message"}
    Write-Host "Stopping script"
    Exit 1
}

# cleanup registry cache
function cleanupLogonCache()
{
    Param(
        [string]$originalUserName = $OriginalUserName,
        [string]$logonCache = "HKLM:\SOFTWARE\Microsoft\IdentityStore\LogonCache",
        [array]$logonCacheGUID = (Get-ChildItem -Path $logonCache | Select-Object Name | Split-Path -Leaf).trim('{}')
    )
    Write-Host "Cleaning up logon cache..."
    foreach($guid in $logonCacheGUID)
    {
        $subKeys = Get-ChildItem -Path "$logonCache\$guid" -ErrorAction Ignore | Select-Object -ExpandProperty Name | Split-Path -Leaf
        if(!($subKeys))
        {
            Write-Host "No subkeys found in $guid"
            $logObject += @{Name="Subkeys Found in $guid";Status="FALSE"}
        }
        else
        {
            $subKeys = $subKeys.trim('{}')
            foreach($subKey in $subKeys)
            {
                if($subKey -eq "Name2Sid" -or $subKey -eq "SAM_Name" -or $subKey -eq "Sid2Name")
                {
                    $subFolders = Get-ChildItem -Path "$logonCache\$guid\$subKey" -ErrorAction Ignore | Select-Object -ExpandProperty Name | Split-Path -Leaf
                    if(!($subFolders))
                    {
                        Write-Host "No subfolders found for $subKey"
                        $logObject += @{Name="Subfolders Found for $subKey";Status="FALSE"}
                    }
                    else
                    {
                        $subFolders = $subFolders.trim('{}')
                        foreach($subFolder in $subFolders)
                        {
                            $cacheUsername = Get-ItemPropertyValue -Path "$logonCache\$guid\$subKey\$subFolder" -Name "IdentityName" -ErrorAction Ignore
                            if($cacheUsername -eq $originalUserName)
                            {
                                Write-Host "Deleting $logonCache\$guid\$subKey\$subFolder"
                                try 
                                {
                                    Remove-Item -Path "$logonCache\$guid\$subKey\$subFolder" -Recurse -Force
                                    Write-Host "$logonCache\$guid\$subKey\$subFolder deleted"
                                    $logObject += @{Name="$logonCache\$guid\$subKey\$subFolder Deleted";Status="TRUE"}
                                }
                                catch 
                                {
                                    $message = $_.Exception.Message
                                    Write-Host "Error deleting $logonCache\$guid\$subKey\$($subFolder): $message"
                                    $logObject += @{Name="$subKey\$subFolder Deleted";Status="FALSE: $message"}
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

# run cleanupLogonCache
try 
{
    cleanupLogonCache
    Write-Host "Logon cache cleaned"
    $logObject += @{Name="Logon Cache Cleaned";Status="TRUE"}
}
catch 
{
    $message = $_.Exception.Message
    Write-Host "Error cleaning logon cache: $message"
    $logObject += @{Name="Logon Cache Cleaned";Status="FALSE: $message"}
    Write-Host "Stopping script"
    Exit 1
}

# Cleanup identity store
function cleanupIdentityStore()
{
    Param(
        [string]$originalUserName = $OriginalUserName,
        [string]$identityCache = "HKLM:\SOFTWARE\Microsoft\IdentityStore\Cache",
        [array]$identityCacheKeys = (Get-ChildItem -Path $identityCache | Select-Object Name | Split-Path -Leaf).trim('{}')
    )
    Write-Host "Cleaning up identity store..."
    foreach($key in $identityCacheKeys)
    {
        $subKeys = Get-ChildItem -Path "$identityCache\$key" -ErrorAction Ignore | Select-Object -ExpandProperty Name | Split-Path -Leaf
        if(!($subKeys))
        {
            Write-Host "No keys listed under '$identityCache\$key' -skipping..."
            continue
        }
        else
        {
            $subKeys = $subKeys.trim('{}')
            foreach($subKey in $subKeys)
            {
                $subFolders = Get-ChildItem -Path "$identityCache\$key\$subKey" -ErrorAction Ignore | Select-Object -ExpandProperty Name | Split-Path -Leaf
                if(!($subFolders))
                {
                    Write-Host "Error - no subfolders found for $subKey. Skipping subkey '$subKey'..."
                    continue
                }
                else
                {
                    $subFolders = $subFolders.trim('{}')
                    foreach($subFolder in $subFolders)
                    {
                        $identityCacheUsername = Get-ItemPropertyValue -Path "$identityCache\$key\$subKey\$subFolder" -Name "UserName" -ErrorAction Ignore
                        if($identityCacheUsername -eq $originalUserName)
                        {
                            Write-Host "Deleting $identityCache\$key\$subKey\$subFolder"
                            try 
                            {
                                Remove-Item -Path "$identityCache\$key\$subKey\$subFolder" -Recurse -Force
                                Write-Host "$identityCache\$key\$subKey\$subFolder deleted"
                                $logObject += @{Name="$identityCache\$key\$subKey\$subFolder Deleted";Status="TRUE"}
                            }
                            catch 
                            {
                                $message = $_.Exception.Message
                                Write-Host "Error deleting $identityCache\$key\$subKey\$($subFolder): $message"
                                $logObject += @{Name="$identityCache\$key\$subKey\$subFolder Deleted";Status="FALSE: $message"}
                            }
                        }
                    }
                }
            }
        }
    }
}

# run cleanupIdentityStore
try 
{
    cleanupIdentityStore
    Write-Host "Identity store cleaned"
    $logObject += @{Name="Identity Store Cleaned";Status="TRUE"}
}
catch 
{
    $message = $_.Exception.Message
    Write-Host "Error cleaning identity store: $message"
    $logObject += @{Name="Identity Store Cleaned";Status="FALSE: $message"}
    Write-Host "Stopping script"
    Exit 1
}

# Reset GPO settings
function setLastLogonPolicy()
{
    Param(
        [string]$lastLogonPolicyPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
        [string]$lastLogonPolicyName = "dontdisplaylastusername",
        [int]$lastLogonPolicyValue = 0
    )
    Write-Host "Resetting last logon policy settings..."
    try 
    {
        Set-ItemProperty -Path $lastLogonPolicyPath -Name $lastLogonPolicyName -Value $lastLogonPolicyValue 
        Write-Host "Last logon policy settings reset"
        $logObject += @{Name="Last Logon Policy Settings Reset";Status="TRUE"}
    }
    catch 
    {
        $message = $_.Exception.Message
        Write-Host "Error resetting last logon policy settings: $message"
        $logObject += @{Name="Last Logon Policy Settings Reset";Status="FALSE: $message"}
    }
}

# run setLastLogonPolicy
try 
{
    setLastLogonPolicy
    Write-Host "Last logon policy settings reset"
    $logObject += @{Name="Last Logon Policy Settings Reset";Status="TRUE"}
}
catch 
{
    $message = $_.Exception.Message
    Write-Host "Error resetting last logon policy settings: $message"
    $logObject += @{Name="Last Logon Policy Settings Reset";Status="FALSE: $message"}
    Write-Host "WARNING: Check PC integrity after migration..."
}

# log to Log Analytics
function logAnalytics()
{
    Param(
        [boolean]$logAnalyticsEnabled = $settings.logAnalytics.enabled,
        [string]$customerId = $settings.logAnalytics.workspaceID,
        [string]$sharedKey = $settings.logAnalytics.sharedKey,
        [string]$logType = "finalBoot"
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
    Write-Host "Log Analytics data submitted"
    $logObject += @{Name="Log Analytics Data Submitted";Status="TRUE"}
}
catch 
{
    $message = $_.Exception.Message
    Write-Host "Error submitting Log Analytics data: $message"
    $logObject += @{Name="Log Analytics Data Submitted";Status="FALSE: $message"}
}

# stop transcript
Stop-Transcript

# reboot machine
shutdown -r -t 00