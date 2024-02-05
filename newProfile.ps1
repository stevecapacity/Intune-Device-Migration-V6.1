# NEWPROFILE.PS1
# This script is used to capture the SID of the destination user account after sign in.  The SID is then written to the registry.
# It is executed by the 'newProfile' scheduled task.
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
    $newProfileLog = "$logPath\newProfile.log"
    Start-Transaction -Path $newProfileLog -Verbose
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

# disable newProfile task
function disableNewProfileTask()
{
    Param(
        [string]$newProfileTask = "newProfile"
    )
    Write-Host "Disabling newProfile task..."
    try 
    {
        Disable-ScheduledTask -TaskName $newProfileTask -ErrorAction Ignore
        Write-Host "newProfile task disabled"    
        $logObject += @{Name="newProfile Task Disabled"; Status="TRUE"}
    }
    catch 
    {
        $message = $_.Exception.Message
        Write-Host "newProfile task not disabled: $message"
        $logObject += @{Name="newProfile Task Disabled"; Status="FALSE: $message"}
    }
}

# run disableNewProfileTask
try 
{
    disableNewProfileTask
    Write-Host "newProfile task disabled"
    $logObject += @{Name="newProfile Task Disabled"; Status="TRUE"}
}
catch 
{
    $message = $_.Exception.Message
    Write-Host "Error disabling newProfile task: $message"
    $logObject += @{Name="newProfile Task Disabled"; Status="FALSE: $message"}
    Write-Host "Stopping script"
    Exit 1
}

# Get SID of destination user account
function getNewUserSID()
{
    Param(
        [string]$newUser = (Get-WmiObject -Class Win32_ComputerSystem | Select-Object -ExpandProperty UserName),
        [string]$newUserSID = (New-Object System.Security.Principal.NTAccount($newUser)).Translate([System.Security.Principal.SecurityIdentifier]).Value,
        [string]$regPath = $settings.regPath    
    )
    if(![string]::IsNullOrEmpty($newUserSID))
    {
        Write-Host "New user SID: $newUserSID"
        $logObject += @{Name="New User SID"; Status="TRUE"; SID=$newUserSID}
        Write-Host "Writing new user SID to registry..."
        try
        {
            reg.exe add $regPath /v "NewUserSID" /t REG_SZ /d $newUserSID /f
            Write-Host "New user SID written to registry"
            $logObject += @{Name="New User SID Written to Registry"; Status="TRUE"}
        }
        catch
        {
            $message = $_.Exception.Message
            Write-Host "Error writing new user SID to registry: $message"
            $logObject += @{Name="New User SID Written to Registry"; Status="FALSE: $message"}
        }
    }
    else
    {
        Write-Host "New user SID not found"
        $logObject += @{Name="New User SID"; Status="FALSE: SID not found"}
    }
}

# run getNewUserSID
try 
{
    getNewUserSID
    Write-Host "New user SID captured"
    $logObject += @{Name="New User SID Captured"; Status="TRUE"}
}
catch 
{
    $message = $_.Exception.Message
    Write-Host "Error getting new user SID: $message"
    $logObject += @{Name="New User SID"; Status="FALSE: $message"}
    Write-Host "Stopping script"
    Exit 1
}

# set lock screen image
function setLockScreen()
{
    Param(
        [string]$lockScreenImg1 = $settings.lockScreen1,
        [string]$lockScreenImg1Path = "$($localPath)\$lockScreenImg1",
        [string]$lockScreenRegPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\PersonalizationCSP",
        [int]$lockScreenStatus = 1
    )
    if(Test-Path $lockScreenImg1Path)
    {
        reg.exe add $lockScreenRegPath /v LockScreenImagePath /t REG_SZ /d $lockScreenImg1Path /f | Out-Host
        reg.exe add $lockScreenRegPath /v LockScreenImageUrl /t REG_SZ /d $lockScreenImg1Path /f | Out-Host
        reg.exe add $lockScreenRegPath /v LockScreenImageStatus /t REG_DWORD /d $lockScreenStatus /f | Out-Host
    }
    else
    {
        Write-Host "Lock screen image not found"
        $logObject += @{Name="Lock screen image found:";Value="FALSE"}
    }
}

# run setLockScreen
try 
{
    setLockScreen
    Write-Host "Lock screen image set"
    $logObject += @{Name="Lock Screen Image Set"; Status="TRUE"}
}
catch 
{
    $message = $_.Exception.Message
    Write-Host "Error setting lock screen image: $message"
    $logObject += @{Name="Lock Screen Image Set"; Status="FALSE: $message"}
}

function setFinalMigrationTasks()
{
    Param(
        [string]$finalBoot = "$($localPath)\finalBoot.xml",
        [string]$postMigrate = "$($localPath)\postMigrate.xml",
        [string]$autopilotRegistration = "$($localPath)\autopilotRegistration.xml",
        [array]$tasks = @($finalBoot, $postMigrate, $autopilotRegistration)
    )
    foreach($task in $tasks)
    {
        if($null -ne $task)
        {
            Write-Host "Setting $($task.BaseName) task..."
            try 
            {
                schtasks.exe /Create /TN $($task.BaseName) /XML $($task.FullName)
                Write-Host "$($task.BaseName) task set"
                $logObject += @{Name="$($task.BaseName) Task Set"; Status="TRUE"}
            }
            catch 
            {
                $message = $_.Exception.Message
                Write-Host "$($task.BaseName) task not set: $message"
                $logObject += @{Name="$($task.BaseName) Task Set"; Status="FALSE: $message"}    
            }
        }
        else
        {
            Write-Host "Task not found"
            $logObject += @{Name="Task Found"; Status="FALSE"}
        }
    }
}

# run setFinalMigrationTasks
try 
{
    setFinalMigrationTasks
    Write-Host "Final migration tasks set"
    $logObject += @{Name="Final Migration Tasks Set"; Status="TRUE"}
}
catch 
{
    $message = $_.Exception.Message
    Write-Host "Error setting final migration tasks: $message"
    $logObject += @{Name="Final Migration Tasks Set"; Status="FALSE: $message"}
    Write-Host "Stopping script"
    Exit 1
}

# log to Log Analytics
function logAnalytics()
{
    Param(
        [boolean]$logAnalyticsEnabled = $settings.logAnalytics.enabled,
        [string]$customerId = $settings.logAnalytics.workspaceID,
        [string]$sharedKey = $settings.logAnalytics.sharedKey,
        [string]$logType = "newProfile"
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
    $logObject += @{Name="Log Analytics Data Submitted"; Status="TRUE"}
}
catch 
{
    $message = $_.Exception.Message
    Write-Host "Error submitting Log Analytics data: $message"
    $logObject += @{Name="Log Analytics Data Submitted"; Status="FALSE: $message"}
}

# stop transcript
Stop-Transcript

# restart computer
shutdown -r -t 30