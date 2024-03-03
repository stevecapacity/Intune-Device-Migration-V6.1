# FUNCTION: Log
# PURPOSE: Log messages to console and log file
# DESCRIPTION: This function logs messages to the console and log file.  It takes a message as input and outputs the message with a timestamp to the console and log file.
# INPUTS: $message (string)
# OUTPUTS: example; 2021-01-01 12:00:00 PM message
function log()
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory=$true)]
        [string]$message
    )
    $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss tt"
    Write-Output "$ts $message"
}

# FUNCTION: exitScript
# PURPOSE: Exit script with error code
# DESCRIPTION: This function exits the script with an error code.  It takes an exit code, function name, and local path as input and outputs the error message to the console and log file.  It also removes the local path and reboots the device if the exit code is 1.
# INPUTS: $exitCode (int), $functionName (string), $localpath (string)
# OUTPUTS: example; Function functionName failed with critical error.  Exiting script with exit code exitCode.
function exitScript()
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [int]$exitCode,
        [Parameter(Mandatory=$true)]
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

# FUNCTION: joinStatus
# PURPOSE: Get join status of device
# DESCRIPTION: This function gets the join status of the device.  It takes a join type as input and outputs the join status to the console.
# INPUTS: $joinType (string) | example; AzureAdJoined, WorkplaceJoined, DomainJoined
# OUTPUTS: $status (bool) | example; True, False
function joinStatus()
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [string]$joinType
    )
    $dsregStatus = dsregcmd.exe /status
    $status = ($dsregStatus | Select-String $joinType).ToString().Split(":")[1].Trim()
    return $status
}

# FUNCTION: getAccountStatus
# PURPOSE: Get account status of specified local account
# DESCRIPTION: This function gets the account status of the specified local account.  It takes a local account as input and outputs the account status to the console.
# INPUTS: $localAccount (string) | example; Administrator
# OUTPUTS: $accountStatus, ""
function getAccountStatus()
{
    Param(
        [Parameter(Mandatory=$true)]
        [string]$localAccount
    )
    $accountStatus = (Get-LocalUser -Name $localAccount).Enabled
    log "Administrator account is $($accountStatus)."
    return $accountStatus
}

# FUNCTION: generatePassword
# PURPOSE: Generate a secure password for built in local admin account
# DESCRIPTION: This function generates a secure password for the built in local admin account when unjoining from domain.  It takes a length as input and outputs a secure password to the console.
# INPUTS: $length (int) | example; 12
# OUTPUTS: $securePassword (SecureString) | example; ************
function generatePassword {
    Param(
        [Parameter(Mandatory=$true)]
        [int]$length
    )
    $charSet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+[]{}|;:',<.>/?"
    $securePassword = New-Object -TypeName System.Security.SecureString
    1..$length | ForEach-Object {
        $random = $charSet[(Get-Random -Minimum 0 -Maximum $charSet.Length)]
        $securePassword.AppendChar($random)
    }
    return $securePassword
}

# FUNCTION: getSettingsJSON
# PURPOSE: Get settings from JSON file
# DESCRIPTION: This function gets the settings from the JSON file and creates a global variable to be used throughout migration process.  It takes a JSON file as input and outputs the settings to the console.
# INPUTS: $json (string) | example; settings.json
# OUTPUTS: $settings (object) | example; @{setting1=value1; setting2=value2}
function getSettingsJSON
{
    Param(
        [string]$json = "settings.json"
    )
    $global:settings = Get-Content -Path "$($PSScriptRoot)\$($json)" | ConvertFrom-Json
    return $settings
}

# FUNCTION: initializeScript
# PURPOSE: Initialize the migration script
# DESCRIPTION: This function initializes the script.  It takes an install tag, log name, log path, and local path as input and outputs the local path to the console.
# INPUTS: $installTag (bool), $logName (string), $logPath (string), $localPath (string)
# OUTPUTS: $localPath (string) | example; C:\ProgramData\IntuneMigration
function initializeScript()
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$false)]
        [bool]$installTag,
        [Parameter(Mandatory=$true)]
        [string]$logName,
        [string]$logPath = $settings.logPath,
        [string]$localPath = $settings.localPath
    )
    Start-Transcript -Path "$($logPath)\$($logName).log" -Verbose
    log "Initializing script..."
    if(!(Test-Path $localPath))
    {
        mkdir $localPath
        log "Created $($localPath)."
    }
    else 
    {
        log "$($localPath) already exists."
    }
    if($installTag -eq $true)
    {
        log "Install tag is $installTag.  Creating at $($localPath)\installed.tag..."
        New-Item -Path "$($localPath)\installed.tag" -ItemType "file" -Force
        log "Created $($localPath)\installed.tag."
    }
    else
    {
        log "Install tag is $installTag."
    }
    $global:localPath = $localPath
    $context = whoami
    log "Running as $($context)."
    log "Script initialized."
    return $localPath
}

# FUNCTION: copyPackageFiles
# PURPOSE: Copy package files to local path
# DESCRIPTION: This function copies the package files to the local path.  It takes a destination as input and outputs the package files to the console.
# INPUTS: $destination (string) | example; C:\ProgramData\IntuneMigration
# OUTPUTS: example; Copied file to destination
function copyPackageFiles()
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [string]$destination
    )
    log "Copying package files to $($destination)..."
    Copy-Item -Path "$($PSScriptRoot)\*" -Destination $destination -Recurse -Force
    $packageFiles = Get-ChildItem -Path $destination
    foreach($file in $packageFiles)
    {
        if($file)
        {
            log "Copied $file to $destination."
        }
        else
        {
            log "Failed to copy $file to $destination."
        }
    }
}

# FUNCTION: msGraphAuthenticate
# PURPOSE: Authenticate to Microsoft Graph
# DESCRIPTION: This function authenticates to Microsoft Graph.  It takes a tenant, client id, and client secret as input and outputs the headers to the console.
# INPUTS: $tenant (string), $clientId (string), $clientSecret (string)
# OUTPUTS: $headers (object) | example; @{Authorization=Bearer}
function msGraphAuthenticate()
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [string]$tenant,
        [Parameter(Mandatory=$true)]
        [string]$clientId,
        [Parameter(Mandatory=$true)]
        [string]$clientSecret
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

# FUNCTION: newDeviceObject
# PURPOSE: Create a new device object
# DESCRIPTION: This function creates a new device object.  It takes a serial number, hostname, disk size, free space, OS version, OS build, memory, azure ad joined, domain joined, bitlocker, group tag, and mdm as input and outputs the device object to the console.
# INPUTS: $serialNumber (string), $hostname (string), $diskSize (string), $freeSpace (string), $OSVersion (string), $OSBuild (string), $memory (string), $azureAdJoined (string), $domainJoined (string), $bitLocker (string), $groupTag (string), $mdm (bool)
# OUTPUTS: $pc (object) | example; @{serialNumber=serialNumber; hostname=hostname; diskSize=diskSize; freeSpace=freeSpace; OSVersion=OSVersion; OSBuild=OSBuild; memory=memory; azureAdJoined=azureAdJoined; domainJoined=domainJoined; bitLocker=bitLocker; groupTag=groupTag; mdm=mdm}
function newDeviceObject()
{
    Param(
        [string]$serialNumber = (Get-WmiObject -Class Win32_Bios).serialNumber,
        [string]$hostname = $env:COMPUTERNAME,
        [string]$diskSize = ([Math]::Round(((Get-WmiObject -Class Win32_LogicalDisk -Filter "DeviceID='C:'").Size / 1GB), 2)).ToString() + " GB",
        [string]$freeSpace = ([Math]::Round(((Get-WmiObject -Class Win32_LogicalDisk -Filter "DeviceID='C:'").FreeSpace / 1GB), 2)).ToString() + " GB",
        [string]$OSVersion = (Get-WmiObject -Class Win32_OperatingSystem).Version,
        [string]$OSBuild = (Get-WmiObject -Class Win32_OperatingSystem).BuildNumber,
        [string]$memory = ([Math]::Round(((Get-WmiObject -Class Win32_ComputerSystem).TotalPhysicalMemory / 1GB), 2)).ToString() + " GB",
        [string]$azureAdJoined = (dsregcmd.exe /status | Select-String "AzureAdJoined").ToString().Split(":")[1].Trim(),
        [string]$domainJoined = (dsregcmd.exe /status | Select-String "DomainJoined").ToString().Split(":")[1].Trim(),
        [string]$certPath = 'Cert:\LocalMachine\My',
        [string]$issuer = "Microsoft Intune MDM Device CA",
        [string]$bitLocker = (Get-BitLockerVolume -MountPoint "C:").ProtectionStatus,
        [string]$groupTag = $settings.groupTag,
        [bool]$mdm = $false
    )
    $cert = Get-ChildItem -Path $certPath | Where-Object {$_.Issuer -match $issuer}
    if($cert)
    {
        $mdm = $true
        $intuneObject = (Invoke-RestMethod -Method Get -Uri "https://graph.microsoft.com/beta/deviceManagement/managedDevices?`$filter=serialNumber eq '$serialNumber'" -Headers $headers)
        if(($intuneObject.'@odata.count') -eq 1)
        {
            $intuneId = $intuneObject.value.id
            $azureAdDeviceId = (Invoke-RestMethod -Method Get -Uri "https://graph.microsoft.com/beta/devices?`$filter=deviceId eq '$($intuneObject.value.azureAdDeviceId)'" -Headers $headers).value.id
            $autopilotObject = (Invoke-RestMethod -Method Get -Uri "https://graph.microsoft.com/beta/deviceManagement/windowsAutopilotDeviceIdentities?`$filter=contains(serialNumber,'$($serialNumber)')" -Headers $headers)
            if(($autopilotObject.'@odata.count') -eq 1)
            {
                $autopilotId = $autopilotObject.value.id
                if([string]::IsNullOrEmpty($groupTag))
                {
                    $groupTag = $autopilotObject.value.groupTag
                }
                else
                {
                    $groupTag = $groupTag
                }
            }
            else
            {
                $autopilotId = $null
            }
        }
        else 
        {
            $intuneId = $null
            $azureAdDeviceId = $null
        }
    }
    else
    {
        $intuneId = $null
        $azureAdDeviceId = $null
        $autopilotId = $null
    }
    if([string]::IsNullOrEmpty($groupTag))
    {
        $groupTag = $null
    }
    else
    {
        $groupTag = $groupTag
    }
    $pc = @{
        serialNumber = $serialNumber
        hostname = $hostname
        diskSize = $diskSize
        freeSpace = $freeSpace
        OSVersion = $OSVersion
        OSBuild = $OSBuild
        memory = $memory
        azureAdJoined = $azureAdJoined
        domainJoined = $domainJoined
        bitLocker = $bitLocker
        mdm = $mdm
        intuneId = $intuneId
        azureAdDeviceId = $azureAdDeviceId
        autopilotId = $autopilotId
        groupTag = $groupTag
    }
    return $pc
}

# FUNCTION: newUserObject
# PURPOSE: Create new user object
# DESCRIPTION: This function constructs a new user object.  It takes a domain join, user, SID, profile path, and SAM name as input and outputs the user object to the console.
# INPUTS: $domainJoin (string), $user (string), $SID (string), $profilePath (string), $SAMName (string)
# OUTPUTS: $userObject (object) | example; @{user=user; SID=SID; profilePath=profilePath; SAMName=SAMName; upn=upn}
function newUserObject()
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$false)]
        [string]$domainJoin,
        [Parameter(Mandatory=$false)]
        [string]$aadJoin,
        [string]$user = (Get-WmiObject -Class Win32_ComputerSystem | Select-Object UserName).UserName,
        [string]$SID = (New-Object System.Security.Principal.NTAccount($user)).Translate([System.Security.Principal.SecurityIdentifier]).Value,
        [string]$profilePath = (Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$($SID)" -Name "ProfileImagePath"),
        [string]$SAMName = ($user).Split("\")[1]
    )
    if($domainJoin -eq "NO")
    {
        $upn = (Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Microsoft\IdentityStore\Cache\$($SID)\IdentityCache\$($SID)" -Name "UserName")
        if($aadJoin -eq "YES")
        {
            $aadId = (Invoke-RestMethod -Method Get -Uri "https://graph.microsoft.com/beta/users/$($upn)" -Headers $headers).id
        }
        else
        {
            $aadId = $null
        }
    }
    else
    {
        $upn = $null
        $aadId = $null
    }
    $userObject = @{
        user = $user
        SID = $SID
        profilePath = $profilePath
        SAMName = $SAMName
        upn = $upn
        aadId = $aadId
    }
    return $userObject
}

# FUNCTION: getMigrateData
# PURPOSE: Get migration data from registry
# DESCRIPTION: This function gets the migration data from the registry.  It takes a registry path, key, and values as input and outputs the migration data to the console.
# INPUTS: $regPath (string), $regKey (string), $values (array) | example; ("OG_SID", "OG_profilePath", "OG_SAMName", "OG_upn", "NEW_SID", "OG_domainJoined")
# OUTPUTS: $migrateData (object) | example; @{OG_SID=OG_SID; OG_profilePath=OG_profilePath; OG_SAMName=OG_SAMName; OG_upn=OG_upn; NEW_SID=NEW_SID; OG_domainJoined=OG_domainJoined}
function getMigrateData()
{
    Param(
        [string]$regPath = $settings.regPath,
        [string]$regKey = "Registry::$regPath",
        [array]$values = @("OG_SID", "OG_profilePath", "OG_SAMName", "OG_upn", "NEW_SID", "OG_domainJoined", "NEW_SAMName")
    )
    $global:migrateData = @{}
    foreach ($value in $values) {
        $migrateData[$value] = (Get-ItemProperty -Path $regKey -Name $value -ErrorAction Ignore).$value
    }
    return $migrateData
}

# FUNCTION: setReg
# PURPOSE: Set registry value
# DESCRIPTION: This function sets a registry value.  It takes a path, name, int value, and string value as input and outputs the status to the console.
# INPUTS: $path (string), $name (string), $dValue (int), $sValue (string)
# OUTPUTS: example; Set name to value in path.
function setReg ()
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [string]$path,
        [Parameter(Mandatory=$true)]
        [string]$name,
        [Parameter(Mandatory=$false)]
        [int]$dValue,
        [Parameter(Mandatory=$false)]
        [string]$sValue
    )
    if($dValue)
    {
        $existingValue = (Get-ItemProperty -Path $path -Name $name -ErrorAction Ignore).$name
        if($existingValue -eq $dValue)
        {
            $status = "Value $name already set to $dValue in $path."
            log $status
        }
        else
        {
            reg.exe add $path /v $name /t REG_DWORD /d $dValue /f | Out-Host
            $status = "Set $name to $dValue in $path."
            log $status
        }
    }
    elseif($sValue)
    {
        $existingValue = (Get-ItemProperty -Path $path -Name $name -ErrorAction Ignore).$name
        if($existingValue -eq $sValue)
        {
            $status = "Value $name already set to $sValue in $path."
            log $status
        }
        else
        {
            reg.exe add $path /v $name /t REG_SZ /d $sValue /f | Out-Host
            $status = "Set $name to $sValue in $path."
            log $status
        }
    }
    else
    {
        $status = "No value to set in $path."
        log $status
    }
    return $status
}

# FUNCTION: getReg
# PURPOSE: Get registry value
# DESCRIPTION: This function gets a registry value.  It takes a path and name as input and outputs the value to the console.
# INPUTS: $path (string), $name (string)
# OUTPUTS: $value (string) | example; value
function getReg()
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [string]$path,
        [Parameter(Mandatory=$true)]
        [string[]]$name,
        [string]$key = "Registry::$path"
    )
    $value = (Get-ItemProperty -Path $key -Name $name -ErrorAction Ignore).$name
    return $value
}

# FUNCTION: setRegObject
# PURPOSE: Set original or new PC or user settings
# DESCRIPTION: This function sets the original or new PC or user settings.  It takes a name, value, and state as input and outputs the status to the console.
# INPUTS: $name (string), $value (string), $state (string) (OG, NEW)
# OUTPUTS: example; Set state_name to value in regPath.
function setRegObject()
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [string]$name,
        [Parameter(Mandatory=$true)]
        [string]$value,
        [Parameter(Mandatory=$true)]
        [string]$state,
        [string]$regPath = $settings.regPath
    )
    log "Setting $($state)_$($name) to $value in $regPath."
    if([string]::IsNullOrEmpty($value))
    {
        log "No value to set in $regPath."
    }
    else
    {
        setReg -path $regPath -name "$($state)_$($name)" -sValue $value
        log "Set $($state)_$($name) to $value in $regPath."
    }
}

# FUNCTION: removeMDMEnrollments
# PURPOSE: Remove MDM enrollments
# DESCRIPTION: This function removes MDM enrollments.  It takes an enrollment path as input and outputs the status to the console.
# INPUTS: $enrollmentPath (string) | example; HKLM:\SOFTWARE\Microsoft\Enrollments\
# OUTPUTS: example; Removed enrollmentPath

function removeMDMEnrollments()
{
    Param(
        [string]$enrollmentPath = "HKLM:\SOFTWARE\Microsoft\Enrollments\"
    )
    $enrollments = Get-ChildItem -Path $enrollmentPath
    foreach ($enrollment in $enrollments) {
        $object = Get-ItemProperty Registry::$enrollment
        $enrollPath = $enrollmentPath + $object.PSChildName
        $key = Get-ItemProperty -Path $enrollPath -Name "DiscoveryServiceFullURL"
        if($key)
        {
            log "Removing $($enrollPath)..."
            Remove-Item -Path $enrollPath -Recurse -Force
            $status = "Removed $($enrollPath)."
            log $status
        }
        else
        {
            $status = "No MDM enrollment found at $($enrollPath)."
            log $status
        }
    }
    $enrollID = $enrollPath.Split("\")[-1]
    $additionalPaths = @(
        "HKLM:\SOFTWARE\Microsoft\Enrollments\Status\$($enrollID)",
        "HKLM:\SOFTWARE\Microsoft\EnterpriseResourceManager\Tracked\$($enrollID)",
        "HKLM:\SOFTWARE\Microsoft\PolicyManager\AdmxInstalled\$($enrollID)",
        "HKLM:\SOFTWARE\Microsoft\PolicyManager\Providers\$($enrollID)",
        "HKLM:\SOFTWARE\Microsoft\Provinsioning\OMADM\Accounts\$($enrollID)",
        "HKLM:\SOFTWARE\Microsoft\Provisioning\OMADM\Logger\$($enrollID)",
        "HKLM:\SOFTWARE\Microsoft\Provisioning\OMADM\Sessions\$($enrollID)"
    )
    foreach($path in $additionalPaths)
    {
        if(Test-Path $path)
        {
            log "Removing $($path)..."
            Remove-Item -Path $path -Recurse -Force
            $status = "Removed $($path)."
            log $status
        }
        else
        {
            $status = "No MDM enrollment found at $($path)."
            log $status
        }
    }
}

# FUNCTION: removeMDMCertificate
# PURPOSE: Remove MDM certificate
# DESCRIPTION: This function removes the MDM certificate.  It takes a certificate path and issuer as input and outputs the status to the console.
# INPUTS: $certPath (string) | example; Cert:\LocalMachine\My, $issuer (string) | example; Microsoft Intune MDM Device CA
function removeMDMCertificate()
{
    Param(
        [string]$certPath = 'Cert:\LocalMachine\My',
        [string]$issuer = "Microsoft Intune MDM Device CA"
    )
    Get-ChildItem -Path $certPath | Where-Object {$_.Issuer -match $issuer} | Remove-Item -Force
    log "Removed MDM Certificate"
}

# FUNCTION: setTask
# PURPOSE: Set scheduled task
# DESCRIPTION: This function sets a scheduled task.  It takes a task name and local path as input and outputs the status to the console.
# INPUTS: $taskName (string), $localPath (string) | example; C:\ProgramData\IntuneMigration
# OUTPUTS: example; Set taskName
function setTask()
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [string[]]$taskName,
        [string]$localPath = $localPath
    )
    foreach($task in $taskName)
    {
        $taskPath = "$($localPath)\$($task).xml"
        log "Setting $($task)..."
        if(Test-Path $taskPath)
        {
            schtasks.exe /Create /TN $task /XML $taskPath
            log "Set $($task)."
        }
        else
        {
            log "Failed to set $($task)."
        }
    }
}

# FUNCTION: stopTask
# PURPOSE: Disable scheduled task
# DESCRIPTION: This function disables a scheduled task.  It takes a task name as input and outputs the status to the console.
# INPUTS: $taskName (string) | example; finalBoot
# OUTPUTS: example; Disabled taskName
function stopTask()
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [string[]]$taskName
    )
    foreach($task in $taskName)
    {
        log "Disabling $($task)..."
        Disable-ScheduledTask -TaskName $task
        log "Disabled $($task)."
    }
}

# FUNCTION: leaveAzureADJoin
# PURPOSE: Leave Azure AD Join
# DESCRIPTION: This function leaves Azure AD Join.  It takes a dsregcmd as input and outputs the status to the console.
# INPUTS: $dsregCmd (string) | example; dsregcmd.exe
function leaveAzureADJoin()
{
    Param(
        [string]$dsregCmd = "dsregcmd.exe"
    )
    log "Leaving Azure AD Join..."
    Start-Process -FilePath $dsregCmd -ArgumentList "/leave"
    log "Left Azure AD Join."
}

# FUNCTION: unjoinDomain
# PURPOSE: Unjoin from domain
# DESCRIPTION: This function unjoins from the domain.  It takes an unjoin account and hostname as input and outputs the status to the console.  If the account is disabled, it will enable the account and set the password.  If the account is enabled, it will set the password.
# INPUTS: $unjoinAccount (string), $hostname (string)
# OUTPUTS: example; Unjoined from domain
function unjoinDomain()
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [string]$unjoinAccount,
        [Parameter(Mandatory=$true)]
        [string]$hostname
    )
    log "Unjoining from domain..."
    $password = generatePassword -length 12
    log "Generated password for $unjoinAccount."
    log "Checking $($unjoinAccount) status..."
    [bool]$acctStatus = getAccountStatus -localAccount $unjoinAccount
    if($acctStatus -eq $false)
    {
        log "$($unjoinAccount) is disabled; setting password and enabling..."
        Set-LocalUser -Name $unjoinAccount -Password $password -PasswordNeverExpires $true
        Get-LocalUser -Name $unjoinAccount | Enable-LocalUser
        log "Enabled $($unjoinAccount) account and set password."
    }
    else 
    {
        log "$($unjoinAccount) is enabled; setting password..."
        Set-LocalUser -Name $unjoinAccount -Password $password -PasswordNeverExpires $true
        log "Set password for $($unjoinAccount) account."
    }
    $cred = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList ("$hostname\$unjoinAccount", $password)
    log "Unjoining from domain..."
    Remove-Computer -UnjoinDomainCredential $cred -PassThru -Force -Verbose
    log "Unjoined from domain."
}

# FUNCTION: deleteGraphObjects
# PURPOSE: Delete Intune and Autopilot objects
# DESCRIPTION: This function deletes the Intune and Autopilot objects from the source Azure environment.  It takes an Intune ID and Autopilot ID as input and outputs the status to the console.
function deleteGraphObjects()
{
    [CmdletBinding()]
    Param(
        [string]$intuneId,
        [string]$autopilotId
    )
    if(![string]::IsNullOrEmpty($intuneId))
    {
        log "Deleting Intune object..."
        Invoke-RestMethod -Method Delete -Uri "https://graph.microsoft.com/beta/deviceManagement/managedDevices/$($intuneId)" -Headers $headers
        log "Deleted Intune object."
    }
    else
    {
        log "No Intune object found."
    }
    if(![string]::IsNullOrEmpty($autopilotId))
    {
        log "Deleting Autopilot object..."
        Invoke-RestMethod -Method Delete -Uri "https://graph.microsoft.com/beta/deviceManagement/windowsAutopilotDeviceIdentities/$($autopilotId)" -Headers $headers
        log "Deleted Autopilot object."
    }
    else
    {
        log "No Autopilot object found."
    }
}

# FUNCTION: setAutoLogon
# PURPOSE: Set auto logon
# DESCRIPTION: This function sets the auto logon to the migration admin account.  It takes a migration admin, auto logon path, auto logon name, auto logon value, default user name, and default password as input and outputs the status to the console.
function setAutoLogon()
{
    Param(
        [string]$migrationAdmin = "MigrationInProgress",
        [string]$autoLogonPath = "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
        [string]$autoLogonName = "AutoAdminLogon",
        [string]$autoLogonValue = 1,
        [string]$defaultUserName = "DefaultUserName",
        [string]$defaultPW = "DefaultPassword"
    )
    log "Create migration admin account..."
    $migrationPassword = generatePassword
    New-LocalUser -Name $migrationAdmin -Password $migrationPassword
    Add-LocalGroupMember -Group "Administrators" -Member $migrationAdmin
    log "Migration admin account created: $($migrationAdmin)."

    log "Setting auto logon..."
    reg.exe add $autoLogonPath /v $autoLogonName /t REG_SZ /d $autoLogonValue /f | Out-Host
    reg.exe add $autoLogonPath /v $defaultUserName /t REG_SZ /d $migrationAdmin /f | Out-Host
    reg.exe add $autoLogonPath /v $defaultPW /t REG_SZ /d "@Password*123" /f | Out-Host
    log "Set auto logon to $($migrationAdmin)."
}

# FUNCTION: removeAADBrokerPlugin
# PURPOSE: Remove AAD Broker Plugin
# DESCRIPTION: This function removes the AAD Broker Plugin from the original profile.  It takes an original profile path and AAD Broker Plugin as input and outputs the status to the console.
# INPUTS: $originalProfilePath (string), $aadBrokerPlugin (string) | example; Microsoft.AAD.BrokerPlugin_*
# OUTPUTS: example; Removed AAD Broker Plugin from originalProfilePath.
function removeAADBrokerPlugin()
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [string]$originalProfilePath,
        [string]$aadBrokerPlugin = "Microsoft.AAD.BrokerPlugin_*"
    )
    log "Removing AAD Broker Plugin from original profile..."
    $aadBrokerPath = (Get-ChildItem -Path "$($originalProfilePath)\AppData\Local\Packages" -Recurse | Where-Object {$_.Name -match $aadBrokerPlugin} | Select-Object FullName).FullName
    if([string]::IsNullOrEmpty($aadBrokerPath))
    {
        $status = "No AAD Broker Plugin found in $($originalProfilePath)."
        log $status
    }
    else 
    {
        Remove-Item -Path $aadBrokerPath -Recurse -Force -ErrorAction SilentlyContinue
        $status = "Removed AAD Broker Plugin from $($originalProfilePath)."
        log $status
    }
    return $status
}

# FUNCTION: deleteUserProfile
# PURPOSE: Delete user profile
# DESCRIPTION: This function deletes the new user profile.  It takes a user SID as input and outputs the status to the console.
# INPUTS: $userSID (string)
# OUTPUTS: example; Deleted user profile
function deleteUserProfile()
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [string]$userSID
    )
    log "Deleting new user profile..."
    $userProfile = Get-CimInstance -ClassName Win32_UserProfile | Where-Object {$_.SID -eq $userSID}
    Remove-CimInstance -InputObject $userProfile -Verbose | Out-Null
    log "$($userSID) user profile deleted"
}

# FUNCTION: changeProfileOwner
# PURPOSE: Change profile owner
# DESCRIPTION: This function changes the ownership of the original profile to the new user.  It takes an original user SID and new user SID as input and outputs the status to the console.
# INPUTS: $originalUserSID (string), $newUserSID (string)
# OUTPUTS: example; Changed ownership of original profile to newUserSID
function changeProfileOwner()
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [string]$originalUserSID,
        [Parameter(Mandatory=$true)]
        [string]$newUserSID
    )
    log "Changing ownership of original profile..."
    $originalProfile = Get-CimInstance -ClassName Win32_UserProfile | Where-Object {$_.SID -eq $originalUserSID}
    $changeArguments = @{
        NewOwnerSID = $newUserSID
        Flags = 0
    }
    $originalProfile | Invoke-CimMethod -MethodName ChangeOwner -Arguments $changeArguments
    log "Changed ownership of original profile to $($newUserSID)."
}

# FUNCTION: cleanupLogonCache
# PURPOSE: Cleanup identity store cache
# DESCRIPTION: This function cleans up the identity store cache.  It takes an old username and logon cache as input and outputs the status to the console.
# INPUTS: $oldUserName (string), $logonCache (string) | example; HKLM:\SOFTWARE\Microsoft\IdentityStore\LogonCache
# OUTPUTS: example; Registry key deleted: logonCache\GUID\subKey\subFolder
function cleanupLogonCache()
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [string]$oldUserName,
        [string]$logonCache = "HKLM:\SOFTWARE\Microsoft\IdentityStore\LogonCache"
        
    )
    log "Cleaning up identity store cache..."
    $logonCacheGUID = (Get-ChildItem -Path $logonCache | Select-Object Name | Split-Path -Leaf).trim('{}')
    foreach($GUID in $logonCacheGUID)
    {
        $subKeys = Get-ChildItem -Path "$logonCache\$GUID" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name | Split-Path -Leaf
        if(!($subKeys))
        {
            log "No subkeys found for $GUID"
            continue
        }
        else
        {
            $subKeys = $subKeys.trim('{}')
            foreach($subKey in $subKeys)
            {
                if($subKey -eq "Name2Sid" -or $subKey -eq "SAM_Name" -or $subKey -eq "Sid2Name")
                {
                    $subFolders = Get-ChildItem -Path "$logonCache\$GUID\$subKey" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name | Split-Path -Leaf
                    if(!($subFolders))
                    {
                        log "Error - no sub folders found for $subKey"
                        continue
                    }
                    else
                    {
                        $subFolders = $subFolders.trim('{}')
                        foreach($subFolder in $subFolders)
                        {
                            $cacheUsername = Get-ItemPropertyValue -Path "$logonCache\$GUID\$subKey\$subFolder" -Name "IdentityName" -ErrorAction SilentlyContinue
                            if($cacheUsername -eq $oldUserName)
                            {
                                Remove-Item -Path "$logonCache\$GUID\$subKey\$subFolder" -Recurse -Force
                                log "Registry key deleted: $logonCache\$GUID\$subKey\$subFolder"
                                continue                                       
                            }
                            else
                            {
                                log "No registry key found for $oldUserName"
                                continue
                            }
                        }
                    }
                }
            }
        }
    }
}

# FUNCTION: cleanupIdentityStore
# PURPOSE: Cleanup identity store cache
# DESCRIPTION: This function cleans up the identity store cache.  It takes an old username and identity store cache as input and outputs the status to the console.
# INPUTS: $oldUserName (string), $idCache (string) | example; HKLM:\SOFTWARE\Microsoft\IdentityStore\Cache
# OUTPUTS: example; Registry path deleted: idCache\key\subKey\subFolder
function cleanupIdentityStore()
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [string]$oldUserName,
        [string]$idCache = "HKLM:\Software\Microsoft\IdentityStore\Cache"
    )
    log "Cleaning up identity store cache..."
    $idCacheKeys = (Get-ChildItem -Path $idCache | Select-Object Name | Split-Path -Leaf).trim('{}')
    foreach($key in $idCacheKeys)
    {
        $subKeys = Get-ChildItem -Path "$idCache\$key" -ErrorAction SilentlyContinue | Select-Object Name | Split-Path -Leaf
        if(!($subKeys))
        {
            log "No keys listed under '$idCache\$key' - skipping..."
            continue
        }
        else
        {
            $subKeys = $subKeys.trim('{}')
            foreach($subKey in $subKeys)
            {
                $subFolders = Get-ChildItem -Path "$idCache\$key\$subKey" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name | Split-Path -Leaf
                if(!($subFolders))
                {
                    log "No subfolders detected for $subkey- skipping..."
                    continue
                }
                else
                {
                    $subFolders = $subFolders.trim('{}')
                    foreach($subFolder in $subFolders)
                    {
                        $idCacheUsername = Get-ItemPropertyValue -Path "$idCache\$key\$subKey\$subFolder" -Name "UserName" -ErrorAction SilentlyContinue
                        if($idCacheUsername -eq $oldUserName)
                        {
                            Remove-Item -Path "$idCache\$key\$subKey\$subFolder" -Recurse -Force
                            log "Registry path deleted: $idCache\$key\$subKey\$subFolder"
                            continue
                        }
                        else
                        {
                            log "No registry path found for $oldUserName"
                            continue
                        }
                    }
                }
            }
        }
    }
}

# FUNCTION: updateSamNameLogonCache
# PURPOSE: Update SamName in LogonCache registry
# DESCRIPTION: This function updates the SamName in the LogonCache registry.  It takes a new user SID, original user, new user, and logon cache as input and outputs the status to the console.
# INPUTS: $newUserSID (string), $originalUser (string), $newUser (string), $logonCache (string) | example; HKLM:\SOFTWARE\Microsoft\IdentityStore\LogonCache
# OUTPUTS: example; Attempted to update SAMName value (in Name2Sid registry folder) to 'originalUser'.
function updateSamNameLogonCache()
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [string]$newUserSID,
        [Parameter(Mandatory=$true)]
        [string]$originalUser,
        [Parameter(Mandatory=$true)]
        [string]$newUser,
        [string]$logonCache = "HKLM:\SOFTWARE\Microsoft\IdentityStore\LogonCache"
    )

    if($newUser -like "$($originalUser)_*")
    {
        log "New user is $newUser, which is the same as $originalUser with _##### appended to the end. Removing appended characters on SamName in LogonCache registry..."

        $logonCacheGUID = (Get-ChildItem -Path $logonCache | Select-Object Name | Split-Path -Leaf).trim('{}')
        foreach($GUID in $logonCacheGUID)
        {
            $subKeys = Get-ChildItem -Path "$logonCache\$GUID" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name | Split-Path -Leaf
            if(!($subKeys))
            {
                log "No subkeys found for $GUID"
                continue
            }
            else
            {
                $subKeys = $subKeys.trim('{}')
                foreach($subKey in $subKeys)
                {
                    if($subKey -eq "Name2Sid")
                    {
                        $subFolders = Get-ChildItem -Path "$logonCache\$GUID\$subKey" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name | Split-Path -Leaf
                        if(!($subFolders))
                        {
                            log "Error - no sub folders found for $subKey"
                            continue
                        }
                        else
                        {
                            $subFolders = $subFolders.trim('{}')
                            foreach($subFolder in $subFolders)
                            {
                                $detectedUserSID = Get-ItemProperty -Path "$logonCache\$GUID\$subKey\$subFolder" | Select-Object -ExpandProperty "Sid" -ErrorAction SilentlyContinue
                                if($detectedUserSID -eq $newUserSID)
                                {
                                    Set-ItemProperty -Path "$logonCache\$GUID\$subKey\$subFolder" -Name "SAMName" -Value $originalUser -Force
                                    log "Attempted to update SAMName value (in Name2Sid registry folder) to '$($originalUser)'."
                                    continue                                       
                                }
                                else
                                {
                                    log "Detected Sid '$detectedUserSID' is for different user - skipping Sid in Name2Sid registry folder..."
                                }
                            }
                        }
                    }
                    elseif($subKey -eq "SAM_Name")
                    {
                        $subFolders = Get-ChildItem -Path "$logonCache\$GUID\$subKey" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name | Split-Path -Leaf
                        if(!($subFolders))
                        {
                            log "Error - no sub folders found for $subKey"
                            continue
                        }
                        else
                        {
                            $subFolders = $subFolders.trim('{}')
                            foreach($subFolder in $subFolders)
                            {
                                $detectedUserSID = Get-ItemProperty -Path "$logonCache\$GUID\$subKey\$subFolder" | Select-Object -ExpandProperty "Sid" -ErrorAction SilentlyContinue
                                if($detectedUserSID -eq $newUserSID)
                                {
                                    Rename-Item "$logonCache\$GUID\$subKey\$subFolder" -NewName $originalUser -Force
                                    log "Attempted to update SAM_Name key name (in SAM_Name registry folder) to '$($originalUser)'."
                                    continue                                       
                                }
                                else
                                {
                                    log "Skipping different user in SAM_Name registry folder (User: $subFolder, SID: $detectedUserSID)..."
                                }
                            }
                        }
                    }
                    elseif($subKey -eq "Sid2Name")
                    {
                        $subFolders = Get-ChildItem -Path "$logonCache\$GUID\$subKey" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name | Split-Path -Leaf
                        if(!($subFolders))
                        {
                            log "Error - no sub folders found for $subKey"
                            continue
                        }
                        else
                        {
                            $subFolders = $subFolders.trim('{}')
                            foreach($subFolder in $subFolders)
                            {
                                if($subFolder -eq $newUserSID)
                                {
                                    Set-ItemProperty -Path "$logonCache\$GUID\$subKey\$subFolder" -Name "SAMName" -Value $originalUser -Force
                                    log "Attempted to update SAM_Name value (in Sid2Name registry folder) to '$($originalUser)'."
                                    continue                                       
                                }
                                else
                                {
                                    log "Skipping different user SID ($subFolder) in Sid2Name registry folder..."
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    else
    {
        log "New username is $newUser, which does not match older username ($originalUser) with _##### appended to end. SamName LogonCache registry will not be updated."
    }
}

# FUNCTION: updateSamNameIdentityStore
# PURPOSE: Update SamName in IdentityStore registry
# DESCRIPTION: This function updates the SamName in the IdentityStore registry.  It takes a new user SID, new user, and identity store cache as input and outputs the status to the console.
# INPUTS: $newUserSID (string), $newUser (string), $idCache (string) | example; HKLM:\SOFTWARE\Microsoft\IdentityStore\Cache
# OUTPUTS: example; Attempted to update SAMName value to newUser in idCache\key\subKey\subFolder
function updateSamNameIdentityStore()
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [string]$targetSAMName,
        [Parameter(Mandatory=$true)]
        [string]$newUserSID,
        [string]$idCache = "HKLM:\Software\Microsoft\IdentityStore\Cache"
    )
    log "Cleaning up identity store cache..."
    $idCacheKeys = (Get-ChildItem -Path $idCache | Select-Object Name | Split-Path -Leaf).trim('{}')
    foreach($key in $idCacheKeys)
    {
        $subKeys = Get-ChildItem -Path "$idCache\$key" -ErrorAction SilentlyContinue | Select-Object Name | Split-Path -Leaf
        if(!($subKeys))
        {
            log "No keys listed under '$idCache\$key' - skipping..."
            continue
        }
        else
        {
            $subKeys = $subKeys.trim('{}')
            foreach($subKey in $subKeys)
            {
                $subFolders = Get-ChildItem -Path "$idCache\$key\$subKey" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name | Split-Path -Leaf
                if(!($subFolders))
                {
                    log "No subfolders detected for $subkey- skipping..."
                    continue
                }
                else
                {
                    $subFolders = $subFolders.trim('{}')
                    foreach($subFolder in $subFolders)
                    {
                        if($subFolder -eq $newUserSID)
                        {
                            Set-ItemProperty -Path "$idCache\$key\$subKey\$subFolder" -Name "SAMName" -Value $targetSAMName -Force
                            log "Attempted to update SAMName value to $targetSAMName."
                        }
                    }
                }
            }
        }
    }
}

# FUNCTION: setPrimaryUser
# PURPOSE: Set primary user for Intune device
# DESCRIPTION: This function sets the primary user for the Intune device.  It takes an Intune ID and user ID as input and outputs the status to the console.
# INPUTS: $intuneID (string), $userID (string)
# OUTPUTS: example; Primary user for intuneID set to userID
function setPrimaryUser()
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [string]$intuneID,
        [Parameter(Mandatory=$true)]
        [string]$userID,
        [string]$userUri = "https://graph.microsoft.com/beta/users/$userID",
        [string]$intuneDeviceRefUri = "https://graph.microsoft.com/beta/deviceManagement/managedDevices/$intuneID/users/`$ref"
    )
    log "Setting primary user..."
    $id = "@odata.id"
    $JSON = @{ $id="$userUri" } | ConvertTo-Json

    Invoke-RestMethod -Uri $intuneDeviceRefUri -Headers $headers -Method Post -Body $JSON
    log "Primary user for $intuneID set to $userID"
}

# FUNCTION: setGroupTag
# PURPOSE: Set group tag for Intune device
# DESCRIPTION: This function sets the group tag for the Intune device.  It takes a group tag and Azure AD device ID as input and outputs the status to the console.
# INPUTS: $groupTag (string), $azureAdDeviceId (string)
# OUTPUTS: example; Group tag set to groupTag
function setGroupTag()
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [string]$groupTag,
        [Parameter(Mandatory=$true)]
        [string]$azureAdDeviceId
    )
    log "Setting group tag..."
    $aadObject = Invoke-RestMethod -Method Get -Uri "https://graph.microsoft.com/devices?`$filter=deviceId eq '$($azureAdDeviceId)'" -Headers $headers
    $physicalIds = $aadObject.value.physicalIds
    $deviceId = $aadObject.value.id
    $groupTag = "[OrderID]:$($groupTag)"
    $physicalIds += $groupTag
    $body = @{
        physicalIds = $physicalIds
    } | ConvertTo-Json
    Invoke-RestMethod -Method Patch -Uri "https://graph.microsoft.com/devices/$($deviceId)" -Headers $headers -Body $body
    log "Group tag set to $groupTag"
}

# FUNCTION: migrateBitlockerKey
# PURPOSE: Migrate Bitlocker key
# DESCRIPTION: This function migrates the Bitlocker key to Azure AD.  It takes a mount point and Bitlocker volume as input and outputs the status to the console.
# INPUTS: $mountPoint (string), $bitLockerVolume (PSCustomObject), $keyProtectorId (string)
# OUTPUTS: example; Bitlocker key migrated
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

# FUNCTION: decryptDrive
# PURPOSE: Decrypt drive
# DESCRIPTION: This function decrypts the drive.  It takes a mount point as input and outputs the status to the console.
# INPUTS: $mountPoint (string)
# OUTPUTS: example; Drive mountPoint decrypted
function decryptDrive()
{
    Param(
        [string]$mountPoint = "C:"
    )
    Disable-BitLocker -MountPoint $mountPoint
    log "Drive $mountPoint decrypted"
}

# FUNCTION: resetLockScreenCaption
# PURPOSE: Reset lock screen caption
# DESCRIPTION: This function resets the lock screen caption.  It takes a lock screen registry path, lock screen caption, and lock screen text as input and outputs the status to the console.
# INPUTS: $lockScreenRegPath (string), $lockScreenCaption (string), $lockScreenText (string)
# OUTPUTS: example; Lock screen caption reset
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

# FUNCTION: installModules
# PURPOSE: Install PowerShell modules
# DESCRIPTION: This function installs the required PowerShell modules.  It takes a list of modules as input and outputs the status to the console.
# INPUTS: $modules (string[])
# OUTPUTS: example; Installed module
function installModules()
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [string[]]$modules
    )
    log "Checking for NuGet package provider..."
    $installedNuGet = Get-PackageProvider -Name NuGet -ListAvailable -ErrorAction SilentlyContinue
    if(-not($installedNuGet))
    {
        Install-PackageProvider -Name NuGet -Confirm:$false -Force
        log "NuGet package provider installed successfully."
    }
    else
    {
        log "NuGet package provider already installed."
    }
    foreach($module in $modules)
    {
        log "Checking for $module..."
        $installedModule = Get-Module -Name $module -ErrorAction SilentlyContinue
        if(-not($installedModule))
        {
            Install-Module -Name $module -Confirm:$false -Force
            Import-Module $module
            log "$module installed successfully."
        }
        else
        {
            Import-Module $module
            log "$module already installed."
        }
    }
}

# FUNCTION: autopilotAuthenticate
# PURPOSE: Authenticate to Microsoft Graph for Autopilot
# DESCRIPTION: This function authenticates to Microsoft Graph for Autopilot.  It takes a tenant ID, client ID, client secret, and tenant name as input and outputs the status to the console.
# INPUTS: $tenantId (string), $clientId (string), $clientSecret (string), $tenantName (string)
# OUTPUTS: example; Authenticated to Microsoft Graph for Autopilot.
function autopilotAuthenticate()
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [string]$tenantId,
        [Parameter(Mandatory=$true)]
        [string]$clientId,
        [Parameter(Mandatory=$true)]
        [string]$clientSecret,
        [Parameter(Mandatory=$true)]
        [string]$tenantName
    )
    log "Authentication to Microsoft Graph for Autopilot..."
    $clientSecureSecret = ConvertTo-SecureString -String $clientSecret -AsPlainText -Force
    $clientSecretCredential = New-Object -TypeName "System.Management.Automation.PSCredential" -ArgumentList $clientId, $clientSecureSecret
    Connect-MgGraph -TenantId $tenantId -ClientSecretCredential $clientSecretCredential
    log "Authenticated to Microsoft Graph for Autopilot."
}

function autopilotRegister()
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [string]$regPath,
        [string]$regKey = "Registry::$regPath",
        [string]$serialNumber = (Get-WmiObject -Class Win32_BIOS).SerialNumber,
        [string]$hardwareIdentifier = ((Get-WmiObject -Namespace root/cimv2/mdm/dmmap -Class MDM_DevDetail_Ext01 -Filter "InstanceID='Ext' AND ParentID='./DevDetail'").DeviceHardwareData),
        [string]$groupTag = (Get-ItemProperty -Path $regKey -Name "GroupTag").GroupTag
    )
    log "Registering device with Autopilot..."
    if([string]::IsNullOrEmpty($groupTag))
    {
        Add-AutopilotImportedDevice -serialNumber $serialNumber -hardwareIdentifier $hardwareIdentifier
        log "Device registered with Autopilot - NO GROUP TAG."
    }
    else
    {
        Add-AutopilotImportedDevice -serialNumber $serialNumber -hardwareIdentifier $hardwareIdentifier -groupTag $groupTag
        log "Device registered with Autopilot - GROUP TAG: $groupTag."
    }
}