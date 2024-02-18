
# Functions that wil be used throughout the device migration process.

# log function
# DESCRIPTION: Logs a message to the log file and appends the time and date.
# USE: log "This is a log message."
# PARAMETER: message - The message to be logged.
# RETURN: None
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

# get json settings
# DESCRIPTION: Gets the settings from the settings.json file and stores them in a global variable.
# USE: getSettingsJSON
# RETURN: $settings - The settings from the settings.json file.
function getSettingsJSON()
{
    param(
        [string]$json = "settings.json"
    )
    $global:settings = Get-Content -Path "$($PSScriptRoot)\$($json)" | ConvertFrom-Json
    log "Settings loaded from settings.json"
    return $settings
}

# initialize script
# DESCRIPTION: Initializes the script by creating the log directory and starting the transcript.
# USE: initializeScript -logName "scriptName" -installFlag $true
# PARAMETER: logPath - The path to the log directory.
# PARAMETER: logName - The name of the log file.
# PARAMETER: localPath - The path to the local directory.
# RETURN: $localPath - The path to the local directory.
function initializeScript()
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [string]$logName,
        [Parameter(Mandatory=$false)]
        [bool]$installFlag = $false,
        [string]$logPath = $settings.logPath,
        [string]$localPath = $settings.localPath
    )
    Start-Transcript -Path "$($logPath)\$($logName).log" -Verbose
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
    if($installFlag -eq $true)
    {
        log "Install flag set to $installFlag"
        New-Item -Path "$($localPath)\$logName.tag" -ItemType File -Force
    }
    $context = whoami
    log "Running as $($context)"
    $global:localPath = $localPath
}

# copy package files
# DESCRIPTION: Copies the package files from the source directory to the destination directory of local path.
# USE: copyPackageFiles
# RETURN: None
function copyPackageFiles()
{
    Param(
        [string]$destination = $localPath
    )
    Copy-Item -Path "$($PSScriptRoot)\*" -Recurse -Destination $destination -Force
    log "Package files copied to $destination"
}

# authenticate to msGraph
# DESCRIPTION: Authenticates to Microsoft Graph using the client id and client secret from the settings.json file.  Sets global headers for use in other functions.
# USE: authenticateToMsGraph
# RETURN: None
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

# get account status
# DESCRIPTION: Gets the account status of the local user on the device.
# USE: getAccountStatus -userName "username"
# PARAMETER: userName - The username of the local user.
# RETURN: $status - The account status of the local user.
function getAccountStatus()
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [string]$userName
    )
    $status = (Get-LocalUser -Name $userName).Enabled
    log "$userName account is $($status)."
    return $status
}

# generate random admin password
# DESCRIPTION: Generates a random password for the local administrator account.
# USE: generateRandomAdminPassword -length 12
# PARAMETER: length - The length of the password to generate.
# RETURN: $password - The generated password [secureString].
function generatePassword()
{
    [CmdletBinding()]
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
    log "Password generated"
    return $securePassword
}

# exit function
# DESCRIPTION: Exits the script and stops the transcript.  Restores the password login provider.
# USE: exitScript -exitCode 1
# PARAMETER: exitCode - The exit code to return.
# RETURN: None
function exitScript()
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [int]$exitCode,
        [Parameter(Mandatory=$false)]
        [string]$functionName,
        [string]$localPath = $localPath
    )
    if($exitCode -eq 1)
    {
        log "Function $functionName failed with critical error.  Exiting script with exit code $exitCode."
        log "Removing $localPath and rebooting device. Please login with admin credentials and check the log file for more information."
        Remove-Item -Path $localPath -Recurse -Force
        reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers\{60b78e88-ead8-445c-9cfd-0b87f74ea6cd}" /v "Disabled" /t REG_DWORD /d 0 /f | Out-Host
        log "Enabled logon provider"
        log "rebooting device"
        shutdown -r -t 00
        Stop-Transcript
        Exit -1
    }
}

# get intune enrollment status
# DESCRIPTION: Gets the Intune enrollment status of the device.
# USE: getIntuneEnrollmentStatus
# RETURN: $status - The Intune enrollment status of the device.
function getIntuneStatus()
{
    Param(
        [string]$certPath = 'Cert:\LocalMachine\My',
        [string]$issuer = "Microsoft Intune MDM Device CA"
    )
    $cert = (Get-ChildItem -Path $certPath | Where-Object { $_.Issuer -eq $issuer })
    $enrolled = $false
    if($cert)
    {
        $enrolled = $true
        return $enrolled
    }
    else
    {
        return $enrolled
    }
}

# construct device object
# DESCRIPTION: Constructs a device object with the device information.
# USE: constructDeviceObject -deviceName "hostname" -serialNumber "serialNumber" -OSVersion "OSVersion" -OSBuild "OSBuild" -memory "memory" -bitlockerStatus "bitlockerStatus" -azureADJoined "azureADJoined" -domainJoined "domainJoined" -intuneEnrolled "intuneEnrolled" -intuneDeviceId "intuneDeviceId" -aadDeviceId "aadDeviceId" -autopilotDeviceId "autopilotDeviceId" -groupTag "groupTag"
# PARAMETER: deviceName - The hostname of the device.
# PARAMETER: serialNumber - The serial number of the device.
# PARAMETER: OSVersion - The OS version of the device.
# PARAMETER: OSBuild - The OS build of the device.
# PARAMETER: memory - The memory of the device.
# PARAMETER: bitlockerStatus - The bitlocker status of the device.
# PARAMETER: azureADJoined - The Azure AD join status of the device.
# PARAMETER: domainJoined - The domain join status of the device.
# PARAMETER: intuneEnrolled - The Intune enrollment status of the device.
# PARAMETER: intuneDeviceId - The Intune device id of the device.
# PARAMETER: aadDeviceId - The Azure AD device id of the device.
# PARAMETER: autopilotDeviceId - The Autopilot device id of the device.
# PARAMETER: groupTag - The group tag of the device.
# RETURN: $device - The device object.
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
        [bool]$mdm = $false
    )
    $cert = Get-ChildItem -Path $certPath | Where-Object {$_.Issuer -match $issuer}
    if($cert)
    {
        $mdm = $true
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
    }
    return $pc
}

$computer4 = newDeviceObject

# get device graph info
# DESCRIPTION: Gets the device information for Azure and Intune if the device is enrolled.
# USE: getIntuneDeviceInfo -serialNumber "serialNumber"
# PARAMETER: serialNumber - The serial number of the device.
# RETURN: $device - The device object.
function getDeviceGraphInfo()
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [string]$serialNumber,
        [Parameter(Mandatory=$true)]
        [string]$device
    )
    
}