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
    [CmdletBinding()]
    Param(
        [string]$json = "settings.json"
    )
    $global:settings = Get-Content -Path "$($PSScriptRoot)\$($json)" | ConvertFrom-Json
    return $settings
}

function initializeScript()
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true)]
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