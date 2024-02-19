<# AUTOPILOTREGISTRATION.PS1
Synopsis
AutopilotRegistration.ps1 is the last script in the device migration process.
DESCRIPTION
This script is used to register the PC in the destination tenant Autopilot environment.  Will use a group tag if available.
USE
.\AutopilotRegistration.ps1
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

# error function
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
    Param(
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
        [string]$logName = "autopilotRegistration.log",
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

# disable scheduled task
function disableAutopilotRegistrationTask()
{
    Param(
        [string]$taskName = "AutopilotRegistration"
    )
    Disable-ScheduledTask -TaskName $taskName
    log "AutopilotRegistration task disabled"    
}

# install modules
function installModules()
{
    Param(
        [string]$nuget = "NuGet",
        [string[]]$modules = @(
            "Microsoft.Graph.Intune",
            "WindowsAutoPilotIntune"
        )
    )
    log "Checking for NuGet..."
    $installedNuGet = Get-PackageProvider -Name $nuget -ListAvailable -ErrorAction SilentlyContinue
    if(-not($installedNuGet))
    {      
        Install-PackageProvider -Name $nuget -Confirm:$false -Force
        log "NuGet successfully installed"    
    }
    else
    {
        log "NuGet already installed"
    }
    log "Checking for required modules..."
    foreach($module in $modules)
    {
        log "Checking for $module..."
        $installedModule = Get-Module -Name $module -ErrorAction SilentlyContinue
        if(-not($installedModule))
        {
            Install-Module -Name $module -Confirm:$false -Force
            Import-Module $module
            log "$module successfully installed"
        }
        else
        {
            Import-Module $module
            log "$module already installed"
        }
    }
}

# authenticate ms graph
function msGraphAuthenticate()
{
    Param(
        [string]$tenant = $settings.targetTenant.tenantName,
        [string]$clientId = $settings.targetTenant.clientId,
        [string]$clientSecret = $settings.targetTenant.clientSecret,
        [string]$tenantId = $settings.targetTenant.tenantId
    )
    log "Authenticating to Microsoft Graph..."
    $clientSecureSecret = ConvertTo-SecureString $clientSecret -AsPlainText -Force
    $clientSecretCredential = New-Object System.Management.Automation.PSCredential -ArgumentList $clientId,$clientSecureSecret
    Connect-MgGraph -TenantId $tenantId -ClientSecretCredential $clientSecretCredential
    log "Authenticated to  $($tenant) Microsoft Graph"
}

# get autopilot info
function getAutopilotInfo()
{
    Param(
        [string]$serialNumber = (Get-WmiObject -Class Win32_BIOS).SerialNumber,
        [string]$hardwareIdentifier = ((Get-WmiObject -Namespace root/cimv2/mdm/dmmap -Class MDM_DevDetail_Ext01 -Filter "InstanceID='Ext' AND ParentID='./DevDetail'").DeviceHardwareData)
    )
    log "Collecting Autopilot device info..."
    if([string]::IsNullOrWhiteSpace($serialNumber)) 
    { 
        $serialNumber = $env:COMPUTERNAME 
    }
    $global:autopilotInfo = @{
        serialNumber = $serialNumber
        hardwareIdentifier = $hardwareIdentifier
    }
    log "Autopilot device info collected"
    return $autopilotInfo    
}

# register autopilot device
function autopilotRegister()
{
    Param(
        [string]$regPath = $settings.regPath,
        [string]$regKey = "Registry::$regPath",
        [string]$serialNumber = $autopilotInfo.serialNumber,
        [string]$hardwareIdentifier = $autopilotInfo.hardwareIdentifier,
        [string]$groupTag = (Get-ItemPropertyValue -Path $regKey -Name "GroupTag")
    )
    log "Registering Autopilot device..."
    if([string]::IsNullOrWhiteSpace($groupTag))
    {
        Add-AutopilotImportedDevice -serialNumber $serialNumber -hardwareIdentifier $hardwareIdentifier
        log "Autopilot device registered"
    }
    else 
    {
        Add-AutopilotImportedDevice -serialNumber $serialNumber -hardwareIdentifier $hardwareIdentifier -groupTag $groupTag
        log "Autopilot device registered with group tag $groupTag"
    }
}

# END SCRIPT FUNCTIONS

# START SCRIPT

# get settings
log "Running FUNCTION: getSettingsJSON..."
try 
{
    getSettingsJSON
    log "FUNCTION: getSettingsJSON completed"
}
catch 
{
    $message = $_.Exception.Message
    log "FUNCTION: getSettingsJSON failed: $message"
    log "Exiting script"
    exitScript -exitCode 2 -functionName "getSettingsJSON"
}

# initialize script
log "Running FUNCTION: initializeScript..."
try 
{
    initializeScript
    log "FUNCTION: initializeScript completed"
}
catch 
{
    $message = $_.Exception.Message
    log "FUNCTION: initializeScript failed: $message"
    log "Exiting script"
    exitScript -exitCode 2 -functionName "initializeScript"
}

# disable scheduled task
log "Running FUNCTION: disableAutopilotRegistrationTask..."
try 
{
    disableAutopilotRegistrationTask
    log "FUNCTION: disableAutopilotRegistrationTask completed"
}
catch 
{
    $message = $_.Exception.Message
    log "FUNCTION: disableAutopilotRegistrationTask failed: $message"
    log "Exiting script"
    exitScript -exitCode 2 -functionName "disableAutopilotRegistrationTask"
}

# install modules
log "Running FUNCTION: installModules..."
try 
{
    installModules
    log "FUNCTION: installModules completed"
}
catch 
{
    $message = $_.Exception.Message
    log "FUNCTION: installModules failed: $message"
    log "Exiting script"
    exitScript -exitCode 2 -functionName "installModules"
}

# authenticate ms graph
log "Running FUNCTION: msGraphAuthenticate..."
try 
{
    msGraphAuthenticate
    log "FUNCTION: msGraphAuthenticate completed"
}
catch 
{
    $message = $_.Exception.Message
    log "FUNCTION: msGraphAuthenticate failed: $message"
    log "Exiting script"
    exitScript -exitCode 2 -functionName "msGraphAuthenticate"
}

# get autopilot info
log "Running FUNCTION: getAutopilotInfo..."
try 
{
    getAutopilotInfo
    log "FUNCTION: getAutopilotInfo completed"
}
catch 
{
    $message = $_.Exception.Message
    log "FUNCTION: getAutopilotInfo failed: $message"
    log "Exiting script"
    exitScript -exitCode 2 -functionName "getAutopilotInfo"
}

# register autopilot device
log "Running FUNCTION: autopilotRegister..."
try 
{
    autopilotRegister
    log "FUNCTION: autopilotRegister completed"
}
catch 
{
    $message = $_.Exception.Message
    log "FUNCTION: autopilotRegister failed: $message"
    log "WARNING: Try to manually register the device in Autopilot"
}

# END SCRIPT

# stop transcript
log "Script completed"

Stop-Transcript