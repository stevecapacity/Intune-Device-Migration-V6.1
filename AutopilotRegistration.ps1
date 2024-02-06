# This script is used to register the PC in the destination tenant Autopilot environment.
# It is executed by the 'AutopilotRegistration' scheduled task.

$settings = Get-Content -Path "$($PSScriptRoot)\settings.json" | ConvertFrom-Json

$localPath = $settings.localPath
if(!(Test-Path $localPath))
{
    mkdir $localPath
}

# Start Logging
$logPath = $settings.logPath
Start-Transcript -Path "$logPath\AutopilotRegistration.log" -Verbose

# Disable AutopilotRegistration task
Write-Host "Disabling AutopilotRegistration task..."
try 
{
    Disable-ScheduledTask -TaskName "AutopilotRegistration"
    Write-Host "AutopilotRegistration task disabled"    
}
catch 
{
    $message = $_.Exception.Message
    Write-Host "AutopilotRegistration task not disabled: $message"
}

# install required modules
Write-Host "Installing required modules..."
$nuget = Get-PackageProvider -Name NuGet -ErrorAction Ignore
Write-Host "Checking for NuGet..."
if(-not($nuget))
{
    Write-Host "NuGet not found.  Installing NuGet..."
    try {
        Install-PackageProvider -Name NuGet -Confirm:$false -Force
        Write-Host "NuGet installed"    
    }
    catch {
        $message = $_.Exception.Message
        Write-Host "NuGet not installed: $message"
    }
}
else
{
    Write-Host "NuGet found"
}

$requiredModules = @(
    "Microsoft.Graph.Intune"
    "WindowsAutoPilotIntune"
)

foreach($module in $requiredModules)
{
    Write-Host "Checking for $module..."
    $installedModule = Get-Module -Name $module -ErrorAction Ignore
    if(-not($installedModule))
    {
        Write-Host "$module not found.  Installing $module..."
        try {
            Install-Module -Name $module -Confirm:$false -AllowClobber -Force
            Write-Host "$module installed"    
        }
        catch {
            $message = $_.Exception.Message
            Write-Host "$module not installed: $message"
        }
    }
    else
    {
        Write-Host "$module found"
    }
}

# Authenticate to destination tenant
$clientId = $settings.targetTenant.clientId
$clientSecret = $settings.targetTenant.clientSecret
$clientSecureSecret = ConvertTo-SecureString $clientSecret -AsPlainText -Force
$clientSecretCredential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $clientId, $clientSecureSecret
$tenantId = $settings.targetTenant.tenantId

Connect-MgGraph  -TenantId $tenantId -ClientSecret $clientSecretCredential

# get Autopilot device info
Write-Host "Collecting Autopilot device info..."
$serialNumber = Get-WmiObject -Class Win32_BIOS | Select-Object -ExpandProperty SerialNumber
if([string]::IsNullOrWhiteSpace($serialNumber)) { $serialNumber = $env:COMPUTERNAME }
Write-Host "Serial number: $serialNumber"

$hwid = ((Get-WmiObject -Namespace root/cimv2/mdm/dmmap -Class MDM_DevDetail_Ext01 -Filter "InstanceID='Ext' AND ParentID='./DevDetail'").DeviceHardwareData)
Write-Host "Hardware ID: $hwid"

Write-Host "Retrieving Group tag from registry..."
$regPath = $settings.regPath
$key = "Registry::$regPath"
$groupTag = Get-ItemPropertyValue -Path $key -Name "GroupTag"

$useTag = ""

if($groupTag -ne $null)
{
    $tag = $groupTag
    Write-Host "Group tag: $tag"
    $useTag = $true
}
else 
{
    Write-Host "Will not be used"
    $useTag = $false
}

# Register device in Autopilot
Write-Host "Registering device in Autopilot..."
if($useTag)
{
    Write-Host "Using group tag..."
    try 
    {
        Add-AutopilotImportedDevice -serialNumber $serialNumber -hardwareIdentifier $hwid -groupTag $tag
        Write-Host "Device registered in Autopilot"    
    }
    catch 
    {
        $message = $_.Exception.Message
        Write-Host "Device not registered in Autopilot: $message"
    }
}
else
{
    Write-Host "Not using group tag..."
    try 
    {
        Add-AutopilotImportedDevice -serialNumber $serialNumber -hardwareIdentifier $hwid
        Write-Host "Device registered in Autopilot"    
    }
    catch 
    {
        $message = $_.Exception.Message
        Write-Host "Device not registered in Autopilot: $message"
    }
}
