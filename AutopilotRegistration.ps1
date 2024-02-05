# AUTOPILOTREGISTRATION.PS1
# This script is used to register the PC in the destination tenant Autopilot environment.
# It is executed by the 'AutopilotRegistration' scheduled task.

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
    $autopilotRegistrationLog = "$logPath\autopilotRegistration.log"
    Start-Transaction -Path $autopilotRegistrationLog -Verbose
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

# installAutopilotModules
function installAutopilotModules()
{
    Param(
        [string]$nuget = (Get-PackageProvider -Name NuGet -ErrorAction SilentlyContinue).Name,
        [array]$requiredModules = @("Microsoft.Graph.Intune","WindowsAutopilotIntune")
    )
    Write-Host "Checking for NuGet package provider..."
    if([string]::IsNullOrEmpty($nuget))
    {
        Write-Host "NuGet package provider not found. Installing..."
        try
        {
            Install-PackageProvider -Name NuGet -Confirm:$false -Force
            Write-Host "NuGet package provider installed"
            $logObject += @{Name="NuGet Package Provider"; Status="TRUE"}
        }
        catch
        {
            $message = $_.Exception.Message
            Write-Host "Error installing NuGet package provider: $message"
            $logObject += @{Name="NuGet Package Provider"; Status="FALSE: $message"}
        }
    }
    else
    {
        Write-Host "NuGet package provider found"
        $logObject += @{Name="NuGet Package Provider"; Status="TRUE"}
    }
    Write-Host "Checking for required modules..."
    foreach($module in $requiredModules)
    {
        $installedModule = (Get-Module -Name $module -ErrorAction SilentlyContinue).Name
        if([string]::IsNullOrEmpty($installedModule))
        {
            Write-Host "$module not found. Installing..."
            try
            {
                Install-Module -Name $module -Confirm:$false -Force
                Write-Host "$module installed"
                $logObject += @{Name="$module"; Status="TRUE"}
            }
            catch
            {
                $message = $_.Exception.Message
                Write-Host "Error installing $($module): $message"
                $logObject += @{Name="$module"; Status="FALSE: $message"}
            }
        }
        else
        {
            Write-Host "$module found"
            $logObject += @{Name="$module"; Status="TRUE"}
        } 
    }
}

# run installAutopilotModule
try 
{
    installAutopilotModules
    Write-Host "Autopilot modules installed"
    $logObject += @{Name="Autopilot Modules Installed"; Status="TRUE"}
}
catch 
{
    $message = $_.Exception.Message
    Write-Host "Error installing Autopilot modules: $message"
    $logObject += @{Name="Autopilot Modules Installed"; Status="FALSE: $message"}
}

# authenticate to target tenant
function msGraphAuthenticate()
{
    Param(
        [string]$clientId = $settings.targetTenant.clientId,
        [string]$clientSecret = $settings.targetTenant.clientSecret,
        [string]$clientSecureSecret = (ConvertTo-SecureString -String $clientSecret -AsPlainText -Force),
        [securestring]$clientSecretCredential = (New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $clientId, $clientSecureSecret),
        [string]$tenantId = $settings.targetTenant.tenantId
    )
    Write-Host "Authenticating to target tenant..."
    try
    {
        Connect-MgGraph -TenantId $tenantId -ClientSecretCredential $clientSecretCredential
        Write-Host "Authenticated to target tenant"
        $logObject += @{Name="MS Graph Authentication"; Status="TRUE"}
    }
    catch
    {
        $message = $_.Exception.Message
        Write-Host "Error authenticating to target tenant: $message"
        $logObject += @{Name="MS Graph Authentication"; Status="FALSE: $message"}
    }
}

# run msGraphAuthenticate
try 
{
    msGraphAuthenticate
    Write-Host "Authenticated to target tenant"
    $logObject += @{Name="MS Graph Authentication"; Status="TRUE"}
}
catch 
{
    $message = $_.Exception.Message
    Write-Host "Error authenticating to target tenant: $message"
    $logObject += @{Name="MS Graph Authentication"; Status="FALSE: $message"}
    Write-Host "Stopping script"
    Exit 1
}

# register device in Autopilot
function autopilotRegister()
{
    Param(
        [string]$serialNumber = (Get-WmiObject -Class Win32_BIOS | Select-Object -ExpandProperty SerialNumber),
        [string]$hwid = ((Get-WmiObject -Namespace root/cimv2/mdm/dmmap -Class MDM_DevDetail_Ext01 -Filter "InstanceID='Ext' AND ParentID='./DevDetail'").DeviceHardwareData),
        [string]$regPath = $settings.regPath,
        [string]$regKey = "Registry::$regPath",
        [string]$groupTag = (Get-ItemPropertyValue -Path $regKey -Name "GroupTag" -ErrorAction SilentlyContinue) ,
        [boolean]$useGroupTag = $false
    )
    Write-Host "Checking for group tag..."
    if([string]::IsNullOrEmpty($groupTag))
    {
        Write-Host "Group tag not found. Not using Group tag"
        $logObject += @{Name="Use Group Tag"; Status="FALSE"}
    }
    else
    {
        Write-Host "Group tag found: $groupTag"
        $useGroupTag = $true
        $logObject += @{Name="Use Group Tag"; Status="TRUE"}
    }
    Write-Host "Registering device in Autopilot..."
    if($useGroupTag -eq $true)
    {
        Write-Host "Using Group Tag..."
        try
        {
            Add-AutopilotImportedDevice -serialNumber $serialNumber -hardwareIdentifier $hwid -groupTag $groupTag
            Write-Host "Device registered in Autopilot"
            $logObject += @{Name="Autopilot Registration"; Status="TRUE"}
        }
        catch
        {
            $message = $_.Exception.Message
            Write-Host "Error registering device in Autopilot: $message"
            $logObject += @{Name="Autopilot Registration"; Status="FALSE: $message"}
        }
    }
    else
    {
        Write-Host "Not using Group Tag..."
        try
        {
            Add-AutopilotImportedDevice -serialNumber $serialNumber -hardwareIdentifier $hwid
            Write-Host "Device registered in Autopilot"
            $logObject += @{Name="Autopilot Registration"; Status="TRUE"}
        }
        catch
        {
            $message = $_.Exception.Message
            Write-Host "Error registering device in Autopilot: $message"
            $logObject += @{Name="Autopilot Registration"; Status="FALSE: $message"}
        }
    }
}

# run autopilotRegister
try 
{
    autopilotRegister
    Write-Host "Device registered in Autopilot"
    $logObject += @{Name="Autopilot Registration"; Status="TRUE"}
}
catch 
{
    $message = $_.Exception.Message
    Write-Host "Error registering device in Autopilot: $message"
    $logObject += @{Name="Autopilot Registration"; Status="FALSE: $message"}
    Write-Host "WARNING: Device not registered in Autopilot"
}

# log to Log Analytics
function logAnalytics()
{
    Param(
        [boolean]$logAnalyticsEnabled = $settings.logAnalytics.enabled,
        [string]$customerId = $settings.logAnalytics.workspaceID,
        [string]$sharedKey = $settings.logAnalytics.sharedKey,
        [string]$logType = "autopilotRegistration"
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
    $logObject += @{Name="Log Analytics"; Status="TRUE"}
}
catch 
{
    $message = $_.Exception.Message
    Write-Host "Error submitting Log Analytics data: $message"
    $logObject += @{Name="Log Analytics"; Status="FALSE: $message"}
}

# stop transcript
Stop-Transcript