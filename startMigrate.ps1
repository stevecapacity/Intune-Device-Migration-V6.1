<# INTUNE TENANT-TO-TENANT DEVICE MIGRATION V6.0
Synopsis
This solution will automate the migration of devices from one Intune tenant to another Intune tenant.  Devices can be hybrid AD Joined or Azure AD Joined.
DESCRIPTION
Intune Tenant-to-Tenant Migration Solution leverages the Microsoft Graph API to automate the migration of devices from one Intune tenant to another Intune tenant.  Devices can be hybrid AD Joined or Azure AD Joined.  The solution will also migrate the device's primary user profile data and files.  The solution leverages Windows Configuration Designer to create a provisioning package containing a Bulk Primary Refresh Token (BPRT).  Tasks are set to run after the user signs into the PC with destination tenant credentials to update Intune attributes including primary user, Entra ID device group tag, and device category.  In the last step, the device is registered to the destination tenant Autopilot service.  
USE
This script is packaged along with the other files into an intunewin file.  The intunewin file is then uploaded to Intune and assigned to a group of devices.  The script is then run on the device to start the migration process.
INPUTS
-LogAnalytics - This switch will enable logging to Log Analytics
NOTES
When deploying with Microsoft Intune, the install command must be "%WinDir%\Sysnative\WindowsPowerShell\v1.0\powershell.exe -ExecutionPolicy Bypass -File startMigrate.ps1" to ensure the script runs in 64-bit mode.
.OWNER
Steve Weiner
.CONTRIBUTORS
Logan Lautt
Jesse Weimer
#>

$ErrorActionPreference = "SilentlyContinue"

# Import JSON contents from settings.json
$settings = Get-Content -Path "$($PSScriptRoot)\settings.json" | ConvertFrom-Json

# Variables from settings.json
$localPath = $settings.localPath
$logPath = $settings.logPath
$clientId = $settings.sourceTenant.clientID
$clientSecret = $settings.sourceTenant.clientSecret
$tenant = $settings.sourceTenant.tenantName
$groupTag = $settings.groupTag
$regPath = $settings.regPath
$lockImg1 = $settings.lockScreen.lockScreen1

# Create local path, extract files, and start logging
$localPath = $settings.localPath
if(!(Test-Path $localPath)) {
    New-Item -ItemType Directory -Force -Path $localPath
}

Copy-Item -Path "$($PSScriptRoot)\*" -Destination $localPath -Force

# Create install flag
$installFlag = "$($localPath)\startMigrate.flag"
New-Item -ItemType File -Force -Path $installFlag

# Start logging
$log = "$($logPath)\startMigrate.log"
$LogTime = Get-Date -Format "MM-dd-yyyy HH:mm:ss"
$LogMessage = "[$LogTime] Starting startMigrate.ps1"
Add-Content -Path $log -Value $LogMessage
Start-Transcript -Path $log -Append -Verbose

# Check if running as system
$context = whoami
Write-Host "Running as $context"

# Authenticate to Graph (source tenant)
Write-Host "Authenticating to MS Graph..."
$clientId = $settings.sourceTenant.clientID
$clientSecret = $settings.sourceTenant.clientSecret
$tenant = $settings.sourceTenant.tenantName

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
Write-Host "MS Graph Authenticated"

# Get local device info
$hostname = $env:COMPUTERNAME
Write-Host "Hostname: $hostname"

$serialNumber = Get-WmiObject -Class Win32_BIOS | Select-Object -ExpandProperty SerialNumber
Write-Host "Serial Number: $serialNumber"

# Get user info
$originalUser = Get-WmiObject -Class Win32_ComputerSystem | Select-Object -ExpandProperty UserName
Write-Host "Original user: $originalUser"
$originalUserSID = (New-Object System.Security.Principal.NTAccount($originalUser)).Translate([System.Security.Principal.SecurityIdentifier]).Value
Write-Host "Original user SID: $originalUserSID"
$originalUserName = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Microsoft\IdentityStore\Cache\$($originalUserSID)\IdentityCache\$($originalUserSID)" -Name "Username"
Write-Host "Original user Name: $originalUserName"
$originalProfilePath = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$($originalUserSID)" -Name "ProfileImagePath"
Write-Host "Original Profile Path: $originalProfilePath"

# Get device info from Graph (source tenant)
Write-Host "Getting device info from Graph..."

# Intune object
Write-Host "Getting Intune object..."
$intuneObject = Invoke-RestMethod -Uri "https://graph.microsoft.com/beta/deviceManagement/managedDevices?`$filter=contains(serialNumber,'$($serialNumber)')" -Headers $headers -Method Get    
if($intuneObject -ne $null)
{
    Write-Host "Intune object found"
    try 
    {
        $intuneID = $intuneObject.value.id
        Write-Host "Intune ID: $intuneID"
    }
    catch 
    {
        $message = $_.Exception.Message
        Write-Host "Error getting Intune ID: $message"
    }
}
else 
{
    $message = $_.Exception.Message
    Write-Host "Error getting Intune object: $message"
}

# Autopilot object
Write-Host "Getting Autopilot object..."
$autopilotObject = Invoke-RestMethod -Uri "https://graph.microsoft.com/beta/deviceManagement/windowsAutopilotDeviceIdentities?`$filter=contains(serialNumber,'$($serialNumber)')" -Headers $headers -Method Get
if($autopilotObject -ne $null)
{
    Write-Host "Autopilot object found"
    try 
    {
        $autopilotID = $autopilotObject.value.id
        Write-Host "Autopilot ID: $autopilotID"
    }
    catch 
    {
        $message = $_.Exception.Message
        Write-Host "Error getting Autopilot ID: $message"
    }
}
else 
{
    $message = $_.Exception.Message
    Write-Host "Error getting Autopilot object: $message"
}


# Check for group tag if Autopilot object exists AND if group tag is not already set
$groupTag = $settings.groupTag
if($groupTag -eq "")
{
    Write-Host "No group tag specified- try to get from source tenant Autopilot object..."
    try 
    {
        $groupTag = $autopilotObject.value.groupTag
        Write-Host "Group Tag: $groupTag"
    }
    catch 
    {
        $message = $_.Exception.Message
        Write-Host "Error getting group tag: $message"
    }
}
else
{
    Write-Host "Group Tag: $groupTag"
}

# Write values to registry
Write-Host "Writing values to registry..."
$regPath = $settings.regPath

if($originalUserName -ne $null)
{
    Write-Host "Writing original user name to registry..."
    try 
    {
        reg.exe add $regPath /v "OriginalUserName" /t REG_SZ /d "$($originalUserName)" /f | Out-Host
        Write-Host "Original user name written to registry"
    }
    catch 
    {
        $message = $_.Exception.Message
        Write-Host "Error writing original user name to registry: $message"
    }
}
else 
{
    Write-Host "Original user name not found"
}

if($originalUserSID -ne $null)
{
    Write-Host "Writing original user SID to registry..."
    try 
    {
        reg.exe add $regPath /v "OriginalUserSID" /t REG_SZ /d "$($originalUserSID)" /f | Out-Host
        Write-Host "Original user SID written to registry"
    }
    catch 
    {
        $message = $_.Exception.Message
        Write-Host "Error writing original user SID to registry: $message"
    }
}
else 
{
    Write-Host "Original user SID not found"
}

if($originalProfilePath -ne $null)
{
    Write-Host "Writing original profile path to registry..."
    try 
    {
        reg.exe add $regPath /v "OriginalProfilePath" /t REG_SZ /d "$($originalProfilePath)" /f | Out-Host
        Write-Host "Original profile path written to registry"
    }
    catch 
    {
        $message = $_.Exception.Message
        Write-Host "Error writing original profile path to registry: $message"
    }
}
else 
{
    Write-Host "Original profile path not found"
}

if($groupTag -ne $null)
{
    Write-Host "Writing group tag to registry..."
    try 
    {
reg.exe add $regPath /v "GroupTag" /t REG_SZ /d "$($groupTag)" /f | Out-Host
Write-Host "Group tag written to registry"
    }
    catch 
    {
        $message = $_.Exception.Message
        Write-Host "Error writing group tag to registry: $message"
    }
}
else
{
    Write-Host "Group tag not found"
}

# Ensure Microsoft Account creation policy is enabled

$regPath = "HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\Accounts"
$regName = "AllowMicrosoftAccountConnection"
$value = 1

$currentRegValue = Get-ItemPropertyValue -Path $regPath -name $regName -ErrorAction SilentlyContinue

if ($currentRegValue -eq $value) {
    Write-Host "Registry value for AllowMicrosoftAccountConnection is correctly set to $value."
}
else {
    Write-Host "Setting MDM registry value for AllowMicrosoftAccountConnection..."
    reg.exe add "HKLM\SOFTWARE\Microsoft\PolicyManager\current\device\Accounts" /v "AllowMicrosoftAccountConnection" /t REG_DWORD /d 1 /f | Out-Host
}

<#===============================================================================================#>
# Only show OTHER USER option after reboot
Write-Host "Turning off Last Signed-In User Display...."
try {
    Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name dontdisplaylastusername -Value 1 -Type DWORD -Force
    Write-Host "Enabled Interactive Logon policy"
} 
catch {
    Write-Host "Failed to enable policy"
}


# Remove MDM certificate
Write-Host "Removing MDM Certificate..."
Get-ChildItem -Path 'Cert:\LocalMachine\My' | Where-Object {$_.Issuer -match "Microsoft Intune MDM Device CA"} | Remove-Item -Force
Write-Host "MDM Certificate removed"

# Remove MDM enrollment entries
Write-Host "Removing MDM enrollment entries..."
$EnrollmentsPath = "HKLM:\Software\Microsoft\Enrollments\"
$ERPath = "HKLM:\Software\Microsoft\Enrollments\"
$Enrollments = Get-ChildItem -Path $EnrollmentsPath
foreach ($enrollment in $Enrollments) {
    $object = Get-ItemProperty Registry::$enrollment
    $discovery = $object."DiscoveryServiceFullURL"
    if ($discovery -eq "https://enrollment.manage.microsoft.com/enrollmentserver/discovery.svc") {
        $enrollPath = $ERPath + $object.PSChildName
        Remove-Item -Path $enrollPath -Recurse
    }
}

# Remove MDM scheduled tasks
Write-Host "Removing MDM scheduled tasks..."
$enrollID = $enrollPath.Split("\")[-1]
$tasks = Get-ScheduledTask -TaskPath "\Microsoft\Windows\EnterpriseMgmt\$($enrollID)" -ErrorAction SilentlyContinue
if($tasks.Count -gt 0)
{
    foreach($task in $tasks)
    {
        try 
        {
            Unregister-ScheduledTask -TaskName $task.TaskName -Confirm:$false -ErrorAction SilentlyContinue
            Write-Host "MDM scheduled task removed"
        }
        catch 
        {
            $message = $_.Exception.Message
            Write-Host "Error removing MDM scheduled task: $message"
        }
    }
}
else
{
    Write-Host "No MDM scheduled tasks found"
}

# Set tasks to run after user signs in
Write-Host "Setting post migration tasks..."

try 
{
    schtasks.exe /Create /TN "middleBoot" /XML "$($localPath)\middleBoot.xml"
    Write-Host "middleBoot task set"
}
catch 
{
    $message = $_.Exception.Message
    Write-Host "Error setting middleBoot task: $message"
    Write-Host "Stopping migration process..."
    Exit 1
}

try
{
    schtasks.exe /Create /TN "newProfile" /XML "$($localPath)\newProfile.xml"
    Write-Host "newProfile task set"
}
catch 
{
    $message = $_.Exception.Message
    Write-Host "Error setting newProfile task: $message"
    Write-Host "Stopping migration process..."
    Exit 1
}


# Set lock screen image
$lockImgPath1 = "$($localPath)\$($lockImg1)"

$lockScreenPath = "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\PersonalizationCSP"
reg.exe add $lockScreenPath /v "LockScreenImagePath" /t REG_SZ /d $lockImgPath1 /f | Out-Host
reg.exe add $lockScreenPath /v "LockScreenImageStatus" /t REG_DWORD /d 1 /f | Out-Host

# remove device from Azure AD
Write-Host "Removing device from Azure AD..."
Start-Process "C:\Windows\System32\dsregcmd.exe" -ArgumentList "/leave"
Write-Host "Device removed from Azure AD"

# Check for domain join and remove if necessary
$domainJoin = (dsregcmd /status | Select-String "DomainJoined").ToString().Split(":")[1].Trim()
if($domainJoin -eq "YES")
{
    Write-Host "Computer is domain joined- removing from domain..."
    $chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_-=+?<>~"
    $random = 1..16 | ForEach-Object { Get-Random -Maximum $chars.Length } | ForEach-Object { $chars[ $_ ] }
    $passwordString = -join $random
    $password = ConvertTo-SecureString -String $passwordString -AsPlainText -Force
    # try to enable local admin account and set password
    try
    {
        Set-LocalUser -Name "Administrator" -Password $password
        Get-LocalUser -Name "Administrator" | Enable-LocalUser
        $cred = New-Object System.Management.Automation.PSCredential ("$hostname\Administrator", $password)
        Write-Host "Enabled local admin account and set password"
        try 
        {
            Remove-Computer -UnjoinDomainCredential $cred -Force -PassThru -Verbose
            Write-Host "Computer removed from domain"
            Start-Sleep -Seconds 2
        }
        catch 
        {
            $message = $_.Exception.Message
            Write-Host "Error removing computer from domain: $message"
            Write-Host "Stopping migration process..."
            Exit 1
        }
    }
    catch
    {
        $message = $_.Exception.Message
        Write-Host "Error enabling local admin account and setting password: $message"
        Write-Host "Stopping migration process..."
        Exit 1
    }
}
else
{
    Write-Host "Computer is not domain joined"
}

# Run ppkg to join device to destination tenant
$ppkg = Get-ChildItem -Path $localPath -Filter *.ppkg -Recurse
Write-Host "Installing provisioning package..."
try
{
    Install-ProvisioningPackage -PackagePath $ppkg.FullName -QuietInstall -Force
    Write-Host "Provisioning package installed"
}
catch
{
    $message = $_.Exception.Message
    Write-Host "Error installing provisioning package: $message"
    Exit 1
}

# Delete Intune Object in source tenant
Write-Host "Deleting Intune object in source tenant..."
if($intuneID -ne $null)
{
    try 
    {
        Invoke-RestMethod -Uri "https://graph.microsoft.com/beta/deviceManagement/managedDevices/$($intuneID)" -Headers $headers -Method Delete
        Write-Host "Intune object deleted"
        Start-Sleep -Seconds 2
    }
    catch 
    {
        $message = $_.Exception.Message
        Write-Host "Error deleting Intune object: $message"
    }
}
else
{
    Write-Host "Intune object not found"
}

# Delete Autopilot object in source tenant
Write-Host "Deleting Autopilot object in source tenant..."
if($autopilotID -ne $null)
{
    try 
    {
        Invoke-RestMethod -Uri "https://graph.microsoft.com/beta/deviceManagement/windowsAutopilotDeviceIdentities/$($autopilotID)" -Headers $headers -Method Delete
        Write-Host "Autopilot object deleted"
        Start-Sleep -Seconds 2
    }
    catch 
    {
        $message = $_.Exception.Message
        Write-Host "Error deleting Autopilot object: $message"
    }
}
else
{
    Write-Host "Autopilot object not found"
}

Write-Host "StartMigrate process complete... shutting down in 30 seconds"

Stop-Transcript

shutdown -r -t 30