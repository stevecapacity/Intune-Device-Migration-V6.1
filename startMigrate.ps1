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
$logObject = @()

# Import JSON contents from settings.json
$settings = Get-Content -Path "$($PSScriptRoot)\settings.json" | ConvertFrom-Json

# Create local path, set install flag, and start transcript
function initializeScript()
{
    Param(
        [string]$localPath = $settings.localPath,
        [string]$logPath = $settings.logPath
    )
    if(!(Test-Path $localPath))
    {
        mkdir $localPath
    }
    $installTag = "$($localPath)\install.tag" 
    New-Item -Path $installTag -ItemType file -Force

    $startMigrateLog = "$($logPath)\startMigrate.log"
    Start-Transcript -Path $startMigrateLog -Verbose
}

# run initializeScript
try 
{
    initializeScript
    Write-Host "Script initialized"
    $logObject += @{Name="Script initialized:";Value="TRUE"}
}
catch 
{
    $message = $_.Exception.Message
    Write-Host "Error initializing script: $message"
    $logObject += @{Name="Script initialized:";Value="ERROR: $message"}
    Write-Host "Stopping migration process..."
    Exit 1
}

# Check context
$context = whoami
Write-Host "Running as $context"
$logObject += @{Name="Running as:";Value=$context}

# Copy package files to local path
function copyPackageFiles()
{
    Param(
        [string]$sourcePath = "$($PSScriptRoot)",
        [array]$packageFiles = (Get-ChildItem -Path $sourcePath -Recurse)
    )
    foreach($file in $packageFiles)
    {
        $source = $file.FullName
        $destination = $localPath
        try
        {
            Copy-Item -Path $source -Destination $destination -Force
            Write-Host "Copied $($file.Name) to $($destination)"
            $logObject += @{Name="Copied $($file.Name) to $($destination):";Value="TRUE"}
        }
        catch
        {
            $message = $_.Exception.Message
            Write-Host "Error copying $($file.Name) to $($destination): $message"
            $logObject += @{Name="Copied $($file.Name) to $($destination):";Value="ERROR: $message"}
        }
    }
}

# run copyPackageFiles
try 
{
    copyPackageFiles
    Write-Host "Package files copied"
    $logObject += @{Name="Package files copied:";Value="TRUE"}
}
catch 
{
    $message = $_.Exception.Message
    Write-Host "Error copying package files: $message"
    $logObject += @{Name="Package files copied:";Value="ERROR: $message"}
    Write-Host "Stopping migration process..."
    Exit 1
}


# Authenticate to Graph (source tenant)
function msGraphAuthenticate()
{
    Param(
    [string]$clientId = $settings.sourceTenant.clientID,
    [string]$clientSecret = $settings.sourceTenant.clientSecret,
    [string]$tenant = $settings.sourceTenant.tenantName
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
    Write-Host "MS Graph Authenticated"
    $logObject += @{Name="MS Graph Authenticated:";Value="TRUE"}
}
catch 
{
    $message = $_.Exception.Message
    Write-Host "Error authenticating to MS Graph: $message"
    $logObject += @{Name="MS Graph Authenticated:";Value="ERROR: $message"}
    Write-Host "Stopping migration process..."
    Exit 1
}

# Get local device info
function getLocalDeviceInfo()
{
    Param(
        [string]$hostname = $env:COMPUTERNAME,
        [string]$serialNumber = (Get-WmiObject -Class Win32_BIOS | Select-Object -ExpandProperty SerialNumber)
    )
    $deviceInfo = @{
        "Hostname" = $hostname
        "SerialNumber" = $serialNumber
    }
    
    foreach($key in $deviceInfo.GetEnumerator())
    {
        if(![string]::IsNullOrEmpty($key.Value))
        {
            Write-Host "$($key.Name):$($key.Value)"
            $logObject += @{Name="$($key.Name):";Value="$($key.Value)"}
        }
        else
        {
            Write-Host "$($key.Name) not found"
            $logObject += @{Name="$($key.Name) written to registry:";Value="FALSE"}
        }
    }
}

# run getLocalDeviceInfo
try 
{
    getLocalDeviceInfo
    Write-Host "Local device info retrieved"
    $logObject += @{Name="Local device info retrieved:";Value="TRUE"}
}
catch 
{
    $message = $_.Exception.Message
    Write-Host "Error getting local device info: $message"
    $logObject += @{Name="Local device info retrieved:";Value="ERROR: $message"}
    Write-Host "Stopping migration process..."
    Exit 1
}

# Get user info
function getUserInfo() 
{
    Param(
        [string]$originalUser = (Get-WmiObject -Class Win32_ComputerSystem | Select-Object -ExpandProperty UserName),
        [string]$originalUserSID = (New-Object System.Security.Principal.NTAccount($originalUser)).Translate([System.Security.Principal.SecurityIdentifier]).Value,
        [string]$originalUserName = (Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Microsoft\IdentityStore\Cache\$($originalUserSID)\IdentityCache\$($originalUserSID)" -Name "Username"),
        [string]$originalProfilePath = (Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$($originalUserSID)" -Name "ProfileImagePath"),
        [string]$regPath = $settings.regPath
    )
    $userInfo = @{
        "OriginalUser" = $originalUser
        "OriginalUserSID" = $originalUserSID
        "OriginalUserName" = $originalUserName
        "OriginalProfilePath" = $originalProfilePath
    }
    foreach($key in $userInfo.GetEnumerator())
    {
        if(![string]::IsNullOrEmpty($key.Value))
        {
            Write-Host "$($key.Name):$($key.Value)"
            $logObject += @{Name="$($key.Name):";Value="$($key.Value)"}
            try 
            {
                reg.exe add $regPath /v "$($key.Name)" /t REG_SZ /d "$($key.Value)" /f | Out-Host
                Write-Host "$($key.Name) written to registry"
                $logObject += @{Name="$($key.Name) written to registry:";Value="TRUE"}
            }
            catch 
            {
                $message = $_.Exception.Message
                Write-Host "Error writing $($key.Name) to registry: $message"
                $logObject += @{Name="$($key.Name) written to registry:";Value="ERROR: $message"}
            }
        }
        else
        {
            Write-Host "$($key.Name) not found"
            $logObject += @{Name="$($key.Name) written to registry:";Value="FALSE"}
        }
    }
}

# run getUserInfo
try 
{
    getUserInfo
    Write-Host "User info retrieved"
    $logObject += @{Name="User info retrieved:";Value="TRUE"}
}
catch 
{
    $message = $_.Exception.Message
    Write-Host "Error getting user info: $message"
    $logObject += @{Name="User info retrieved:";Value="ERROR: $message"}
    Write-Host "Stopping migration process..."
    Exit 1
}

# Get device info from source tenant
function getGraphInfo() {
    Param(
        [string]$serial = $serialNumber,
        [string]$regPath = $regPath,
        [string]$intuneGraphURI = "https://graph.microsoft.com/beta/deviceManagement/managedDevices",
        [string]$autopilotGraphURI = "https://graph.microsoft.com/beta/deviceManagement/importedWindowsAutopilotDeviceIdentities",
        [string]$groupTag = $settings.groupTag
    )
    $graphInfo = @()
    try 
    {
        $intuneObject = Invoke-RestMethod -Method Get -Uri "$($intuneGraphURI)?`$filter=contains(serialNumber,'$($serial)')" -Headers $headers
        try 
        {
            $intuneID = $intuneObject.value.id
            $graphInfo += @{Name="Intune ID:";Value=$intuneID}  
        }
        catch 
        {
            $message = $_.Exception.Message
            Write-Host "Error getting Intune ID: $message"
            $logObject += @{Name="Intune ID:";Value="ERROR: $message"}
        }
    }
    catch 
    {
        $message = $_.Exception.Message
        Write-Host "Error getting Intune object: $message"
        $logObject += @{Name="Intune object retrieved:";Value="ERROR: $message"}
    }
    try 
    {
        $autopilotObject = Invoke-RestMethod -Method Get -Uri "$($autopilotGraphURI)?`$filter=contains(serialNumber,'$($serial)')" -Headers $headers
        try 
        {
            $autopilotID = $autopilotObject.value.id
            $graphInfo += @{Name="Autopilot ID:";Value=$autopilotID}
        }
        catch 
        {
            $message = $_.Exception.Message
            Write-Host "Error getting Autopilot ID: $message"
            $logObject += @{Name="Autopilot ID:";Value="ERROR: $message"}
        }
    }
    catch 
    {
        $message = $_.Exception.Message
        Write-Host "Error getting Autopilot object: $message"
        $logObject += @{Name="Autopilot object retrieved:";Value="ERROR: $message"}
    }
    if([string]::IsNullOrEmpty($groupTag))
    {
        Write-Host "Group tag not found in settings.json"
        try 
        {
            $groupTag = $autopilotObject.value.groupTag
            $graphInfo += @{Name="Group tag:";Value=$groupTag}
        }
        catch 
        {
            $message = $_.Exception.Message
            Write-Host "Error getting group tag: $message"
            $logObject += @{Name="Group tag:";Value="ERROR: $message"}
        }
    }
    else
    {
        Write-Host "Group tag not found in settings.json"
        $logObject += @{Name="Group tag:";Value=$groupTag}
    }

    foreach($key in $graphInfo.GetEnumerator())
    {
        if(![string]::IsNullOrEmpty($key.Value))
        {
            Write-Host "$($key.Name):$($key.Value)"
            $logObject += @{Name="$($key.Name):";Value="$($key.Value)"}
            try 
            {
                reg.exe add $regPath /v "$($key.Name)" /t REG_SZ /d "$($key.Value)" /f | Out-Host
                Write-Host "$($key.Name) written to registry"
                $logObject += @{Name="$($key.Name) written to registry:";Value="TRUE"}
            }
            catch 
            {
                $message = $_.Exception.Message
                Write-Host "Error writing $($key.Name) to registry: $message"
                $logObject += @{Name="$($key.Name) written to registry:";Value="ERROR: $message"}
            }
        }
        else
        {
            Write-Host "$($key.Name) not found"
            $logObject += @{Name="$($key.Name) written to registry:";Value="FALSE"}
        }
    }
}

# run getGraphInfo
try 
{
    getGraphInfo
    Write-Host "Graph info retrieved"
    $logObject += @{Name="Graph info retrieved:";Value="TRUE"}
}
catch 
{
    $message = $_.Exception.Message
    Write-Host "Error getting graph info: $message"
    $logObject += @{Name="Graph info retrieved:";Value="ERROR: $message"}
    Write-Host "Stopping migration process..."
    Exit 1
}

# set required policy
function setAllowMicrosoftAccountConnections()
{
    Param(
        [string]$policyPath = "HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\Accounts",
        [string]$policyName = "AllowMicrosoftAccountConnection",
        [int]$policyValue = 1
    )
    $currentPolicyValue = Get-ItemPropertyValue -Path $policyPath -Name $policyName -ErrorAction Ignore
    if($currentPolicyValue -ne $policyValue)
    {
        try 
        {
            reg.exe add $policyPath /v $policyName /t REG_DWORD /d $policyValue /f | Out-Host
            Write-Host "$($policyName) set to $policyValue"
            $logObject += @{Name="$($policyName) set to:";Value=$policyValue}
        }
        catch 
        {
            $message = $_.Exception.Message
            Write-Host "Error setting $($policyName) to $($policyValue): $message"
            $logObject += @{Name="$($policyName) set to:";Value="ERROR: $message"}
        }
    }
    else
    {
        Write-Host "$($policyName) already set to $policyValue"
        $logObject += @{Name="$($policyName) already set:";Value=$policyValue}
    }
}

# run setAllowMicrosoftAccountConnections
try 
{
    setAllowMicrosoftAccountConnections
    Write-Host "Allow Microsoft Account Connections set"
    $logObject += @{Name="Allow Microsoft Account Connections set:";Value="TRUE"}
}
catch 
{
    $message = $_.Exception.Message
    Write-Host "Error setting Allow Microsoft Account Connections: $message"
    $logObject += @{Name="Allow Microsoft Account Connections set:";Value="ERROR: $message"}
    Write-Host "WARNING: verify PC integrity after migration..."
}

# set lastLogonPolicy
function setLastLogonPolicy()
{
    Param(
        [string]$lastLogonPolicyPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
        [string]$lastLogonPolicyName = "dontdisplaylastusername",
        [int]$lastLogonPolicyValue = 1
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
    Write-Host "WARNING: verify PC integrity after migration..."
}

# remove previous MDM enrollments
function removeMDMEnrollments()
{
    Param(
        [string]$EnrollmentsPath = "HKLM:\SOFTWARE\Microsoft\Enrollments\",
        [string]$ERPath = "HKLM:\SOFTWARE\Microsoft\Enrollments\",
        [string]$DiscoveryServiceFullURL = "https://enrollment.manage.microsoft.com/enrollmentserver/discovery.svc"
    )
    $enrollments = Get-ChildItem -Path $EnrollmentsPath
    foreach($enrollment in $enrollments)
    {
        $object = Get-ItemProperty Registry::$enrollment
        $discovery = $object."DiscoveryServiceFullURL"
        if($discovery -eq $DiscoveryServiceFullURL)
        {
            $enrollPath = $ERPath + $object.PSChildName
            Write-Host "Enrollment found. Removing $($enrollPath)..."
            try
            {
                Remove-Item -Path $enrollPath -Recurse -Force
                Write-Host "Removed $($enrollPath)"
                $logObject += @{Name="Removed $($enrollPath):";Value="TRUE"}
            }
            catch
            {
                $message = $_.Exception.Message
                Write-Host "Error removing $($enrollPath): $message"
                $logObject += @{Name="Removed $($enrollPath):";Value="ERROR: $message"}
            }
        }
        else
        {
            Write-Host "No MDM enrollments found"
            $logObject += @{Name="No MDM enrollments found:";Value="TRUE"}
        }
    }
}

# run removeMDMEnrollments
try 
{
    removeMDMEnrollments
    Write-Host "MDM enrollments removed"
    $logObject += @{Name="MDM enrollments removed:";Value="TRUE"}
}
catch 
{
    $message = $_.Exception.Message
    Write-Host "Error removing MDM enrollments: $message"
    $logObject += @{Name="MDM enrollments removed:";Value="ERROR: $message"}
    Write-Host "WARNING: verify PC integrity after migration..."
}

# remove MDM certificate
function removeMDMCertificate()
{
    Param(
        [string]$certPath = 'Cert:\LocalMachine\My',
        [string]$issuer = "Microsoft Intune MDM Device CA"
    )
    try
    {
        Get-ChildItem -Path $certPath | Where-Object { $_.Issuer -eq $issuer } | Remove-Item -Force
        Write-Host "MDM certificate removed"
        $logObject += @{Name="MDM certificate removed:";Value="TRUE"}
    }
    catch
    {
        $message = $_.Exception.Message
        Write-Host "Error removing MDM certificate: $message"
        $logObject += @{Name="MDM certificate removed:";Value="ERROR: $message"}
    }
}

# run removeMDMCertificate
try 
{
    removeMDMCertificate
    Write-Host "MDM certificate removed"
    $logObject += @{Name="MDM certificate removed:";Value="TRUE"}
}
catch 
{
    $message = $_.Exception.Message
    Write-Host "Error removing MDM certificate: $message"
    $logObject += @{Name="MDM certificate removed:";Value="ERROR: $message"}
    Write-Host "WARNING: verify PC integrity after migration..."
}

# set post migration tasks
function setPostMigrationTasks()
{
    Param(
        [string]$middleBoot = "$($localPath)\middleBoot.xml",
        [string]$newProfile = "$($localPath)\newProfile.xml",
        [array]$tasks = @($middleBoot, $newProfile)
    )

    foreach($task in $tasks)
    {
        if($null -ne $task)
        {
            Write-Host "Creating task $($task.BaseName)..."
            try 
            {
                schtasks.exe /Create /TN $($task.BaseName) /XML $($task.FullName)
                Write-Host "Task $($task.BaseName) created"
                $logObject += @{Name="Task $($task.BaseName) created:";Value="TRUE"}
            }
            catch 
            {
                $message = $_.Exception.Message
                Write-Host "Error creating task $($task.BaseName): $message"
                $logObject += @{Name="Task $($task.BaseName) created:";Value="ERROR: $message"}
            }
        }
        else
        {
            Write-Host "Task $($task.BaseName) not found"
            $logObject += @{Name="Task $($task.BaseName) created:";Value="FALSE"}
        
        }
    }
}

# run setPostMigrationTasks
try 
{
    setPostMigrationTasks
    Write-Host "Post migration tasks set"
    $logObject += @{Name="Post migration tasks set:";Value="TRUE"}
}
catch 
{
    $message = $_.Exception.Message
    Write-Host "Error setting post migration tasks: $message"
    $logObject += @{Name="Post migration tasks set:";Value="ERROR: $message"}
    Write-Host "WARNING: verify PC integrity after migration..."
}

# set lock screen
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
    Write-Host "Lock screen set"
    $logObject += @{Name="Lock screen set:";Value="TRUE"}
}
catch 
{
    $message = $_.Exception.Message
    Write-Host "Error setting lock screen: $message"
    $logObject += @{Name="Lock screen set:";Value="ERROR: $message"}
    Write-Host "WARNING: verify PC integrity after migration..."
}

# unjoin source tenant
function unjoinAzureAD()
{
    Param(
        [string]$dsreg = "dsregcmd /status",
        [string]$aadJoined = "AzureAdJoined : YES",
        [string]$domainJoined = "DomainJoined : YES",
        [string]$dsregPath = "C:\Windows\System32\dsregcmd.exe"
    )
    $status = Invoke-Expression $dsreg
    if($status -match $aadJoined)
    {
        Write-Host "Azure AD Joined: YES.  Unjoining..."
        $logObject += @{Name="Azure AD Joined:";Value="TRUE"}
        try 
        {
            Start-Process $dsregPath -ArgumentList "/leave"
            Write-Host "Unjoined Azure AD: TRUE"
            $logObject += @{Name="Unjoined Azure AD:";Value="TRUE"}
        }
        catch 
        {
            $message = $_.Exception.Message
            Write-Host "Error unjoining Azure AD: $message"
            $logObject += @{Name="Unjoined Azure AD:";Value="ERROR: $message"}
        }
    }
    else
    {
        Write-Host "Azure AD Joined: NO"
        $logObject += @{Name="Azure AD Joined:";Value="FALSE"}
    }
}

# run unjoinAzureAD
try 
{
    unjoinAzureAD
    Write-Host "Unjoined Azure AD"
    $logObject += @{Name="Unjoined Azure AD:";Value="TRUE"}
}
catch 
{
    $message = $_.Exception.Message
    Write-Host "Error unjoining Azure AD: $message"
    $logObject += @{Name="Unjoined Azure AD:";Value="ERROR: $message"}
    Write-Host "WARNING: verify PC integrity after migration..."
}

# leave domain
function leaveDomain()
{
    Param(
        [string]$dsreg = "dsregcmd /status",
        [string]$domainJoined = "DomainJoined : YES",
        [string]$builtinAdmin = "$hostname\Administrator"
    )
    $status = Invoke-Expression $dsreg
    if($status -match $domainJoined)
    {
        Write-Host "Domain Joined: Yes.  UNJOINING..."
        $logObject += @{Name="Domain Joined:";Value="TRUE"}
        $adminAccountStatus = (Get-LocalUser -Name "Administrator").Enabled
        $chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_-=+?<>~"
        $random = 1..16 | ForEach-Object { Get-Random -Maximum $chars.Length } | ForEach-Object { $chars[ $_ ] }
        $passwordString = -join $random
        $password = ConvertTo-SecureString -String $passwordString -AsPlainText -Force
        if($adminAccountStatus -eq "False")
        {
            Write-Host "Built-in Administrator account is disabled.  Enabling and setting password..."
            $logObject += @{Name="Built-in Administrator account enabled:";Value="FALSE"}
            try 
            {
                Set-LocalUser -Name "Administrator" -Password $password
                Get-LocalUser -Name "Administrator" | Enable-LocalUser
                Write-Host "Built-in Administrator account enabled"
                Write-Host "Built-in Administrator account password reset"
                $logObject += @{Name="Built-in Administrator account enabled:";Value="TRUE"}  
                $logObject += @{Name="Built-in Administrator account password reset:";Value="TRUE"}
            }
            catch 
            {
                $message = $_.Exception.Message
                Write-Host "Error enabling built-in Administrator account: $message"
                Write-Host "Error resetting built-in Administrator account password: $message"
                $logObject += @{Name="Built-in Administrator account enabled:";Value="ERROR: $message"}
                $logObject += @{Name="Built-in Administrator account password reset:";Value="ERROR: $message"}
            }
        }
        else
        {
            Write-Host "Built-in Administrator account is enabled.  Resetting password..."
            $logObject += @{Name="Built-in Administrator account enabled:";Value="TRUE"}
            try 
            {
                Set-LocalUser -Name "Administrator" -Password $password
                Write-Host "Built-in Administrator account password reset"
                $logObject += @{Name="Built-in Administrator account password reset:";Value="TRUE"}  
            }
            catch 
            {
                $message = $_.Exception.Message
                Write-Host "Error resetting built-in Administrator account password: $message"
                $logObject += @{Name="Built-in Administrator account password reset:";Value="ERROR: $message"}
            }
        }
    }
    else
    {
        Write-Host "Domain Joined: NO"
        $logObject += @{Name="Domain Joined:";Value="FALSE"}
    }
}

# run leaveDomain
try 
{
    leaveDomain
    Write-Host "Left domain"
    $logObject += @{Name="Left domain:";Value="TRUE"}
}
catch 
{
    $message = $_.Exception.Message
    Write-Host "Error leaving domain: $message"
    $logObject += @{Name="Left domain:";Value="ERROR: $message"}
    Write-Host "WARNING: verify PC integrity after migration..."
}

# Run provisioning package to join destination tenant
function installProvisioningPackage()
{
    Param(
        [string]$ppkg = (Get-ChildItem -Path $localPath -Filter "*.ppkg" -Recurse)
    )
    if($ppkg -ne $null)
    {
        $ppkgPath = "$($localPath)\$($ppkg)"
        Write-Host "Installing provisioning package $($ppkgPath)..."
        try 
        {
            Install-ProvisioningPackage -PackagePath $ppkgPath -QuietInstall -Force
            Write-Host "Provisioning package installed"
            $logObject += @{Name="Provisioning package installed:";Value="TRUE"}
        }
        catch 
        {
            $message = $_.Exception.Message
            Write-Host "Error installing provisioning package: $message"
            $logObject += @{Name="Provisioning package installed:";Value="ERROR: $message"}
        }
    }
    else
    {
        Write-Host "Provisioning package not found"
        $logObject += @{Name="Provisioning package found:";Value="FALSE"}
        Write-Host "Stopping migration process..."
        Exit 1
    }
}

# run installProvisioningPackage
try 
{
    installProvisioningPackage
    Write-Host "Provisioning package installed"
    $logObject += @{Name="Provisioning package installed:";Value="TRUE"}
}
catch 
{
    $message = $_.Exception.Message
    Write-Host "Error installing provisioning package: $message"
    $logObject += @{Name="Provisioning package installed:";Value="ERROR: $message"}
    Write-Host "Stopping migration process..."
    Exit 1
}

# delete source tenant graph objects
function deleteSourceObjects()
{
    Param(
        [string]$intuneID = $intuneID,
        [string]$autopilotID = $autopilotID,
        [string]$intuneGraphURI = $intuneGraphURI,
        [string]$autopilotGraphURI = $autopilotGraphURI
    )
    if(![string]::IsNullOrEmpty($intuneID))
    {
        try 
        {
            Invoke-RestMethod -Method Delete -Uri "$($intuneGraphURI)/$($intuneID)" -Headers $headers
            Write-Host "Intune object deleted"
            $logObject += @{Name="Intune object deleted:";Value="TRUE"}
            Start-Sleep -Seconds 2
        }
        catch 
        {
            $message = $_.Exception.Message
            Write-Host "Error deleting Intune object: $message"
            $logObject += @{Name="Intune object deleted:";Value="ERROR: $message"}
        }
    }
    else
    {
        Write-Host "Intune object not found"
        $logObject += @{Name="Intune object deleted:";Value="FALSE"}
    }
    if(![string]::IsNullOrEmpty($autopilotID))
    {
        try 
        {
            Invoke-RestMethod -Method Delete -Uri "$($autopilotGraphURI)/$($autopilotID)" -Headers $headers
            Write-Host "Autopilot object deleted"
            $logObject += @{Name="Autopilot object deleted:";Value="TRUE"}
            Start-Sleep -Seconds 2
        }
        catch 
        {
            $message = $_.Exception.Message
            Write-Host "Error deleting Autopilot object: $message"
            $logObject += @{Name="Autopilot object deleted:";Value="ERROR: $message"}
        }
    }
    else
    {
        Write-Host "Autopilot object not found"
        $logObject += @{Name="Autopilot object deleted:";Value="FALSE"}
    }
}

# run deleteSourceObjects
try 
{
    deleteSourceObjects
    Write-Host "Source tenant objects deleted"
    $logObject += @{Name="Source tenant objects deleted:";Value="TRUE"}
}
catch 
{
    $message = $_.Exception.Message
    Write-Host "Error deleting source tenant objects: $message"
    $logObject += @{Name="Source tenant objects deleted:";Value="ERROR: $message"}
    Write-Host "WARNING: verify PC integrity after migration..."
}

# log to Log Analytics
function logAnalytics()
{
    Param(
        [boolean]$logAnalyticsEnabled = $settings.logAnalytics.enabled,
        [string]$customerId = $settings.logAnalytics.workspaceID,
        [string]$sharedKey = $settings.logAnalytics.sharedKey,
        [string]$logType = "startMigrate"
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
    $logObject += @{Name="Logged to Log Analytics:";Value="TRUE"}
}
catch 
{
    $message = $_.Exception.Message
    Write-Host "Error logging to Log Analytics: $message"
    $logObject += @{Name="Logged to Log Analytics:";Value="ERROR: $message"}
}

# stop transcript
Stop-Transcript

# restart device
shutdown -r -t 00