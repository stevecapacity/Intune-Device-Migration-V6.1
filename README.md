# Intune Device Migration V6
 V6 (Removes need for profile migration)

 Intune tenant-to-tenant device migration V3 adds the capability of operating off of one, settings file that is modified so that the solution code can remain untouched.

 The migration solution has now been updated to not require any transfer of files from the original user profile to the new user.


## Settings JSON
The following variables are now set in the **settings.json** file.


### Required variables
> Because the settings file is in JSON format, backslashes must be doubled to avoid issues.  For example, ***C:\ProgramData\IntuneMigration*** will be written as ***C:\\\\ProgramData\\\\IntuneMigration***.  Don't worry as they will output correctly into the PowerShell code.

**$localPath**:
* *This is the local path that all working files will be stored on within the client machine.  It is recommended to keep this as the default **C:\ProgramData\IntuneMigration***

**$sourceTenant**
* **$clientID**:
    * *The app registration client ID in the source Azure tenant*
* **$clientSecret**:
    * *The client secret value for the app registration*
* **$tenantName**:
    * *Source tenant domain name*


**$targetTenant**
* **$clientID**:
    * *The app registration client ID in the target Azure tenant*
* **$clientSecret**:
    * *The client secret value for the app registration*
* **$tenantName**:
    * *Target tenant domain name*
* **$tenantID**:
    * *Target tenant ID*

**$regPath**:
* *Registry path needed to write local migration attributes to.  It is recommended to keep this as the default **HKLM\SOFTWARE\IntuneMigration***


## Provisioning package
A Windows Provisioning Package is required for the migration solution to work.  This can be created with the Windows Configuration Designer application found here:
https://apps.microsoft.com/detail/9NBLGGH4TX22?hl=en-US&gl=US

Instructions for generating the package and troubleshooting can be found here:
https://www.getrubix.com/blog/tenant-to-tenant-intune-device-migration-part-4-the-bulk-token

## Application registrations
App registrations are created in both **Tenant A** and **Tenant B**. This will be the primary means of authenticating objects throughout the various scripts used in the process.

Both registratinos will require the following permissions:
* Device.ReadWrite.All
* DeviceManagementApps.ReadWrite.All
* DeviceManagementConfiguration.ReadWrite.All
* DeviceManagementManagedDevices.PrivilegedOperations.All
* DeviceManagementManagedDevices.ReadWrite.All
* DeviceManagementServiceConfig.ReadWrite.All
* User.ReadWrite.All

## Migration solution overview
Tenant to tenant Microsoft Intune device migration As more and more organizations adopt Intune to manage PCs, this was an inevitable scenario. Companies can split into several companies, business acquire new businesses, organizations divest; all reasons you may need to move a PC to a different tenant. This isn’t new, as Active Directory domain migrations are a prevalent process.

But when your PC is Azure AD joined, Autopilot registered, and Intune managed, the only way to move it is to wipe or reimage the device, de-register it from Autopilot, and start all over again in the new tenant. Well, the only “official” way as supported by Microsoft.

Wiping a PC, re-registering it, and waiting for it to go through the Autopilot provisioning process again probably takes a minimum of 2 hours, at best. At worst, you could have users going a whole day or more without a working machine. That’s not good. At least that’s what a large customer of mine thought about 3 years ago when they were facing a divestiture.

This customer had roughly 15,000 Windows machines deployed via Autopilot and Intune. Due to the divestiture, about half of those users would now belong to a new Azure AD tenant, and their PC would need to move to a new Intune environment as well. While evaluating how to move PCs, they were very clear that any extended downtime was unacceptable, despite Microsoft stating this is “just how the process works”.

The customer asked me if there was anyway to automate this process to streamline it and make the end user experience as quick and painless as possible. After some tinkering, Jesse (my lead solutions architect) and I came up with a workable solution. It wasn’t perfect, but it worked, requiring nothing more than one reboot. This more than satisfied our customer’s ask.

Since that time, we have been gradually refining the process, adding more capabilities and automating more pieces. Finally, I believe it is at a point where it can be shared and hopefully help those who are in a similar situation.

### Who can use this?
If you’ve made it this far, or have had any hands-on experience with Intune, you’re probably wondering what we did to accomplish this crazy task. Let’s start with some assumptions, before getting into to the actual solution.

For clarity’s sake, we will be referring to the two Azure tenants as **Tenant A** and **Tenant B**.
**Tenant A** will be the source, or original tenant from which we are migrating from.

**Tenant B** will be the target, or destination tenant from which we are migration to.

We will assume the following about **Tenant A**:

* Users have a minimum license of Intune and Azure AD Premium P1
* Devices are registered in Autopilot
* Devices are Azure AD joined (not local Active Directory joined)
* Devices are enrolled in Intune

Now with any migration, an actual migration has to occur. Let’s make the following assumptions about that migration:

* New identities have been created for users in **Tenant B**
* User Microsoft online data (Exchange online, OneDrive, SharePoint) has been staged and transitioned to **Tenant B**

We will then assume the following about **Tenant B**:

* Users have a minimum license of Intune and Azure AD Premium P1
* Intune has been configured to support the desired configurations, applications, and policy to support devices


