Import-Module ".\migrateFunctionPlusClass.psm1"

$pc = newDeviceObject

function getGraphInfo()
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [object[]]$device
    )
    if($device.mdm -eq $true)
    {
        $intuneObject = Invoke-RestMethod -Method Get -Uri "https://graph.microsoft.com/beta/deviceManagement/managedDevices?`$filter=serialNumber eq '$($device.serialNumber)'" -Headers $headers
        $device += @{
            intuneId = $intuneObject.value.id
            azureAdDeviceId = $intuneObject.value.aadDeviceId
        }
        return $device
    }
    else
    {
        Write-Output "Device is not managed by MDM"
    }   
}