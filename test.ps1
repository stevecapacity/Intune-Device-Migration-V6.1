Import-Module ".\migrateFunctionPlusClass.psm1"

$pc = newDeviceObject

function getGraphInfo()
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [object[]]$device
    )
       
}