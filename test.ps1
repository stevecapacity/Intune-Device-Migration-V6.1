#using module ".\migrateFunctionPlusClass.psm1"


#$AMD2 = newDeviceObject


class test
{
    [string]$name
    [int]$age
    [string]$gender
    [string]$color
    [int]$size
    [bool]$isAlive
}


function testFunction()
{
    $test = [test]::new()
    $test.name = "John"
    $test.age = 25
    $test.gender = "blue"
    return $test
}

$steve = testFunction



$diskSize = (Get-WmiObject Win32_LogicalDisk | Where-Object {$_.DeviceID -eq "C:"}).Size