# random password generator
$chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_-=+?<>~"
$random = 1..16 | ForEach-Object { Get-Random -Maximum $chars.Length } | ForEach-Object { $chars[ $_ ] }
$passwordString = -join $random

# logon provider disable
$path = "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers\{60b78e88-ead8-445c-9cfd-0b87f74ea6cd}"
# Add DWORD Name = "Disabled" Value = "1"
reg.exe add $path /v "Disabled" /t REG_DWORD /d 1 /f | Out-Host

# disable windows hello
$path = "HKLM\SOFTWARE\Policies\Microsoft\Windows\System"
# Add DWORD Name = "AllowDomainPINLogon" Value = "0"
reg.exe add $path /v "AllowDomainPINLogon" /t REG_DWORD /d 0 /f | Out-Host

# create a scheduled task to check if the WINRE partition is mounted at every logon
$taskName = "CheckWinreMounted"
$taskPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\$taskName"
$taskExists = Test-Path $taskPath
if($taskExists)
{
    Write-Host "Task $taskName already exists"
}
else
{
    Write-Host "Creating task $taskName..."
    $taskAction = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-ExecutionPolicy Bypass -File `"$($PSScriptRoot)\checkWinreMounted.ps1`""
    $taskTrigger = New-ScheduledTaskTrigger -AtLogOn
    $taskSettings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -RunOnlyIfNetworkAvailable -DontStopOnIdleEnd
    $taskPrincipal = New-ScheduledTaskPrincipal -GroupId "NT AUTHORITY\SYSTEM" -RunLevel Highest
    Register-ScheduledTask -TaskName $taskName -Action $taskAction -Trigger $taskTrigger -Settings $taskSettings -Principal $taskPrincipal | Out-Null
    Write-Host "Task $taskName created"
}

