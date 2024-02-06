$settings = Get-Content -Path "$($PSScriptRoot)\settings.json" | ConvertFrom-Json

$logPath = $settings.logPath
Start-Transcript -Path "$logPath\middleBoot.log" -Verbose

# Disable middleBoot task
Write-Host "Disabling middleBoot task..."
try 
{
    Disable-ScheduledTask -TaskName "middleBoot" -ErrorAction Stop
    Write-Host "middleBoot task disabled"    
}
catch 
{
    $message = $_.Exception.Message
    Write-Host "middleBoot task not disabled: $message"
}

Start-Sleep -Seconds 2
Stop-Transcript

shutdown -r -t 5
