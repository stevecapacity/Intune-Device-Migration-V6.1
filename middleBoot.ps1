$settings = Get-Content -Path "$($PSScriptRoot)\settings.json" | ConvertFrom-Json

$localPath = $settings.localPath
if(!(Test-Path $localPath))
{
    mkdir $localPath
}

Start-Transcript -Path "$localPath\middleBoot.log" -Verbose

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