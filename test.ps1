<#function cleanupLogonCache()
{
    Param(
        [string]$logonCache = "HKLM:\SOFTWARE\Microsoft\IdentityStore\LogonCache",
        [string]$oldUserName = $OriginalUserName
    )
    
    log "Cleaning up identity store cache..."
    
    Get-ChildItem -Path $logonCache | ForEach-Object {
        $logonCacheGUID = $_.Name.Trim('{}')
        
        Get-ChildItem -Path "$logonCache\$logonCacheGUID" -ErrorAction SilentlyContinue | ForEach-Object {
            $subKey = $_.Name.Trim('{}')
            
            if ($subKey -in "Name2Sid", "SAM_Name", "Sid2Name") {
                Get-ChildItem -Path "$logonCache\$logonCacheGUID\$subKey" -ErrorAction SilentlyContinue | ForEach-Object {
                    $subFolder = $_.Name.Trim('{}')
                    $cacheUsername = Get-ItemPropertyValue -Path "$logonCache\$logonCacheGUID\$subKey\$subFolder" -Name "IdentityName" -ErrorAction SilentlyContinue
                    
                    if ($cacheUsername -eq $oldUserName) {
                        Remove-Item -Path "$logonCache\$logonCacheGUID\$subKey\$subFolder" -Recurse -Force
                        log "Registry key deleted: $logonCache\$logonCacheGUID\$subKey\$subFolder"
                    }
                }
            }
        }
    }
}#>