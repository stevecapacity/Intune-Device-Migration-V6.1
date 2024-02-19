# update samname in identityStore LogonCache (this is required when displaynames are the same in both tenants, and new samname gets random characters added at the end)
function updateSamNameLogonCache()
{
    Param(
        [string]$logonCache = "HKLM:\SOFTWARE\Microsoft\IdentityStore\LogonCache",
        [string]$targetSAMName = $originalUser -replace '.*\\'
    )

    if($newUser -like "$($originalUser)_*")
    {
        log "New user is $newUser, which is the same as $originalUser with _##### appended to the end. Removing appended characters on SamName in LogonCache registry..."

        $logonCacheGUID = (Get-ChildItem -Path $logonCache | Select-Object Name | Split-Path -Leaf).trim('{}')
        foreach($GUID in $logonCacheGUID)
        {
            $subKeys = Get-ChildItem -Path "$logonCache\$GUID" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name | Split-Path -Leaf
            if(!($subKeys))
            {
                log "No subkeys found for $GUID"
                continue
            }
            else
            {
                $subKeys = $subKeys.trim('{}')
                foreach($subKey in $subKeys)
                {
                    if($subKey -eq "Name2Sid")
                    {
                        $subFolders = Get-ChildItem -Path "$logonCache\$GUID\$subKey" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name | Split-Path -Leaf
                        if(!($subFolders))
                        {
                            log "Error - no sub folders found for $subKey"
                            continue
                        }
                        else
                        {
                            $subFolders = $subFolders.trim('{}')
                            foreach($subFolder in $subFolders)
                            {
                                $detectedUserSID = Get-ItemProperty -Path "$logonCache\$GUID\$subKey\$subFolder" | Select-Object -ExpandProperty "Sid" -ErrorAction SilentlyContinue
                                if($detectedUserSID -eq $newUserSID)
                                {
                                    Set-ItemProperty -Path "$logonCache\$GUID\$subKey\$subFolder" -Name "SAMName" -Value $targetSAMName -Force
                                    log "Attempted to update SAMName value (in Name2Sid registry folder) to '$targetSAMName'."
                                    continue                                       
                                }
                                else
                                {
                                    log "Detected Sid '$detectedUserSID' is for different user - skipping Sid in Name2Sid registry folder..."
                                }
                            }
                        }
                    }
                    elseif($subKey -eq "SAM_Name")
                    {
                        $subFolders = Get-ChildItem -Path "$logonCache\$GUID\$subKey" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name | Split-Path -Leaf
                        if(!($subFolders))
                        {
                            log "Error - no sub folders found for $subKey"
                            continue
                        }
                        else
                        {
                            $subFolders = $subFolders.trim('{}')
                            foreach($subFolder in $subFolders)
                            {
                                $detectedUserSID = Get-ItemProperty -Path "$logonCache\$GUID\$subKey\$subFolder" | Select-Object -ExpandProperty "Sid" -ErrorAction SilentlyContinue
                                if($detectedUserSID -eq $newUserSID)
                                {
                                    Rename-Item "$logonCache\$GUID\$subKey\$subFolder" -NewName $targetSAMName -Force
                                    log "Attempted to update SAM_Name key name (in SAM_Name registry folder) to '$targetSAMName'."
                                    continue                                       
                                }
                                else
                                {
                                    log "Skipping different user in SAM_Name registry folder (User: $subFolder, SID: $detectedUserSID)..."
                                }
                            }
                        }
                    }
                    elseif($subKey -eq "Sid2Name")
                    {
                        $subFolders = Get-ChildItem -Path "$logonCache\$GUID\$subKey" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name | Split-Path -Leaf
                        if(!($subFolders))
                        {
                            log "Error - no sub folders found for $subKey"
                            continue
                        }
                        else
                        {
                            $subFolders = $subFolders.trim('{}')
                            foreach($subFolder in $subFolders)
                            {
                                if($subFolder -eq $newUserSID)
                                {
                                    Set-ItemProperty -Path "$logonCache\$GUID\$subKey\$subFolder" -Name "SAMName" -Value $targetSAMName -Force
                                    log "Attempted to update SAM_Name value (in Sid2Name registry folder) to '$targetSAMName'."
                                    continue                                       
                                }
                                else
                                {
                                    log "Skipping different user SID ($subFolder) in Sid2Name registry folder..."
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    else
    {
        log "New username is $newUser, which does not match older username ($oldUser) with _##### appended to end. SamName LogonCache registry will not be updated."
    }
}

# update samname in identityStore Cache (this is required when displaynames are the same in both tenants, and new samname gets random characters added at the end)
function updateSamNameIdentityStore()
{
    Param(
        [string]$idCache = "HKLM:\Software\Microsoft\IdentityStore\Cache",
        [string]$targetSAMName = $originalUser -replace '.*\\'
    )
    log "Cleaning up identity store cache..."
    $idCacheKeys = (Get-ChildItem -Path $idCache | Select-Object Name | Split-Path -Leaf).trim('{}')
    foreach($key in $idCacheKeys)
    {
        $subKeys = Get-ChildItem -Path "$idCache\$key" -ErrorAction SilentlyContinue | Select-Object Name | Split-Path -Leaf
        if(!($subKeys))
        {
            log "No keys listed under '$idCache\$key' - skipping..."
            continue
        }
        else
        {
            $subKeys = $subKeys.trim('{}')
            foreach($subKey in $subKeys)
            {
                $subFolders = Get-ChildItem -Path "$idCache\$key\$subKey" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name | Split-Path -Leaf
                if(!($subFolders))
                {
                    log "No subfolders detected for $subkey- skipping..."
                    continue
                }
                else
                {
                    $subFolders = $subFolders.trim('{}')
                    foreach($subFolder in $subFolders)
                    {
                        if($subFolder -eq $newUserSID)
                        {
                            Set-ItemProperty -Path "$idCache\$key\$subKey\$subFolder" -Name "SAMName" -Value $targetSAMName -Force
                            log "Attempted to update SAMName value to $targetSAMName."
                        }
                    }
                }
            }
        }
    }
}