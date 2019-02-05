<#
    .Synopsis
        Reports list of orphaned disk from given Azure subscriptions

    .Parameter SubList
        Specify the text file with list of subscriptions to scan

    .Parameter DeleteInFile
        Specify the CSV file with list of VHDs to delete
        (NOTE: gather the CSV report using -SubList option first)

    .Parameter WhatIf
        Dry run/Read-only; Do not delete any orphaned VHDs

    .Example
        Get-AzureOrphanedDisks.ps1 -SubList C:\temp\subs.txt
        Redirects output of the script to 'C:\temp\OrphanedDisks-yyyymmdd-hhmmss.csv' e.g. 'c:\temp\OrphanedDisks-20161013-144034.csv'

    .Example
        Get-AzureOrphanedDisks.ps1 -DeleteInFile c:\temp\OrphanedDisks-20161013-144034.csv
        Reads list of VHDs flagged for deletion (i.e.,'DoNotDelete' column is blank) and deletes them
        Skips VHDs flagged for 'DONotDelete'=Y or 'DoNotDelete'=Yes

    .Notes
        NAME:      Get-AzureOrphanedDisks.ps1
        AUTHOR:    Pavan Kumar Mayakuntla
        LASTEDIT:  5/7/2018
#>

[CmdletBinding()]
Param(
    [Parameter()]
    [String]
    $SubList,

    [Parameter()]
    [String]
    $DeleteInFile,

    [Switch]
    $WhatIf
)

if (($SubList -and $DeleteInFile) -or (!$SubList -and !$DeleteInFile)) {
    Write-Host "ERROR: Please specify either 'SubList' OR 'DeleteInFile' parameter"
    Exit 1
}

$flag = 0
$outFolder = "c:\temp\"
$module = 'Azure'
# Check Azure module existence
if (!(Get-Module $module -ErrorAction SilentlyContinue)) {
    try {
        Import-Module $module
    }
    catch {
        "ERROR : Failed to load $module module, exiting"
        Exit 1
    }
}

# Prerequisite: Azure 3.1.0 module
if ((get-module azure).version -ge '3.1.0') {
    Write-Verbose "$module module is already loaded"
} else {
    Write-Host (Get-Date -format "yyyyMMdd HH:mm:ss") ": ERROR: Azure module version should be >3.1.0, exiting"
    Exit 1
}

$outFileName = "OrphanedDisks-" + (Get-Date -format "yyyyMMdd-HHmmss") + ".csv"
$outFile = Join-Path $outFolder $outFileName

$logName = "Get-AzureOrphanedDisks-LogFile-" + (Get-Date -format "yyyyMMdd-HHmmss") + ".log"
$logFile = Join-Path $outFolder $logName

Start-Transcript -Path $logFile
Write-Host (Get-Date -format "yyyyMMdd HH:mm:ss") ": INFO : Starting the script (last edit: 5/7/2018) (USER: ${env:username}, COMPUTER: ${env:computername})"
# Read subscriptions list from input text file to scan for Orphaned Disks
if ($SubList) {
    $subs = Get-Content -Path $SubList
    Write-Host (Get-Date -format "yyyyMMdd HH:mm:ss") ": INFO : Orphaned disk (if found) list will be saved to $outFile"
    foreach ($sub in $subs) {
        $sub = $sub.Trim() # Trim leading/trailing spaces
        if (!$sub) { Write-Host (Get-Date -format "yyyyMMdd HH:mm:ss") ": INFO : Skipping sub '$sub' (", (++($subs.IndexOf($sub))), "out of", $subs.count, ")--empty sub name?"; continue } # Skip empty lines
        Write-Host (Get-Date -format "yyyyMMdd HH:mm:ss") ": INFO : Scanning sub '$sub' (", (++($subs.IndexOf($sub))), "out of", $subs.count, ")"

        # Query the Classic/ASM subscription
        Select-AzureSubscription -SubscriptionName "$sub" -ErrorAction SilentlyContinue
        if (!$?) {
            write-host (Get-Date -format "yyyyMMdd HH:mm:ss") ": ERROR: Failed to login in classic mode Azure sub (classic) '$sub', error:", $ERROR[0].exception.message
        } else {
            $orphanedVHDs = Get-AzureDisk | Where-Object {$_.AttachedTo –eq $null}
            if (!$?) {
                write-host (Get-Date -format "yyyyMMdd HH:mm:ss") ": ERROR: Failed to get orphaned disk list (classic) in sub '$sub', error:", $ERROR[0].exception.message
            } else {
                if ($orphanedVHDs) {
                    Write-Host (Get-Date -format "yyyyMMdd HH:mm:ss") ": INFO : Found", $orphanedVHDs.count , "Orphaned VHDs (classic) in sub '$sub'"
#$object = New-Object PSObject –Prop $StorAcctAndCntr
#$StorAcctAndCntr = @()
#$orphanedVHDs | % {
#    $object.StorAccount = $_.MediaLink.Host.split(".")[0]
#    $object.StorContainer = $_.MediaLink.localPath.split('/')[1]
#    $StorAcctAndCntr += $object
#}
#write-host $StorAcctAndCntr
#exit
                    Write-Host (Get-Date -format "yyyyMMdd HH:mm:ss") ": INFO : Retrieving age (last modifed time) of the VHDs in sub '$sub'.  Takes a few minutes.."
                    $flag = 1
                    $storAccts = Get-AzureStorageAccount
                    #$allBlobs = $storAccts | Get-AzureStorageContainer | Get-AzureStorageBlob | ? {$_.Name -match '\.vhd$'}
                    $allBlobs = @()
                    $saccount = 0
                    $saincr = 0
                    foreach ($storAcct in $storAccts) {
                        #$strCntnr = Get-AzureStorageContainer -context $storAcct.context
                        # Azure sometimes throws below error. Before 1.5 module, limitation is 300 calls in 5 min.  Hence, continue to pause 
                        #   "TooManyRequests: Too many requests received. Retry after some time."
                        #Write-Progress -Activity "Reading Storage Accounts in '$sub'" -Status 'Progress->' -PercentComplete (++($storAccts.IndexOf($storAcct))) -CurrentOperation "Outer loop - Parsing Storage Accounts"`
                        $isError=0
                        $sacount = ++$saincr # (++($storAccts.IndexOf($storAcct)))
                        $sacountTotal = $storAccts.count
                        $saname = $storAcct.storageAccountName
                        Write-Host "`r" (Get-Date -format "yyyyMMdd HH:mm:ss") ": INFO : Reading Stor Acct '$saname' ($sacount in $sacountTotal) in '$sub' (classic)" -NoNewLine
                        $storCntrs = @()
                        for ($i=1;$i -le 10;$i++) {
                            $storCntrs = Get-AzureStorageContainer -context $storAcct.context
                            if ($?) {
                                break
                                if ($isError) { Write-Host (Get-Date -format "yyyyMMdd HH:mm:ss") ": INFO : Successfully processed" $storAcct.StorageAccountName " after pausing and retrying" }
                            } else {
                                write-host (Get-Date -format "yyyyMMdd HH:mm:ss") ": ERROR:--" $error[0].exception.message "--while processing" $storAcct.StorageAccountName "; Delay 30 sec and retry"
                                start-sleep -seconds 30
                                $isError=1
                            }
                        }
                        $scincr = 0
                        $isError = 0
                        foreach ($strCntr in $storCntrs) {
                            $sccount = ++$scincr # (++($storCntrs.IndexOf($strCntr)))
                            $scname = $strCntr.name
                            $sccountTotal = $storCntrs.count
                            for ($i=1;$i -le 3;$i++) {
                                #Write-Progress -Activity "Reading '$sub': Storage Account '$saname' ($sacount in $sacountTotal) -> container ($sccount out of $sccountTotal)" -Status "Container Name: '$scname'" -CurrentOperation "Looking for Orphaned VHDs in '$scname' container"
                                Write-Progress -Activity "Reading sub '$sub' (classic) -> Storage Account -> container" -Status "Storage Account ($sacount out of $sacountTotal): '$saname'" -CurrentOperation "Container Name ($sccount out of $sccountTotal): '$scname'. Scanning for Orphaned VHDs.."
                                Write-Host "`r" (Get-Date -format "yyyyMMdd HH:mm:ss") ": INFO :     Reading container '$scname' ($sccount in $sccountTotal) (Attempt: $i)" -NoNewLine
                                $blobs = Get-AzureStorageBlob -Container $strCntr.Name -Context $storAcct.context -ServerTimeoutPerRequest 300 -ClientTimeoutPerRequest 360 | ? {$_.Name -match '\.vhd$'}
                                if ($?) {
                                    $allBlobs += $blobs
                                    if ($isError) { Write-Host (Get-Date -format "yyyyMMdd HH:mm:ss") ": INFO : Successfully processed" $storAcct.StorageAccountName "\" $strCntr.Name " after pausing and retrying" }
                                    break
                                #} elseif ($error[0].exception.message -match 'TooManyRequests') {
                                } else {
                                    write-host (Get-Date -format "yyyyMMdd HH:mm:ss") ": ERROR:--" $error[0].exception.message "--while processing" $storAcct.StorageAccountName "\" $strCntr.Name "; Delay 30 sec and retry"
                                    start-sleep -seconds 30
                                    $isError = 1
                                }
                            }
                        }
                    }
                    # Self-ref:
                    # ($allBlobs | where {$_.icloudblob.name -eq 'DEVAZADSQL028/DEVAZADSQL028-C.vhd'}).icloudblob.properties.leasestatus
                    # ($allBlobs | where {$_.icloudblob.uri -eq 'https://avmmdev1.blob.core.windows.net/vhds/UAT-REDUSC-02/UAT-REDUSC-02-O.vhd'}).lastmodified.localdatetime
                    # NOTE: $_.icloudblob.uri fails as some of the blobs do not seem to have this populated.  Fallen back to name comparison
                    foreach ($orphanVHD in $orphanedVHDs) {
                        # E.g., for self-reference: Get-AzureStorageAccount sdodev2sg17  | Get-AzureStorageBlob -container vhds -Blob UATRDSQL10311/UATRDSQL10311-T.vhd
                        $myStorAcct = ($orphanVHD).MediaLink.Host.split(".")[0]
                        $myStorCntnr = ($orphanVHD).MediaLink.localPath.split('/')[1]
                        $myStorBlob = ($orphanVHD).MediaLink.localPath.Replace("/$myStorCntnr/",'')
                        # For self-ref:
                        # $vhd = Get-AzureStorageAccount $myStorAcct  | Get-AzureStorageBlob -container $myStorCntnr -Blob $myStorBlob
                        # $ModifiedLocal = ($allBlobs | where {$_.icloudblob.uri -eq $orphanVHD.MediaLink}).lastmodified.localdatetime
                        # NOTE: some blobs names are same.  Hence, validate if the blobs belong to same storage account
                        $myblob = ($allBlobs | where {($_.icloudblob.name -eq $myStorBlob) -and ($_.context.StorageAccountName -eq $myStorAcct)})
                        #clear-variable ModifiedLocal, Now, Days
                        $ModifiedLocal = $myblob.lastmodified.localdatetime
                        # Get utilization for blob
                        $Blob = $myblob
                        $blobSizeInBytes  = 0
                        if ($Blob.BlobType -eq [Microsoft.WindowsAzure.Storage.Blob.BlobType]::BlockBlob) {
#write-host "--", $Blob.BlobType , "<--blobtype"
                            $blobSizeInBytes += 8
                            $Blob.ICloudBlob.DownloadBlockList() | 
                            ForEach-Object { $blobSizeInBytes += $_.Length + $_.Name.Length }
                            $blobSizeInBytes = "{0:N2}" -f ($blobSizeInBytes/1gb)
#write-host "---->", $Blob.name, "           3->", $blobSizeInBytes
                        } else {
#write-host "--", $Blob.BlobType , "<--blobtype"
                            $Blob.ICloudBlob.GetPageRanges() | 
                            ForEach-Object { $blobSizeInBytes += 12 + $_.EndOffset - $_.StartOffset }
                            $blobSizeInBytes = "{0:N2}" -f ($blobSizeInBytes/1gb)
#write-host "---->", $Blob.name, "           4->", $blobSizeInBytes
                        }
                        $Now           = [datetime]::Now
                        ### If a change was made less than 24 hours ago, but it was yesterday return one day and not zero ###
                        if ($ModifiedLocal) { $Days = (New-TimeSpan -Start $ModifiedLocal -End $Now).Days; $ModifiedLocalTime = $ModifiedLocal.ToString('MM/dd/yyyy HH:mm')}
                        else {$Days = "CouldNotDetermine"; $ModifiedLocalTime = "CouldNotDetermine"}
                        $Properties = [ordered]@{
                            SubName        = $sub
                            VHD            = $orphanVHD.DiskName
                            SizeDefinedInGB  = $orphanVHD.DiskSizeinGb
                            SizeUtilizedInGB = $blobSizeInBytes
                            StorageType    = ($storAccts | where {$_.storageaccountname -eq $myStorAcct}).AccountType
                            "Modified/Created(MgdDsk)"       = $ModifiedLocalTime
                            LastWriteDays  = $Days
                            StorageAccount = $myStorAcct
                            FullPath       = $orphanVHD.MediaLink
                            SubType        = "Classic"
                            DoNoTDelete    = ' '
                        }
                        $Object = New-Object PSObject -Property $Properties
                        $Object | Export-Csv -Append -NoTypeInformation $outFile
                    }
                    clear-variable orphanedVHDs
                } else {
                    Write-Host (Get-Date -format "yyyyMMdd HH:mm:ss") ": INFO : No Orphaned VHDs (classic) found in sub '$sub'"
                }
            }
        }

        # Query the ARM subscription
        Try {
            Get-AzureRmContext -ErrorAction Continue | out-null
        }
        Catch [System.Management.Automation.PSInvalidOperationException] {
            Write-Host (Get-Date -format "yyyyMMdd HH:mm:ss") ": INFO : Please login to Azure in the prompt/window"
            Login-AzureRmAccount
        }
        Select-AzureRmSubscription -SubscriptionName "$sub" -ErrorAction SilentlyContinue | out-null
        if (!$?) {
            write-host (Get-Date -format "yyyyMMdd HH:mm:ss") ": ERROR: Skipping sub (ARM) '$sub' with error:", $ERROR[0].exception.message
        } else {
            ## Query orpahned VHDs in unmanaged disks
            $VmVhd = @()
            ### Get registerd in VM VHD in all ResourceGroups ###
            Foreach ($AzRg in ($ResGroup = Get-AzureRmResourceGroup)) {
                Foreach ($AzVm in ($VM = Get-AzureRmVM -ResourceGroupName ($AzRg.ResourceGroupName) -WarningAction SilentlyContinue)) {
                    $VmVhd += $AzVm.StorageProfile.OsDisk.Vhd.Uri
                    Foreach ($DataDisk in $AzVm.StorageProfile.DataDisks) {
                        $VmVhd += ($DataDisk.Vhd.Uri)
                    }
                }
            }

            $orphanedCount = 0
            $armStorAccts = Get-AzureRmStorageAccount
            #$SaVhd = $armStorAccts |Get-AzureStorageContainer |Get-AzureStorageBlob  -ServerTimeoutPerRequest 300 -ClientTimeoutPerRequest 360 |? {$_.Name -match '\.vhd$'}))
            $asaincr = 0
            $asacount = 0
            Foreach ($armStorAcct in $armStorAccts) {
                $isError=0
                $asacount = ++$asaincr # (++($storAccts.IndexOf($storAcct)))
                $asacountTotal = $armStorAccts.count
                $asaname = $armStorAcct.storageAccountName
                Write-Host "`r" (Get-Date -format "yyyyMMdd HH:mm:ss") ": INFO : Reading Stor Acct '$asaname' ($asacount in $asacountTotal) in '$sub' (ARM)" -NoNewLine
                $armStorCntrs = @()
                for ($i=1;$i -le 10;$i++) {
                    $armStorCntrs = Get-AzureStorageContainer -context $armStorAcct.context
                    if ($?) {
                        break
                        if ($isError) { Write-Host (Get-Date -format "yyyyMMdd HH:mm:ss") ": INFO : Successfully processed" $armStorAcct.StorageAccountName " after pausing and retrying" }
                    } else {
                        # Skip if lock found for the resource group
                        #if ($error[0].exception.message -match '') {
                        #    break
                        #}
                        write-host (Get-Date -format "yyyyMMdd HH:mm:ss") ": ERROR:--" $error[0].exception.message "--while processing" $armStorAcct.StorageAccountName "; Delay 30 sec and retry"
                        start-sleep -seconds 30
                        $isError=1
                    }
                }
                $ascincr = 0
                $isError = 0
                foreach ($armStrCntr in $armStorCntrs) {
                    $asccount = ++$ascincr # (++($storCntrs.IndexOf($strCntr)))
                    $ascname = $armStrCntr.name
                    $asccountTotal = $armStorCntrs.count
                    for ($i=1;$i -le 3;$i++) {
                        #Write-Progress -Activity "Reading '$sub': Storage Account '$saname' ($sacount in $sacountTotal) -> container ($sccount out of $sccountTotal)" -Status "Container Name: '$scname'" -CurrentOperation "Looking for Orphaned VHDs in '$scname' container"
                        Write-Progress -Activity "Reading sub '$sub' (ARM) -> Storage Account -> container" -Status "Storage Account ($asacount out of $asacountTotal): '$asaname'" -CurrentOperation "Container Name ($asccount out of $asccountTotal): '$ascname'. Scanning for Orphaned VHDs.."
                        Write-Host "`r" (Get-Date -format "yyyyMMdd HH:mm:ss") ": INFO :     Reading container '$ascname' ($asccount in $asccountTotal) (Attempt: $i)" -NoNewLine
#                $SaVhd = Get-AzureStorageContainer -context $armStorAcct.context |Get-AzureStorageBlob -ServerTimeoutPerRequest 300 -ClientTimeoutPerRequest 360 |? {$_.Name -match '\.vhd$'}
                        $SaVhd = Get-AzureStorageBlob -Container $armStrCntr.Name -Context $armStorAcct.context -ServerTimeoutPerRequest 300 -ClientTimeoutPerRequest 360 | ? {$_.Name -match '\.vhd$'}
                        if ($?) {
                            foreach ($vhd in $SaVhd) {
                                If (($VmVhd -notcontains $Object.FullPath) -and ($Vhd.ICloudBlob.properties.leasestatus -eq 'Unlocked')) {
                                    $ModifiedLocal = $Vhd.LastModified.LocalDateTime
                                    $Now           = [datetime]::Now
                                    if ($ModifiedLocal) { $Days = (New-TimeSpan -Start $ModifiedLocal -End $Now).Days; $ModifiedLocalTime = $ModifiedLocal.ToString('MM/dd/yyyy HH:mm')}
                                    else {$ModifiedLocalTime = "CouldNotDetermine"; $Days = "CouldNotDetermine"}
                        $Blob = $vhd
                        $blobSizeInBytes  = 0
                        if ($Blob.BlobType -eq [Microsoft.WindowsAzure.Storage.Blob.BlobType]::BlockBlob) {
#write-host "--", $Blob.BlobType , "<--blobtype"
                            $blobSizeInBytes += 8
                            $Blob.ICloudBlob.DownloadBlockList() | 
                            ForEach-Object { $blobSizeInBytes += $_.Length + $_.Name.Length }
                            $blobSizeInBytes = "{0:N2}" -f ($blobSizeInBytes/1gb)
#write-host "---->", $Blob.name, "           3->", $blobSizeInBytes
                        } else {
#write-host "--", $Blob.BlobType , "<--blobtype"
                            $Blob.ICloudBlob.GetPageRanges() | 
                            ForEach-Object { $blobSizeInBytes += 12 + $_.EndOffset - $_.StartOffset }
                            $blobSizeInBytes = "{0:N2}" -f ($blobSizeInBytes/1gb)
#write-host "---->", $Blob.name, "           4->", $blobSizeInBytes
                        }
                                    $Properties = [ordered]@{
                                        SubName        = $sub
                                        VHD            = $Vhd.Name
                                        SizeDefinedInGB  = [Math]::Round($Vhd.Length/1GB,0)
                                        SizeUtilizedInGB = $blobSizeInBytes
                                        StorageType    = ($armStorAcct | select -ExpandProperty sku).tier
                                        "Modified/Created(MgdDsk)"       = $ModifiedLocalTime
                                        LastWriteDays  = $Days
                                        StorageAccount = $Vhd.Context.StorageAccountName
                                        FullPath       = $Vhd.ICloudBlob.Uri
                                        SubType        = "ARM"
                                        DoNoTDelete    = ' '
                                    }
                                    $Object = New-Object PSObject -Property $Properties
                                    $Object |Export-Csv -Append -NoTypeInformation $outFile
                                    $flag = 1
                                    $orphanedCount++
                                }
                            }
                            if ($iserror) { Write-Host (Get-Date -format "yyyyMMdd HH:mm:ss") ": INFO : Successfully processed" $armStorAcct.StorageAccountName "\" $armStrCntr.Name " after pausing and retrying" }
                            break
                        #} elseif ($error[0].exception.message -match 'TooManyRequests') {
                        } else {
                            write-host (Get-Date -format "yyyyMMdd HH:mm:ss") ": ERROR:--" $error[0].exception.message "--while processing" $armStorAcct.StorageAccountName "\" $armStrCntr.Name "; Delay 30 sec and retry"
                            start-sleep -seconds 30
                            $iserror = 1
                        }
                    }
                }
            }
            # Query unmanaged VHDs on managed disks
            $orphanedManagedVHDs = Get-AzureRmDisk -WarningAction SilentlyContinue | Where {$_.OwnerId -eq $null -and $_.ManagedBy -eq $null}
            foreach ($orphanedManagedVHD in $orphanedManagedVHDs) {
                $Properties = [ordered]@{
                    SubName        = $sub
                    VHD            = $orphanedManagedVHD.Name
                    SizeDefinedInGB  = $orphanedManagedVHD.DiskSizeGB
                    SizeUtilizedInGB = "NA"
                    StorageType    = $orphanedManagedVHD.AccountType
                    "Modified/Created(MgdDsk)" = $orphanedManagedVHD.TimeCreated
                    LastWriteDays  = "NA"
                    StorageAccount = "ManagedDisk"
                    FullPath       = $orphanedManagedVHD.ID
                    SubType        = "ARM"
                    DoNoTDelete    = ' '
                }
                $Object = New-Object PSObject -Property $Properties
                $Object |Export-Csv -Append -NoTypeInformation $outFile
                $flag = 1
                $orphanedCount++
            }
            if ($orphanedCount) {
                Write-Host (Get-Date -format "yyyyMMdd HH:mm:ss") ": INFO : Found", $orphanedCount, "Orphaned VHDs (A) in sub '$sub'"
            } else {
                Write-Host (Get-Date -format "yyyyMMdd HH:mm:ss") ": INFO : No Orphaned VHDs (ARM) found in sub '$sub'"
            }
        }
    }
}

# Read Orphaned disk list from delete the Disks
if ($DeleteInFile) {
    $deleteVHDsList = Import-CSV -Path $DeleteInFile
    # Split Classic and ARM Orphaned disk list.  First, Classic Orphaned disks
    $deleteVHDsClassic = $deleteVHDsList | where {$_.SubType -eq 'Classic' -and $_.DoNotDelete -notmatch "Y|Yes"}
    if ($deleteVHDsClassic) {
        Write-Host (Get-Date -format "yyyyMMdd HH:mm:ss") ": INFO : Trying to delete Classic VHDs"
        foreach ($dvhd in $deleteVHDsClassic) {
            if (((Get-AzureSubscription -Current).SubscriptionName) -ne $dvhd.SubName) {
                Select-AzureSubscription -SubscriptionName $dvhd.SubName
                if (!$?){
                    write-host (Get-Date -format "yyyyMMdd HH:mm:ss") ": ERROR: Skipping sub (Classic) '$sub' with error:", $ERROR[0].exception.message
                    continue
                }
            }
            if (!$WhatIf) {
                Write-Host (Get-Date -format "yyyyMMdd HH:mm:ss") ": INFO : Trying to delete Classic VHD", $dvhd.VHD, "in", $dvhd.SubName
                # For self-reference: Get-AzureDisk -DiskName $dvhd.VHD
                if (Remove-AzureDisk -DiskName $dvhd.VHD -DeleteVHD) {
                    write-host (Get-Date -format "yyyyMMdd HH:mm:ss") ": INFO : Deleted Classic VHD", $dvhd.VHD, "in", $dvhd.SubName
                } else {
                    write-host (Get-Date -format "yyyyMMdd HH:mm:ss") ": ERROR: Failed to delete Classic VHD", $dvhd.VHD, "in", $dvhd.SubName
                }
            } else {
                 Write-Host (Get-Date -format "yyyyMMdd HH:mm:ss") ": WhatIf: Attempting to delete Classic VHD", $dvhd.VHD, "in", $dvhd.SubName
            }
        }
    }

    # Second, ARM Orphaned Managed and UnManaged disks
    $deleteVHDsARMManaged = $deleteVHDsList | where {$_.SubType -eq 'ARM' -and $_.DoNotDelete -notmatch "Y|Yes" -and $_.StorageAccount -match 'ManagedDisk'}
    if ($deleteVHDsARMManaged) {
        Try {
            Get-AzureRmContext -ErrorAction Continue | out-null
        }
        Catch [System.Management.Automation.PSInvalidOperationException] {
            Write-Host (Get-Date -format "yyyyMMdd HH:mm:ss") ": INFO : Please login to Azure in the prompt/window"
            Login-AzureRmAccount
        }
        Write-Host (Get-Date -format "yyyyMMdd HH:mm:ss") ": INFO : Deleting ARM Managed VHDs"
        foreach ($dvhd in $deleteVHDsARMManaged) {
            if (((Get-AzureRmContext).Subscription.Name) -ne $dvhd.SubName) {
                Select-AzureRmSubscription -SubscriptionName $dvhd.SubName | out-null
                if (!$?){
                    write-host (Get-Date -format "yyyyMMdd HH:mm:ss") ": ERROR: Skipping sub (ARM) '$sub' with error:", $ERROR[0].exception.message
                    continue
                }
            }
            #$myStorPath = $dvhd.FullPath -replace ('^http(:|s:)/{2}','')
            $myRG = ($dvhd.FullPath).split('/')[4]
            #$myStorBlob = ($myStorPath) -Replace (".*?/$myStorCntnr/",'')
            #$mystorageContext = (Get-AzureRmStorageAccount | Where-Object{$_.StorageAccountName -match $dvhd.StorageAccount}).Context
            if (!$WhatIf) {
                Write-Host (Get-Date -format "yyyyMMdd HH:mm:ss") ": INFO : Trying to delete ARM Managed VHD", $dvhd.VHD, "in", $dvhd.SubName
                 # Self-reference: Get-AzureRmStorageAccount  |where {$_.storageaccountname -match $dvhd.StorageAccount } | Get-AzureStorageBlob -container $myStorCntnr -Blob $myStorBlob
                Remove-AzureRmDisk -ResourceGroupName $myRG -Name $dvhd.VHD -Force -ErrorAction Stop
                if ($?) {
                    if (!(Get-AzureRmDisk -WarningAction SilentlyContinue| Where {$_.OwnerId -eq $null -and $_.ManagedBy -eq $null -and $_.ResourceGroupName -eq $myRG -and $_.Name -eq $dvhd.VHD} )) {
                        write-host (Get-Date -format "yyyyMMdd HH:mm:ss") ": INFO : Successfully deleted ", $dvhd.VHD, "in", $dvhd.SubName
                    }
                } else {
                    write-host (Get-Date -format "yyyyMMdd HH:mm:ss") ": INFO : Failed to delete ", $dvhd.VHD, "in", $dvhd.SubName
                }
            } else {
                 Write-Host (Get-Date -format "yyyyMMdd HH:mm:ss") ": WhatIf: Attempting to delete ARM VHD", $dvhd.VHD, "in", $dvhd.SubName
            }
        }
    }
    $deleteVHDsARM = $deleteVHDsList | where {$_.SubType -eq 'ARM' -and $_.DoNotDelete -notmatch "Y|Yes" -and $_.StorageAccount -notmatch 'ManagedDisk'}
    if ($deleteVHDsARM) {
        Try {
            Get-AzureRmContext -ErrorAction Continue | out-null
        }
        Catch [System.Management.Automation.PSInvalidOperationException] {
            Write-Host (Get-Date -format "yyyyMMdd HH:mm:ss") ": INFO : Please login to Azure in the prompt/window"
            Login-AzureRmAccount
        }
        Write-Host (Get-Date -format "yyyyMMdd HH:mm:ss") ": INFO : Deleting ARM Unmanaged VHDs"
        foreach ($dvhd in $deleteVHDsARM) {
            if (((Get-AzureRmContext).Subscription.Name) -ne $dvhd.SubName) {
                Select-AzureRmSubscription -SubscriptionName $dvhd.SubName | out-null
                if (!$?){
                    write-host (Get-Date -format "yyyyMMdd HH:mm:ss") ": ERROR: Skipping sub (ARM) '$sub' with error:", $ERROR[0].exception.message
                    continue
                }
            }
            $myStorPath = $dvhd.FullPath -replace ('^http(:|s:)/{2}','')
            $myStorCntnr = ($myStorPath).split('/')[1]
            $myStorBlob = ($myStorPath) -Replace (".*?/$myStorCntnr/",'')
            $mystorageContext = (Get-AzureRmStorageAccount | Where-Object{$_.StorageAccountName -match $dvhd.StorageAccount}).Context
            if (!$WhatIf) {
                Write-Host (Get-Date -format "yyyyMMdd HH:mm:ss") ": INFO : Trying to delete ARM VHD", $dvhd.VHD, "in", $dvhd.SubName
                 # Self-reference: Get-AzureRmStorageAccount  |where {$_.storageaccountname -match $dvhd.StorageAccount } | Get-AzureStorageBlob -container $myStorCntnr -Blob $myStorBlob
                Remove-AzureStorageBlob -Blob $myStorBlob -Container $myStorCntnr -Context $mystorageContext
                if ($?) {
                    if (!(Get-AzureStorageBlob -Context $mystorageContext -Container $myStorCntnr -blob $myStorBlob -ErrorAction Ignore)) {
                        write-host (Get-Date -format "yyyyMMdd HH:mm:ss") ": INFO : Successfully deleted ", $dvhd.VHD, "in", $dvhd.SubName
                    }
                } else {
                    write-host (Get-Date -format "yyyyMMdd HH:mm:ss") ": INFO : Failed to delete ", $dvhd.VHD, "in", $dvhd.SubName
                }
            } else {
                 Write-Host (Get-Date -format "yyyyMMdd HH:mm:ss") ": WhatIf: Attempting to delete ARM VHD", $dvhd.VHD, "in", $dvhd.SubName
            }
        }
    }
}

if ($flag) {
    Write-Host (Get-Date -format "yyyyMMdd HH:mm:ss") ": INFO : Ending the script.  Please check Orphaned disk list at $outFile"
} else {
    Write-Host (Get-Date -format "yyyyMMdd HH:mm:ss") ": INFO : Ending the script."
}

Stop-Transcript
# copy output file to central location for reference
copy-item $logFile "\\co1-dds-m01.redmond.corp.microsoft.com\logs\Get-AzureOrphanedDisks\"
if (test-path $outFile) { copy-item $outFile "\\co1-dds-m01.redmond.corp.microsoft.com\logs\Get-AzureOrphanedDisks\" }

