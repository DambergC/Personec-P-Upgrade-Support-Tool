function Invoke-DbaAdvancedRestore {
    <#
    .SYNOPSIS
        Allows the restore of modified BackupHistory Objects
        For 90% of users Restore-DbaDatabase should be your point of access to this function. The other 10% use it at their own risk

    .DESCRIPTION
        This is the final piece in the Restore-DbaDatabase Stack. Usually a BackupHistory object will arrive here from `Restore-DbaDatabase` via the following pipeline:
        `Get-DbaBackupInformation  | Select-DbaBackupInformation | Format-DbaBackupInformation | Test-DbaBackupInformation | Invoke-DbaAdvancedRestore`

        We have exposed these functions publicly to allow advanced users to perform operations that we don't support, or won't add as they would make things too complex for the majority of our users

        For example if you wanted to do some very complex redirection during a migration, then doing the rewrite of destinations may be better done with your own custom scripts rather than via `Format-DbaBackupInformation`

        We would recommend ALWAYS pushing your input through `Test-DbaBackupInformation` just to make sure that it makes sense to us.

    .PARAMETER BackupHistory
        The BackupHistory object to be restored.
        Can be passed in on the pipeline

    .PARAMETER SqlInstance
        The SqlInstance to which the backups should be restored

    .PARAMETER SqlCredential
        Login to the target instance using alternative credentials. Accepts PowerShell credentials (Get-Credential).

        Windows Authentication, SQL Server Authentication, Active Directory - Password, and Active Directory - Integrated are all supported.

        For MFA support, please use Connect-DbaInstance.

    .PARAMETER OutputScriptOnly
        If set, the restore will not be performed, but the T-SQL scripts to perform it will be returned

    .PARAMETER VerifyOnly
        If set, performs a Verify of the backups rather than a full restore

    .PARAMETER RestoreTime
        Point in Time to which the database should be restored.

        This should be the same value or earlier, as used in the previous pipeline stages

    .PARAMETER StandbyDirectory
        A folder path where a standby file should be created to put the recovered databases in a standby mode

    .PARAMETER NoRecovery
        Leave the database in a restoring state so that further restore may be made

    .PARAMETER MaxTransferSize
        Parameter to set the unit of transfer. Values must be a multiple by 64kb

    .PARAMETER Blocksize
        Specifies the block size to use. Must be one of 0.5kb,1kb,2kb,4kb,8kb,16kb,32kb or 64kb
        Can be specified in bytes
        Refer to https://msdn.microsoft.com/en-us/library/ms178615.aspx for more detail

    .PARAMETER BufferCount
        Number of I/O buffers to use to perform the operation.
        Refer to https://msdn.microsoft.com/en-us/library/ms178615.aspx for more detail

    .PARAMETER Continue
        Indicates that the restore is continuing a restore, so target database must be in Recovering or Standby states
        When specified, WithReplace will be set to true

    .PARAMETER AzureCredential
        AzureCredential required to connect to blob storage holding the backups

    .PARAMETER WithReplace
        Indicated that if the database already exists it should be replaced

    .PARAMETER KeepReplication
        Indicates whether replication configuration should be restored as part of the database restore operation

    .PARAMETER KeepCDC
        Indicates whether CDC information should be restored as part of the database

    .PARAMETER PageRestore
        The output from Get-DbaSuspect page containing the suspect pages to be restored.

    .PARAMETER WhatIf
        Shows what would happen if the cmdlet runs. The cmdlet is not run.

    .PARAMETER Confirm
        Prompts you for confirmation before running the cmdlet.

    .PARAMETER ExecuteAs
        If set, this will cause the database(s) to be restored (and therefore owned) as the SA user

    .PARAMETER StopMark
        Mark in the transaction log to stop the restore at

    .PARAMETER StopBefore
        Switch to indicate the restore should stop before StopMark

    .PARAMETER StopAfterDate
        By default the restore will stop at the first occurence of StopMark found in the chain, passing a datetime where will cause it to stop the first StopMark atfer that datetime

    .PARAMETER EnableException
        Replaces user friendly yellow warnings with bloody red exceptions of doom!
        Use this if you want the function to throw terminating errors you want to catch.

    .NOTES
        Tags: Restore, Backup
        Author: Stuart Moore (@napalmgram), stuart-moore.com

        Website: https://dbatools.io
        Copyright: (c) 2018 by dbatools, licensed under MIT
        License: MIT https://opensource.org/licenses/MIT

    .LINK
        https://dbatools.io/Invoke-DbaAdvancedRestore

    .EXAMPLE
        PS C:\> $BackupHistory | Invoke-DbaAdvancedRestore -SqlInstance MyInstance

        Will restore all the backups in the BackupHistory object according to the transformations it contains

    .EXAMPLE
        PS C:\> $BackupHistory | Invoke-DbaAdvancedRestore -SqlInstance MyInstance -OutputScriptOnly
        PS C:\> $BackupHistory | Invoke-DbaAdvancedRestore -SqlInstance MyInstance

        First generates just the T-SQL restore scripts so they can be sanity checked, and then if they are good perform the full restore.
        By reusing the BackupHistory object there is no need to rescan all the backup files again

    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = "Low")]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSAvoidUsingPlainTextForPassword", "AzureCredential", Justification = "For Parameter AzureCredential")]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSUseOutputTypeCorrectly", "", Justification = "PSSA Rule Ignored by BOH")]
    param (
        [parameter(Mandatory, ValueFromPipeline)]
        [Object[]]$BackupHistory,
        [DbaInstanceParameter]$SqlInstance,
        [PSCredential]$SqlCredential,
        [switch]$OutputScriptOnly,
        [switch]$VerifyOnly,
        [datetime]$RestoreTime = (Get-Date).AddDays(2),
        [string]$StandbyDirectory,
        [switch]$NoRecovery,
        [int]$MaxTransferSize,
        [int]$BlockSize,
        [int]$BufferCount,
        [switch]$Continue,
        [string]$AzureCredential,
        [switch]$WithReplace,
        [switch]$KeepReplication,
        [switch]$KeepCDC,
        [object[]]$PageRestore,
        [string]$ExecuteAs,
        [switch]$StopBefore,
        [string]$StopMark,
        [datetime]$StopAfterDate,
        [switch]$EnableException
    )
    begin {
        try {
            $server = Connect-DbaInstance -SqlInstance $SqlInstance -SqlCredential $SqlCredential
        } catch {
            Stop-Function -Message "Failure" -Category ConnectionError -ErrorRecord $_ -Target $SqlInstance
            return
        }
        if ($KeepCDC -and ($NoRecovery -or ('' -ne $StandbyDirectory))) {
            Stop-Function -Category InvalidArgument -Message "KeepCDC cannot be specified with Norecovery or Standby as it needs recovery to work"
            return
        }

        if ($null -ne $PageRestore) {
            Write-Message -Message "Doing Page Recovery" -Level Verbose
            $tmpPages = @()
            foreach ($Page in $PageRestore) {
                $tmpPages += "$($Page.FileId):$($Page.PageID)"
            }
            $NoRecovery = $True
            $Pages = $tmpPages -join ','
        }
        $internalHistory = @()
    }
    process {
        foreach ($bh in $BackupHistory) {
            $internalHistory += $bh
        }
    }
    end {
        if (Test-FunctionInterrupt) { return }
        if ($Continue -eq $True) {
            $WithReplace = $True
        }
        $databases = $internalHistory.Database | Select-Object -Unique
        foreach ($database in $databases) {
            $databaseRestoreStartTime = Get-Date
            if ($database -in $server.Databases.Name) {
                if (-not $OutputScriptOnly -and -not $VerifyOnly -and $server.DatabaseEngineEdition -ne "SqlManagedInstance") {
                    if ($Pscmdlet.ShouldProcess("Killing processes in $database on $SqlInstance as it exists and WithReplace specified  `n", "Cannot proceed if processes exist, ", "Database Exists and WithReplace specified, need to kill processes to restore")) {
                        try {
                            Write-Message -Level Verbose -Message "Killing processes on $database"
                            $null = Stop-DbaProcess -SqlInstance $server -Database $database -WarningAction Silentlycontinue
                            $null = $server.Query("Alter database $database set offline with rollback immediate; alter database $database set restricted_user; Alter database $database set online with rollback immediate", 'master')
                            $server.ConnectionContext.Connect()
                        } catch {
                            Write-Message -Level Verbose -Message "No processes to kill in $database"
                        }
                    }
                } elseif (-not $OutputScriptOnly -and -not $VerifyOnly -and $server.DatabaseEngineEdition -eq "SqlManagedInstance") {
                    if ($Pscmdlet.ShouldProcess("Dropping $database on $SqlInstance as it exists and WithReplace specified  `n", "Cannot proceed if database exist, ", "Database Exists and WithReplace specified, need to drop database to restore")) {
                        try {
                            Write-Message -Level Verbose "$SqlInstance is a Managed instance so dropping database was WithReplace not supported"
                            $null = Stop-DbaProcess -SqlInstance $server -Database $database -WarningAction Silentlycontinue
                            $null = Remove-DbaDatabase -SqlInstance $server -Database $database -Confirm:$false
                            $server.ConnectionContext.Connect()
                        } catch {
                            Write-Message -Level Verbose -Message "No processes to kill in $database"
                        }
                    }

                } elseif (-not $WithReplace -and (-not $VerifyOnly)) {
                    Write-Message -Level verbose -Message "$database exists and WithReplace not specified, stopping"
                    continue
                }
            }
            Write-Message -Message "WithReplace  = $WithReplace" -Level Debug
            $backups = @($internalHistory | Where-Object { $_.Database -eq $database } | Sort-Object -Property Type, FirstLsn)
            $BackupCnt = 1

            foreach ($backup in $backups) {
                $fileRestoreStartTime = Get-Date
                $restore = New-Object Microsoft.SqlServer.Management.Smo.Restore
                if (($backup -ne $backups[-1]) -or $true -eq $NoRecovery) {
                    $restore.NoRecovery = $True
                } elseif ($backup -eq $backups[-1] -and '' -ne $StandbyDirectory) {
                    $restore.StandbyFile = $StandByDirectory + "\" + $database + (Get-Date -Format yyyyMMddHHmmss) + ".bak"
                    Write-Message -Level Verbose -Message "Setting standby on last file $($restore.StandbyFile)"
                } else {
                    $restore.NoRecovery = $False
                }
                if (-not [string]::IsNullOrEmpty($StopMark)) {
                    if ($StopBefore -eq $True) {
                        $restore.StopBeforeMarkName = $StopMark
                        if ($null -ne $StopAfterDate) {
                            $restore.StopBeforeMarkAfterDate = $StopAfterDate
                        }
                    } else {
                        $restore.StopAtMarkName = $StopMark
                        if ($null -ne $StopAfterDate) {
                            $restore.StopAtMarkAfterDate = $StopAfterDate
                        }
                    }
                } elseif ($RestoreTime -gt (Get-Date) -or $backup.RestoreTime -gt (Get-Date) -or $backup.RecoveryModel -eq 'Simple') {
                    $restore.ToPointInTime = $null
                } else {
                    if ($RestoreTime -ne $backup.RestoreTime) {
                        $restore.ToPointInTime = $backup.RestoreTime.ToString("yyyy-MM-ddTHH:mm:ss.fff", [System.Globalization.CultureInfo]::InvariantCulture)
                    } else {
                        $restore.ToPointInTime = $RestoreTime.ToString("yyyy-MM-ddTHH:mm:ss.fff", [System.Globalization.CultureInfo]::InvariantCulture)
                    }
                }

                $restore.Database = $database
                if ($server.DatabaseEngineEdition -ne "SqlManagedInstance") {
                    $restore.ReplaceDatabase = $WithReplace
                }
                if ($MaxTransferSize) {
                    $restore.MaxTransferSize = $MaxTransferSize
                }
                if ($BufferCount) {
                    $restore.BufferCount = $BufferCount
                }
                if ($BlockSize) {
                    $restore.Blocksize = $BlockSize
                }
                if ($KeepReplication) {
                    $restore.KeepReplication = $KeepReplication
                }
                if ($true -ne $Continue -and ($null -eq $Pages)) {
                    foreach ($file in $backup.FileList) {
                        $moveFile = New-Object Microsoft.SqlServer.Management.Smo.RelocateFile
                        $moveFile.LogicalFileName = $file.LogicalName
                        $moveFile.PhysicalFileName = $file.PhysicalName
                        $null = $restore.RelocateFiles.Add($moveFile)
                    }
                }
                $action = switch ($backup.Type) {
                    '1' { 'Database' }
                    '2' { 'Log' }
                    '5' { 'Database' }
                    'Transaction Log' { 'Log' }
                    Default { 'Database' }
                }

                Write-Message -Level Debug -Message "restore action = $action"
                $restore.Action = $action
                foreach ($file in $backup.FullName) {
                    Write-Message -Message "Adding device $file" -Level Debug
                    $device = New-Object -TypeName Microsoft.SqlServer.Management.Smo.BackupDeviceItem
                    $device.Name = $file
                    if ($file.StartsWith("http")) {
                        $device.devicetype = "URL"
                    } else {
                        $device.devicetype = "File"
                    }

                    if ($AzureCredential) {
                        $restore.CredentialName = $AzureCredential
                    }

                    $restore.FileNumber = $backup.Position
                    $restore.Devices.Add($device)
                }
                Write-Message -Level Verbose -Message "Performing restore action"
                if ($Pscmdlet.ShouldProcess($SqlInstance, "Restoring $database to $SqlInstance based on these files: $($backup.FullName -join ', ')")) {
                    try {
                        $restoreComplete = $true
                        if ($KeepCDC -and $restore.NoRecovery -eq $false) {
                            $script = $restore.Script($server)
                            if ($script -like '*WITH*') {
                                $script = $script.TrimEnd() + ' , KEEP_CDC'
                            } else {
                                $script = $script.TrimEnd() + ' WITH KEEP_CDC'
                            }
                            if ($true -ne $OutputScriptOnly) {
                                Write-Progress -id 1 -activity "Restoring $database to $SqlInstance - Backup $BackupCnt of $($Backups.count)" -percentcomplete 0 -status ([System.String]::Format("Progress: {0} %", 0))
                                $null = $server.ConnectionContext.ExecuteNonQuery($script)
                                Write-Progress -id 1 -activity "Restoring $database to $SqlInstance - Backup $BackupCnt of $($Backups.count)" -status "Complete" -Completed
                            }
                        } elseif ($null -ne $Pages -and $action -eq 'Database') {
                            $script = $restore.Script($server)
                            $script = $script -replace "] FROM", "] PAGE='$pages' FROM"
                            if ($true -ne $OutputScriptOnly) {
                                Write-Progress -id 1 -activity "Restoring $database to $SqlInstance - Backup $BackupCnt of $($Backups.count)" -percentcomplete 0 -status ([System.String]::Format("Progress: {0} %", 0))
                                $null = $server.ConnectionContext.ExecuteNonQuery($script)
                                Write-Progress -id 1 -activity "Restoring $database to $SqlInstance - Backup $BackupCnt of $($Backups.count)" -status "Complete" -Completed
                            }
                        } elseif ($OutputScriptOnly) {
                            $script = $restore.Script($server)
                            if ($ExecuteAs -ne '' -and $BackupCnt -eq 1) {
                                $script = "EXECUTE AS LOGIN='$ExecuteAs'; " + $script
                            }
                        } elseif ($VerifyOnly) {
                            Write-Message -Message "VerifyOnly restore" -Level Verbose
                            Write-Progress -id 1 -activity "Verifying $database backup file on $SqlInstance - Backup $BackupCnt of $($Backups.count)" -percentcomplete 0 -status ([System.String]::Format("Progress: {0} %", 0))
                            $Verify = $restore.SqlVerify($server)
                            Write-Progress -id 1 -activity "Verifying $database backup file on $SqlInstance - Backup $BackupCnt of $($Backups.count)" -status "Complete" -Completed
                            if ($verify -eq $true) {
                                Write-Message -Message "VerifyOnly restore Succeeded" -Level Verbose
                                return "Verify successful"
                            } else {
                                Write-Message -Message "VerifyOnly restore Failed" -Level Verbose
                                return "Verify failed"
                            }
                        } else {
                            $outerProgress = $BackupCnt / $Backups.Count * 100
                            if ($BackupCnt -eq 1) {
                                Write-Progress -id 1 -Activity "Restoring $database to $SqlInstance - Backup $BackupCnt of $($Backups.count)" -percentcomplete 0
                            }
                            Write-Progress -id 2 -ParentId 1 -Activity "Restore $($backup.FullName -Join ',')" -percentcomplete 0
                            $script = $restore.Script($server)
                            if ($ExecuteAs -ne '' -and $BackupCnt -eq 1) {
                                Write-Progress -id 1 -activity "Restoring $database to $SqlInstance - Backup $BackupCnt of $($Backups.count)" -percentcomplete 0 -status ([System.String]::Format("Progress: {0} %", 0))
                                $script = "EXECUTE AS LOGIN='$ExecuteAs'; " + $script
                                $null = $server.ConnectionContext.ExecuteNonQuery($script)
                                Write-Progress -id 1 -activity "Restoring $database to $SqlInstance - Backup $BackupCnt of $($Backups.count)" -status "Complete" -Completed
                            } else {
                                $percentcomplete = [Microsoft.SqlServer.Management.Smo.PercentCompleteEventHandler] {
                                    Write-Progress -id 2 -ParentId 1 -Activity "Restore $($backup.FullName -Join ',')" -percentcomplete $_.Percent -status ([System.String]::Format("Progress: {0} %", $_.Percent))
                                }
                                $restore.add_PercentComplete($percentcomplete)
                                $restore.PercentCompleteNotification = 1
                                $restore.SqlRestore($server)
                                Write-Progress -id 2 -ParentId 1 -Activity "Restore $($backup.FullName -Join ',')" -Completed
                                Add-TeppCacheItem -SqlInstance $server -Type database -Name $database
                            }
                            Write-Progress -id 1 -Activity "Restoring $database to $SqlInstance - Backup $BackupCnt of $($Backups.count)" -percentcomplete $outerProgress -status ([System.String]::Format("Progress: {0:N2} %", $outerProgress))
                        }
                    } catch {
                        Write-Message -Level Verbose -Message "Failed, Closing Server connection"
                        $restoreComplete = $False
                        $ExitError = $_.Exception.InnerException
                        Stop-Function -Message "Failed to restore db $database, stopping" -ErrorRecord $_ -Continue
                        break
                    } finally {
                        if ($OutputScriptOnly -eq $false) {
                            $pathSep = Get-DbaPathSep -Server $server
                            $RestoreDirectory = ((Split-Path $backup.FileList.PhysicalName -Parent) | Sort-Object -Unique).Replace('\', $pathSep) -Join ','
                            [PSCustomObject]@{
                                ComputerName           = $server.ComputerName
                                InstanceName           = $server.ServiceName
                                SqlInstance            = $server.DomainInstanceName
                                Database               = $backup.Database
                                DatabaseName           = $backup.Database
                                DatabaseOwner          = $server.ConnectionContext.TrueLogin
                                Owner                  = $server.ConnectionContext.TrueLogin
                                NoRecovery             = $restore.NoRecovery
                                WithReplace            = $WithReplace
                                KeepReplication        = $KeepReplication
                                RestoreComplete        = $restoreComplete
                                BackupFilesCount       = $backup.FullName.Count
                                RestoredFilesCount     = $backup.Filelist.PhysicalName.count
                                BackupSizeMB           = if ([bool]($backup.psobject.Properties.Name -contains 'TotalSize')) { [Math]::Round(($backup | Measure-Object -Property TotalSize -Sum).Sum / $backup.FullName.Count / 1mb, 2) } else { $null }
                                CompressedBackupSizeMB = if ([bool]($backup.psobject.Properties.Name -contains 'CompressedBackupSize')) { [Math]::Round(($backup | Measure-Object -Property CompressedBackupSize -Sum).Sum / $backup.FullName.Count / 1mb, 2) } else { $null }
                                BackupFile             = $backup.FullName -Join ','
                                RestoredFile           = $((Split-Path $backup.FileList.PhysicalName -Leaf) | Sort-Object -Unique) -Join ','
                                RestoredFileFull       = ($backup.Filelist.PhysicalName -Join ',')
                                RestoreDirectory       = $RestoreDirectory
                                BackupSize             = if ([bool]($backup.psobject.Properties.Name -contains 'TotalSize')) { [dbasize](($backup | Measure-Object -Property TotalSize -Sum).Sum / $backup.FullName.Count) } else { $null }
                                CompressedBackupSize   = if ([bool]($backup.psobject.Properties.Name -contains 'CompressedBackupSize')) { [dbasize](($backup | Measure-Object -Property CompressedBackupSize -Sum).Sum / $backup.FullName.Count) } else { $null }
                                BackupStartTime        = $backup.Start
                                BackupEndTime          = $backup.End
                                RestoreTargetTime      = if ($RestoreTime -lt (Get-Date)) { $RestoreTime } else { 'Latest' }
                                Script                 = $script
                                BackupFileRaw          = ($backups.Fullname)
                                FileRestoreTime        = New-TimeSpan -Seconds ((Get-Date) - $fileRestoreStartTime).TotalSeconds
                                DatabaseRestoreTime    = New-TimeSpan -Seconds ((Get-Date) - $databaseRestoreStartTime).TotalSeconds
                                ExitError              = $ExitError
                            } | Select-DefaultView -Property ComputerName, InstanceName, SqlInstance, BackupFile, BackupFilesCount, BackupSize, CompressedBackupSize, Database, Owner, DatabaseRestoreTime, FileRestoreTime, NoRecovery, RestoreComplete, RestoredFile, RestoredFilesCount, Script, RestoreDirectory, WithReplace
                        } else {
                            $script
                        }
                        if ($restore.Devices.Count -gt 0) {
                            $restore.Devices.Clear()
                        }
                        Write-Message -Level Verbose -Message "Succeeded, Closing Server connection"
                        $server.ConnectionContext.Disconnect()
                    }
                }
                $BackupCnt++
            }
            Write-Progress -id 2 -Activity "Finished" -Completed
            if ($server.ConnectionContext.exists) {
                $server.ConnectionContext.Disconnect()
            }
            Write-Progress -id 1 -Activity "Finished" -Completed
        }
    }
}

# SIG # Begin signature block
# MIIjYAYJKoZIhvcNAQcCoIIjUTCCI00CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCCjkxWQx0pu7tGz
# /6hTuikvGGbgoGorgu2Mrb7DXjgbe6CCHVkwggUaMIIEAqADAgECAhADBbuGIbCh
# Y1+/3q4SBOdtMA0GCSqGSIb3DQEBCwUAMHIxCzAJBgNVBAYTAlVTMRUwEwYDVQQK
# EwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20xMTAvBgNV
# BAMTKERpZ2lDZXJ0IFNIQTIgQXNzdXJlZCBJRCBDb2RlIFNpZ25pbmcgQ0EwHhcN
# MjAwNTEyMDAwMDAwWhcNMjMwNjA4MTIwMDAwWjBXMQswCQYDVQQGEwJVUzERMA8G
# A1UECBMIVmlyZ2luaWExDzANBgNVBAcTBlZpZW5uYTERMA8GA1UEChMIZGJhdG9v
# bHMxETAPBgNVBAMTCGRiYXRvb2xzMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIB
# CgKCAQEAvL9je6vjv74IAbaY5rXqHxaNeNJO9yV0ObDg+kC844Io2vrHKGD8U5hU
# iJp6rY32RVprnAFrA4jFVa6P+sho7F5iSVAO6A+QZTHQCn7oquOefGATo43NAadz
# W2OWRro3QprMPZah0QFYpej9WaQL9w/08lVaugIw7CWPsa0S/YjHPGKQ+bYgI/kr
# EUrk+asD7lvNwckR6pGieWAyf0fNmSoevQBTV6Cd8QiUfj+/qWvLW3UoEX9ucOGX
# 2D8vSJxL7JyEVWTHg447hr6q9PzGq+91CO/c9DWFvNMjf+1c5a71fEZ54h1mNom/
# XoWZYoKeWhKnVdv1xVT1eEimibPEfQIDAQABo4IBxTCCAcEwHwYDVR0jBBgwFoAU
# WsS5eyoKo6XqcQPAYPkt9mV1DlgwHQYDVR0OBBYEFPDAoPu2A4BDTvsJ193ferHL
# 454iMA4GA1UdDwEB/wQEAwIHgDATBgNVHSUEDDAKBggrBgEFBQcDAzB3BgNVHR8E
# cDBuMDWgM6Axhi9odHRwOi8vY3JsMy5kaWdpY2VydC5jb20vc2hhMi1hc3N1cmVk
# LWNzLWcxLmNybDA1oDOgMYYvaHR0cDovL2NybDQuZGlnaWNlcnQuY29tL3NoYTIt
# YXNzdXJlZC1jcy1nMS5jcmwwTAYDVR0gBEUwQzA3BglghkgBhv1sAwEwKjAoBggr
# BgEFBQcCARYcaHR0cHM6Ly93d3cuZGlnaWNlcnQuY29tL0NQUzAIBgZngQwBBAEw
# gYQGCCsGAQUFBwEBBHgwdjAkBggrBgEFBQcwAYYYaHR0cDovL29jc3AuZGlnaWNl
# cnQuY29tME4GCCsGAQUFBzAChkJodHRwOi8vY2FjZXJ0cy5kaWdpY2VydC5jb20v
# RGlnaUNlcnRTSEEyQXNzdXJlZElEQ29kZVNpZ25pbmdDQS5jcnQwDAYDVR0TAQH/
# BAIwADANBgkqhkiG9w0BAQsFAAOCAQEAj835cJUMH9Y2pBKspjznNJwcYmOxeBcH
# Ji+yK0y4bm+j44OGWH4gu/QJM+WjZajvkydJKoJZH5zrHI3ykM8w8HGbYS1WZfN4
# oMwi51jKPGZPw9neGS2PXrBcKjzb7rlQ6x74Iex+gyf8z1ZuRDitLJY09FEOh0BM
# LaLh+UvJ66ghmfIyjP/g3iZZvqwgBhn+01fObqrAJ+SagxJ/21xNQJchtUOWIlxR
# kuUn9KkuDYrMO70a2ekHODcAbcuHAGI8wzw4saK1iPPhVTlFijHS+7VfIt/d/18p
# MLHHArLQQqe1Z0mTfuL4M4xCUKpebkH8rI3Fva62/6osaXLD0ymERzCCBTAwggQY
# oAMCAQICEAQJGBtf1btmdVNDtW+VUAgwDQYJKoZIhvcNAQELBQAwZTELMAkGA1UE
# BhMCVVMxFTATBgNVBAoTDERpZ2lDZXJ0IEluYzEZMBcGA1UECxMQd3d3LmRpZ2lj
# ZXJ0LmNvbTEkMCIGA1UEAxMbRGlnaUNlcnQgQXNzdXJlZCBJRCBSb290IENBMB4X
# DTEzMTAyMjEyMDAwMFoXDTI4MTAyMjEyMDAwMFowcjELMAkGA1UEBhMCVVMxFTAT
# BgNVBAoTDERpZ2lDZXJ0IEluYzEZMBcGA1UECxMQd3d3LmRpZ2ljZXJ0LmNvbTEx
# MC8GA1UEAxMoRGlnaUNlcnQgU0hBMiBBc3N1cmVkIElEIENvZGUgU2lnbmluZyBD
# QTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAPjTsxx/DhGvZ3cH0wsx
# SRnP0PtFmbE620T1f+Wondsy13Hqdp0FLreP+pJDwKX5idQ3Gde2qvCchqXYJawO
# eSg6funRZ9PG+yknx9N7I5TkkSOWkHeC+aGEI2YSVDNQdLEoJrskacLCUvIUZ4qJ
# RdQtoaPpiCwgla4cSocI3wz14k1gGL6qxLKucDFmM3E+rHCiq85/6XzLkqHlOzEc
# z+ryCuRXu0q16XTmK/5sy350OTYNkO/ktU6kqepqCquE86xnTrXE94zRICUj6whk
# PlKWwfIPEvTFjg/BougsUfdzvL2FsWKDc0GCB+Q4i2pzINAPZHM8np+mM6n9Gd8l
# k9ECAwEAAaOCAc0wggHJMBIGA1UdEwEB/wQIMAYBAf8CAQAwDgYDVR0PAQH/BAQD
# AgGGMBMGA1UdJQQMMAoGCCsGAQUFBwMDMHkGCCsGAQUFBwEBBG0wazAkBggrBgEF
# BQcwAYYYaHR0cDovL29jc3AuZGlnaWNlcnQuY29tMEMGCCsGAQUFBzAChjdodHRw
# Oi8vY2FjZXJ0cy5kaWdpY2VydC5jb20vRGlnaUNlcnRBc3N1cmVkSURSb290Q0Eu
# Y3J0MIGBBgNVHR8EejB4MDqgOKA2hjRodHRwOi8vY3JsNC5kaWdpY2VydC5jb20v
# RGlnaUNlcnRBc3N1cmVkSURSb290Q0EuY3JsMDqgOKA2hjRodHRwOi8vY3JsMy5k
# aWdpY2VydC5jb20vRGlnaUNlcnRBc3N1cmVkSURSb290Q0EuY3JsME8GA1UdIARI
# MEYwOAYKYIZIAYb9bAACBDAqMCgGCCsGAQUFBwIBFhxodHRwczovL3d3dy5kaWdp
# Y2VydC5jb20vQ1BTMAoGCGCGSAGG/WwDMB0GA1UdDgQWBBRaxLl7KgqjpepxA8Bg
# +S32ZXUOWDAfBgNVHSMEGDAWgBRF66Kv9JLLgjEtUYunpyGd823IDzANBgkqhkiG
# 9w0BAQsFAAOCAQEAPuwNWiSz8yLRFcgsfCUpdqgdXRwtOhrE7zBh134LYP3DPQ/E
# r4v97yrfIFU3sOH20ZJ1D1G0bqWOWuJeJIFOEKTuP3GOYw4TS63XX0R58zYUBor3
# nEZOXP+QsRsHDpEV+7qvtVHCjSSuJMbHJyqhKSgaOnEoAjwukaPAJRHinBRHoXpo
# aK+bp1wgXNlxsQyPu6j4xRJon89Ay0BEpRPw5mQMJQhCMrI2iiQC/i9yfhzXSUWW
# 6Fkd6fp0ZGuy62ZD2rOwjNXpDd32ASDOmTFjPQgaGLOBm0/GkxAG/AeB+ova+YJJ
# 92JuoVP6EpQYhS6SkepobEQysmah5xikmmRR7zCCBY0wggR1oAMCAQICEA6bGI75
# 0C3n79tQ4ghAGFowDQYJKoZIhvcNAQEMBQAwZTELMAkGA1UEBhMCVVMxFTATBgNV
# BAoTDERpZ2lDZXJ0IEluYzEZMBcGA1UECxMQd3d3LmRpZ2ljZXJ0LmNvbTEkMCIG
# A1UEAxMbRGlnaUNlcnQgQXNzdXJlZCBJRCBSb290IENBMB4XDTIyMDgwMTAwMDAw
# MFoXDTMxMTEwOTIzNTk1OVowYjELMAkGA1UEBhMCVVMxFTATBgNVBAoTDERpZ2lD
# ZXJ0IEluYzEZMBcGA1UECxMQd3d3LmRpZ2ljZXJ0LmNvbTEhMB8GA1UEAxMYRGln
# aUNlcnQgVHJ1c3RlZCBSb290IEc0MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIIC
# CgKCAgEAv+aQc2jeu+RdSjwwIjBpM+zCpyUuySE98orYWcLhKac9WKt2ms2uexuE
# DcQwH/MbpDgW61bGl20dq7J58soR0uRf1gU8Ug9SH8aeFaV+vp+pVxZZVXKvaJNw
# wrK6dZlqczKU0RBEEC7fgvMHhOZ0O21x4i0MG+4g1ckgHWMpLc7sXk7Ik/ghYZs0
# 6wXGXuxbGrzryc/NrDRAX7F6Zu53yEioZldXn1RYjgwrt0+nMNlW7sp7XeOtyU9e
# 5TXnMcvak17cjo+A2raRmECQecN4x7axxLVqGDgDEI3Y1DekLgV9iPWCPhCRcKtV
# gkEy19sEcypukQF8IUzUvK4bA3VdeGbZOjFEmjNAvwjXWkmkwuapoGfdpCe8oU85
# tRFYF/ckXEaPZPfBaYh2mHY9WV1CdoeJl2l6SPDgohIbZpp0yt5LHucOY67m1O+S
# kjqePdwA5EUlibaaRBkrfsCUtNJhbesz2cXfSwQAzH0clcOP9yGyshG3u3/y1Yxw
# LEFgqrFjGESVGnZifvaAsPvoZKYz0YkH4b235kOkGLimdwHhD5QMIR2yVCkliWzl
# DlJRR3S+Jqy2QXXeeqxfjT/JvNNBERJb5RBQ6zHFynIWIgnffEx1P2PsIV/EIFFr
# b7GrhotPwtZFX50g/KEexcCPorF+CiaZ9eRpL5gdLfXZqbId5RsCAwEAAaOCATow
# ggE2MA8GA1UdEwEB/wQFMAMBAf8wHQYDVR0OBBYEFOzX44LScV1kTN8uZz/nupiu
# HA9PMB8GA1UdIwQYMBaAFEXroq/0ksuCMS1Ri6enIZ3zbcgPMA4GA1UdDwEB/wQE
# AwIBhjB5BggrBgEFBQcBAQRtMGswJAYIKwYBBQUHMAGGGGh0dHA6Ly9vY3NwLmRp
# Z2ljZXJ0LmNvbTBDBggrBgEFBQcwAoY3aHR0cDovL2NhY2VydHMuZGlnaWNlcnQu
# Y29tL0RpZ2lDZXJ0QXNzdXJlZElEUm9vdENBLmNydDBFBgNVHR8EPjA8MDqgOKA2
# hjRodHRwOi8vY3JsMy5kaWdpY2VydC5jb20vRGlnaUNlcnRBc3N1cmVkSURSb290
# Q0EuY3JsMBEGA1UdIAQKMAgwBgYEVR0gADANBgkqhkiG9w0BAQwFAAOCAQEAcKC/
# Q1xV5zhfoKN0Gz22Ftf3v1cHvZqsoYcs7IVeqRq7IviHGmlUIu2kiHdtvRoU9BNK
# ei8ttzjv9P+Aufih9/Jy3iS8UgPITtAq3votVs/59PesMHqai7Je1M/RQ0SbQyHr
# lnKhSLSZy51PpwYDE3cnRNTnf+hZqPC/Lwum6fI0POz3A8eHqNJMQBk1RmppVLC4
# oVaO7KTVPeix3P0c2PR3WlxUjG/voVA9/HYJaISfb8rbII01YBwCA8sgsKxYoA5A
# Y8WYIsGyWfVVa88nq2x2zm8jLfR+cWojayL/ErhULSd+2DrZ8LaHlv1b0VysGMNN
# n3O3AamfV6peKOK5lDCCBq4wggSWoAMCAQICEAc2N7ckVHzYR6z9KGYqXlswDQYJ
# KoZIhvcNAQELBQAwYjELMAkGA1UEBhMCVVMxFTATBgNVBAoTDERpZ2lDZXJ0IElu
# YzEZMBcGA1UECxMQd3d3LmRpZ2ljZXJ0LmNvbTEhMB8GA1UEAxMYRGlnaUNlcnQg
# VHJ1c3RlZCBSb290IEc0MB4XDTIyMDMyMzAwMDAwMFoXDTM3MDMyMjIzNTk1OVow
# YzELMAkGA1UEBhMCVVMxFzAVBgNVBAoTDkRpZ2lDZXJ0LCBJbmMuMTswOQYDVQQD
# EzJEaWdpQ2VydCBUcnVzdGVkIEc0IFJTQTQwOTYgU0hBMjU2IFRpbWVTdGFtcGlu
# ZyBDQTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAMaGNQZJs8E9cklR
# VcclA8TykTepl1Gh1tKD0Z5Mom2gsMyD+Vr2EaFEFUJfpIjzaPp985yJC3+dH54P
# Mx9QEwsmc5Zt+FeoAn39Q7SE2hHxc7Gz7iuAhIoiGN/r2j3EF3+rGSs+QtxnjupR
# PfDWVtTnKC3r07G1decfBmWNlCnT2exp39mQh0YAe9tEQYncfGpXevA3eZ9drMvo
# hGS0UvJ2R/dhgxndX7RUCyFobjchu0CsX7LeSn3O9TkSZ+8OpWNs5KbFHc02DVzV
# 5huowWR0QKfAcsW6Th+xtVhNef7Xj3OTrCw54qVI1vCwMROpVymWJy71h6aPTnYV
# VSZwmCZ/oBpHIEPjQ2OAe3VuJyWQmDo4EbP29p7mO1vsgd4iFNmCKseSv6De4z6i
# c/rnH1pslPJSlRErWHRAKKtzQ87fSqEcazjFKfPKqpZzQmiftkaznTqj1QPgv/Ci
# PMpC3BhIfxQ0z9JMq++bPf4OuGQq+nUoJEHtQr8FnGZJUlD0UfM2SU2LINIsVzV5
# K6jzRWC8I41Y99xh3pP+OcD5sjClTNfpmEpYPtMDiP6zj9NeS3YSUZPJjAw7W4oi
# qMEmCPkUEBIDfV8ju2TjY+Cm4T72wnSyPx4JduyrXUZ14mCjWAkBKAAOhFTuzuld
# yF4wEr1GnrXTdrnSDmuZDNIztM2xAgMBAAGjggFdMIIBWTASBgNVHRMBAf8ECDAG
# AQH/AgEAMB0GA1UdDgQWBBS6FtltTYUvcyl2mi91jGogj57IbzAfBgNVHSMEGDAW
# gBTs1+OC0nFdZEzfLmc/57qYrhwPTzAOBgNVHQ8BAf8EBAMCAYYwEwYDVR0lBAww
# CgYIKwYBBQUHAwgwdwYIKwYBBQUHAQEEazBpMCQGCCsGAQUFBzABhhhodHRwOi8v
# b2NzcC5kaWdpY2VydC5jb20wQQYIKwYBBQUHMAKGNWh0dHA6Ly9jYWNlcnRzLmRp
# Z2ljZXJ0LmNvbS9EaWdpQ2VydFRydXN0ZWRSb290RzQuY3J0MEMGA1UdHwQ8MDow
# OKA2oDSGMmh0dHA6Ly9jcmwzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydFRydXN0ZWRS
# b290RzQuY3JsMCAGA1UdIAQZMBcwCAYGZ4EMAQQCMAsGCWCGSAGG/WwHATANBgkq
# hkiG9w0BAQsFAAOCAgEAfVmOwJO2b5ipRCIBfmbW2CFC4bAYLhBNE88wU86/GPvH
# UF3iSyn7cIoNqilp/GnBzx0H6T5gyNgL5Vxb122H+oQgJTQxZ822EpZvxFBMYh0M
# CIKoFr2pVs8Vc40BIiXOlWk/R3f7cnQU1/+rT4osequFzUNf7WC2qk+RZp4snuCK
# rOX9jLxkJodskr2dfNBwCnzvqLx1T7pa96kQsl3p/yhUifDVinF2ZdrM8HKjI/rA
# J4JErpknG6skHibBt94q6/aesXmZgaNWhqsKRcnfxI2g55j7+6adcq/Ex8HBanHZ
# xhOACcS2n82HhyS7T6NJuXdmkfFynOlLAlKnN36TU6w7HQhJD5TNOXrd/yVjmScs
# PT9rp/Fmw0HNT7ZAmyEhQNC3EyTN3B14OuSereU0cZLXJmvkOHOrpgFPvT87eK1M
# rfvElXvtCl8zOYdBeHo46Zzh3SP9HSjTx/no8Zhf+yvYfvJGnXUsHicsJttvFXse
# GYs2uJPU5vIXmVnKcPA3v5gA3yAWTyf7YGcWoWa63VXAOimGsJigK+2VQbc61RWY
# MbRiCQ8KvYHZE/6/pNHzV9m8BPqC3jLfBInwAM1dwvnQI38AC+R2AibZ8GV2QqYp
# hwlHK+Z/GqSFD/yYlvZVVCsfgPrA8g4r5db7qS9EFUrnEw4d2zc4GqEr9u3WfPww
# ggbAMIIEqKADAgECAhAMTWlyS5T6PCpKPSkHgD1aMA0GCSqGSIb3DQEBCwUAMGMx
# CzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwgSW5jLjE7MDkGA1UEAxMy
# RGlnaUNlcnQgVHJ1c3RlZCBHNCBSU0E0MDk2IFNIQTI1NiBUaW1lU3RhbXBpbmcg
# Q0EwHhcNMjIwOTIxMDAwMDAwWhcNMzMxMTIxMjM1OTU5WjBGMQswCQYDVQQGEwJV
# UzERMA8GA1UEChMIRGlnaUNlcnQxJDAiBgNVBAMTG0RpZ2lDZXJ0IFRpbWVzdGFt
# cCAyMDIyIC0gMjCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAM/spSY6
# xqnya7uNwQ2a26HoFIV0MxomrNAcVR4eNm28klUMYfSdCXc9FZYIL2tkpP0GgxbX
# kZI4HDEClvtysZc6Va8z7GGK6aYo25BjXL2JU+A6LYyHQq4mpOS7eHi5ehbhVsbA
# umRTuyoW51BIu4hpDIjG8b7gL307scpTjUCDHufLckkoHkyAHoVW54Xt8mG8qjoH
# ffarbuVm3eJc9S/tjdRNlYRo44DLannR0hCRRinrPibytIzNTLlmyLuqUDgN5YyU
# XRlav/V7QG5vFqianJVHhoV5PgxeZowaCiS+nKrSnLb3T254xCg/oxwPUAY3ugjZ
# Naa1Htp4WB056PhMkRCWfk3h3cKtpX74LRsf7CtGGKMZ9jn39cFPcS6JAxGiS7uY
# v/pP5Hs27wZE5FX/NurlfDHn88JSxOYWe1p+pSVz28BqmSEtY+VZ9U0vkB8nt9Kr
# FOU4ZodRCGv7U0M50GT6Vs/g9ArmFG1keLuY/ZTDcyHzL8IuINeBrNPxB9Thvdld
# S24xlCmL5kGkZZTAWOXlLimQprdhZPrZIGwYUWC6poEPCSVT8b876asHDmoHOWIZ
# ydaFfxPZjXnPYsXs4Xu5zGcTB5rBeO3GiMiwbjJ5xwtZg43G7vUsfHuOy2SJ8bHE
# uOdTXl9V0n0ZKVkDTvpd6kVzHIR+187i1Dp3AgMBAAGjggGLMIIBhzAOBgNVHQ8B
# Af8EBAMCB4AwDAYDVR0TAQH/BAIwADAWBgNVHSUBAf8EDDAKBggrBgEFBQcDCDAg
# BgNVHSAEGTAXMAgGBmeBDAEEAjALBglghkgBhv1sBwEwHwYDVR0jBBgwFoAUuhbZ
# bU2FL3MpdpovdYxqII+eyG8wHQYDVR0OBBYEFGKK3tBh/I8xFO2XC809KpQU31Kc
# MFoGA1UdHwRTMFEwT6BNoEuGSWh0dHA6Ly9jcmwzLmRpZ2ljZXJ0LmNvbS9EaWdp
# Q2VydFRydXN0ZWRHNFJTQTQwOTZTSEEyNTZUaW1lU3RhbXBpbmdDQS5jcmwwgZAG
# CCsGAQUFBwEBBIGDMIGAMCQGCCsGAQUFBzABhhhodHRwOi8vb2NzcC5kaWdpY2Vy
# dC5jb20wWAYIKwYBBQUHMAKGTGh0dHA6Ly9jYWNlcnRzLmRpZ2ljZXJ0LmNvbS9E
# aWdpQ2VydFRydXN0ZWRHNFJTQTQwOTZTSEEyNTZUaW1lU3RhbXBpbmdDQS5jcnQw
# DQYJKoZIhvcNAQELBQADggIBAFWqKhrzRvN4Vzcw/HXjT9aFI/H8+ZU5myXm93KK
# mMN31GT8Ffs2wklRLHiIY1UJRjkA/GnUypsp+6M/wMkAmxMdsJiJ3HjyzXyFzVOd
# r2LiYWajFCpFh0qYQitQ/Bu1nggwCfrkLdcJiXn5CeaIzn0buGqim8FTYAnoo7id
# 160fHLjsmEHw9g6A++T/350Qp+sAul9Kjxo6UrTqvwlJFTU2WZoPVNKyG39+Xgmt
# dlSKdG3K0gVnK3br/5iyJpU4GYhEFOUKWaJr5yI+RCHSPxzAm+18SLLYkgyRTzxm
# lK9dAlPrnuKe5NMfhgFknADC6Vp0dQ094XmIvxwBl8kZI4DXNlpflhaxYwzGRkA7
# zl011Fk+Q5oYrsPJy8P7mxNfarXH4PMFw1nfJ2Ir3kHJU7n/NBBn9iYymHv+XEKU
# gZSCnawKi8ZLFUrTmJBFYDOA4CPe+AOk9kVH5c64A0JH6EE2cXet/aLol3ROLtoe
# HYxayB6a1cLwxiKoT5u92ByaUcQvmvZfpyeXupYuhVfAYOd4Vn9q78KVmksRAsiC
# nMkaBXy6cbVOepls9Oie1FqYyJ+/jbsYXEP10Cro4mLueATbvdH7WwqocH7wl4R4
# 4wgDXUcsY6glOJcB0j862uXl9uab3H4szP8XTE0AotjWAQ64i+7m4HJViSwnGWH2
# dwGMMYIFXTCCBVkCAQEwgYYwcjELMAkGA1UEBhMCVVMxFTATBgNVBAoTDERpZ2lD
# ZXJ0IEluYzEZMBcGA1UECxMQd3d3LmRpZ2ljZXJ0LmNvbTExMC8GA1UEAxMoRGln
# aUNlcnQgU0hBMiBBc3N1cmVkIElEIENvZGUgU2lnbmluZyBDQQIQAwW7hiGwoWNf
# v96uEgTnbTANBglghkgBZQMEAgEFAKCBhDAYBgorBgEEAYI3AgEMMQowCKACgACh
# AoAAMBkGCSqGSIb3DQEJAzEMBgorBgEEAYI3AgEEMBwGCisGAQQBgjcCAQsxDjAM
# BgorBgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCABctjRmFoKnSyKo7e8GYIKpYau
# 4I+nXQtM5vQMzOxHfzANBgkqhkiG9w0BAQEFAASCAQCSC+gdzNzp6KI5rPNErW/O
# UblrmJud6c5Z/eeGA8jG1pF3WZ9cWyyOXPA5YJ0RuGgOS1l0i3TxYnteIz3PYDdL
# iwn3pA9aB6LH6AaEUkWIYVpqgLo7BJbK9l4rhFkzZijoOa1+09V28bMpBoSVcqFG
# f7YIMUbzbhjQj4EXdN5c5YLQlg5A1QWKzcfeH+SYxQI8xvB8f1oqSFSNXHQUL5GV
# 7t8Y1V9vGIJ+EnyFgeAO7yJ5yUs3yeQwFOfl93JJtBCeiZivgn3wx4dkrj86uqVc
# m9JJkI++9CVUTvNhQx53lT44TSKAdOWwRmJnF5ZVPXMflyYorqQuC5Z4VonOMeLa
# oYIDIDCCAxwGCSqGSIb3DQEJBjGCAw0wggMJAgEBMHcwYzELMAkGA1UEBhMCVVMx
# FzAVBgNVBAoTDkRpZ2lDZXJ0LCBJbmMuMTswOQYDVQQDEzJEaWdpQ2VydCBUcnVz
# dGVkIEc0IFJTQTQwOTYgU0hBMjU2IFRpbWVTdGFtcGluZyBDQQIQDE1pckuU+jwq
# Sj0pB4A9WjANBglghkgBZQMEAgEFAKBpMBgGCSqGSIb3DQEJAzELBgkqhkiG9w0B
# BwEwHAYJKoZIhvcNAQkFMQ8XDTIyMTExNzA4NTYzOVowLwYJKoZIhvcNAQkEMSIE
# ICkM0E3YewV/Tk5PFr0qod6wik/W6p+kt3cLrbCs+0vaMA0GCSqGSIb3DQEBAQUA
# BIICAEayMc7ZTLV/NBYeFaNipbwwasjqxK7Pu5MPe4A8s7TzGalAaCb//mtmxeKK
# UxPEYHzWd72nt4JB7dpe8sWDhWTmWEUQEASf69iVFGtt25BnLNmo7oq2amCmxFhi
# ppwhh3QeOBZ/cC/dH/6ENwTDRD00Y0ihU1fxwDVz1caB49A7Y0wjMDBTmYjhm06C
# DonA2lW/ZKwkxS1K+/S14RrUPS6SapJjD7kiw0l7/H8V1lM/5U4ZXpQUr1CbDC08
# 0cXMjiryzh+EucMHoREeAUe2ZAtjHC574ZuHPCzK0h5EqBgtgHy1lcraxYP3sC0o
# dAVPmK+bSE5IiPwvoMQWYIlgiR0BkSgk3wxoTUcUvE9j0bLUEqDmN/iHMIyd2zjg
# UwyYnJ1Vtb5vEjBlM7WX5iGMykpis8/HukPTokc1MDAaQraD/5wQu/8uDQcoxpBY
# dy2b5/bvUN+4p6E3zXeayx0JBh0a9WSv0oVUTsBx/RCa0sq7zRsEgVjr2K5uDcDr
# e/ce+oWH8I8H2VMi/zuywwj4cHdasz4U0ocLtne70HOZh3g7pPCXUTwVMhCtI8kk
# er+8lix72Q1kxSCobzpaAYv1UOA8BLCzrx63oVEtZlpkUhgy9psQWDwetXHP9f3D
# V03T3Wn2dUpo4mmKKaRgtwyEUX1iVZClpcjrCeX+GWc8XEjX
# SIG # End signature block
