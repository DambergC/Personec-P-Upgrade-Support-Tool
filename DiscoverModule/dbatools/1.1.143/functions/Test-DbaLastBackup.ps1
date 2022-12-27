function Test-DbaLastBackup {
    <#
    .SYNOPSIS
        Quickly and easily tests the last set of full backups for a server.

    .DESCRIPTION
        Restores all or some of the latest backups and performs a DBCC CHECKDB.

        1. Gathers information about the last full backups
        2. Restores the backups to the Destination with a new name. If no Destination is specified, the originating SQL Server instance wil be used.
        3. The database is restored as "dbatools-testrestore-$databaseName" by default, but you can change dbatools-testrestore to whatever you would like using -Prefix
        4. The internal file names are also renamed to prevent conflicts with original database
        5. A DBCC CHECKDB is then performed
        6. And the test database is finally dropped

    .PARAMETER SqlInstance
        The target SQL Server instance or instances. Unlike many of the other commands, you cannot specify more than one server.

    .PARAMETER Destination
        The destination server to use to test the restore. By default, the Destination will be set to the source server

        If a different Destination server is specified, you must ensure that the database backups are on a shared location

    .PARAMETER SqlCredential
        Login to the target instance using alternative credentials. Accepts PowerShell credentials (Get-Credential).

        Windows Authentication, SQL Server Authentication, Active Directory - Password, and Active Directory - Integrated are all supported.

        For MFA support, please use Connect-DbaInstance.

    .PARAMETER DestinationSqlCredential
        Login to the target instance using alternative credentials. Accepts PowerShell credentials (Get-Credential).

        Windows Authentication, SQL Server Authentication, Active Directory - Password, and Active Directory - Integrated are all supported.

        For MFA support, please use Connect-DbaInstance.

    .PARAMETER Database
        The database backups to test. If -Database is not provided, all database backups will be tested.

    .PARAMETER ExcludeDatabase
        Exclude specific Database backups to test.

    .PARAMETER DataDirectory
        Specifies an alternative directory for mdfs, ndfs and so on. The command uses the SQL Server's default data directory for all restores.

    .PARAMETER LogDirectory
        Specifies an alternative directory for ldfs. The command uses the SQL Server's default log directory for all restores.

    .PARAMETER FileStreamDirectory
        Specifies a directory for filestream data.

    .PARAMETER VerifyOnly
        If this switch is enabled, VERIFYONLY will be performed. An actual restore will not be executed.

    .PARAMETER NoCheck
        If this switch is enabled, DBCC CHECKDB will be skipped

    .PARAMETER NoDrop
        If this switch is enabled, the newly-created test database will not be dropped.

    .PARAMETER CopyFile
        If this switch is enabled, the backup file will be copied to the destination default backup location unless CopyPath is specified.

    .PARAMETER CopyPath
        Specifies a path relative to the SQL Server to copy backups when CopyFile is specified. If not specified will use destination default backup location. If destination SQL Server is not local, admin UNC paths will be utilized for the copy.

    .PARAMETER MaxSize
        Max size in MB. Databases larger than this value will not be restored.

    .PARAMETER MaxDop
        Allows you to pass in a MAXDOP setting to the DBCC CheckDB command to limit the number of parallel processes used.

    .PARAMETER DeviceType
        Specifies a filter for backup sets based on DeviceTypes. Valid options are 'Disk','Permanent Disk Device', 'Tape', 'Permanent Tape Device','Pipe','Permanent Pipe Device','Virtual Device', in addition to custom integers for your own DeviceTypes.

    .PARAMETER AzureCredential
        The name of the SQL Server credential on the destination instance that holds the key to the azure storage account.

    .PARAMETER IncludeCopyOnly
        If this switch is enabled, copy only backups will be counted as a last backup.

    .PARAMETER IgnoreLogBackup
        If this switch is enabled, transaction log backups will be ignored. The restore will stop at the latest full or differential backup point.

    .PARAMETER IgnoreDiffBackup
        If this switch is enabled, differential backuys will be ignored. The restore will only use Full and Log backups, so will take longer to complete

    .PARAMETER Prefix
        The database is restored as "dbatools-testrestore-$databaseName" by default. You can change dbatools-testrestore to whatever you would like using this parameter.

    .PARAMETER InputObject
        Enables piping from Get-DbaDatabase

    .PARAMETER WhatIf
        If this switch is enabled, no actions are performed but informational messages will be displayed that explain what would happen if the command were to run.

    .PARAMETER Confirm
        If this switch is enabled, you will be prompted for confirmation before executing any operations that change state.

    .PARAMETER MaxTransferSize
        Parameter to set the unit of transfer. Values must be a multiple of 64kb and a max of 4GB
        Parameter is used as passtrough for Restore-DbaDatabase.

    .PARAMETER BufferCount
        Number of I/O buffers to use to perform the operation.
        Refererence: https://msdn.microsoft.com/en-us/library/ms178615.aspx#data-transfer-options
        Parameter is used as passtrough for Restore-DbaDatabase.

    .PARAMETER ReuseSourceFolderStructure
        By default, databases will be migrated to the destination Sql Server's default data and log directories. You can override this by specifying -ReuseSourceFolderStructure.
        The same structure on the SOURCE will be kept exactly, so consider this if you're migrating between different versions and use part of Microsoft's default Sql structure (MSSql12.INSTANCE, etc)

    .PARAMETER EnableException
        By default, when something goes wrong we try to catch it, interpret it and give you a friendly warning message.
        This avoids overwhelming you with "sea of red" exceptions, but is inconvenient because it basically disables advanced scripting.
        Using this switch turns this "nice by default" feature off and enables you to catch exceptions with your own try/catch.


    .NOTES
        Tags: DisasterRecovery, Backup, Restore
        Author: Chrissy LeMaire (@cl), netnerds.net

        Website: https://dbatools.io
        Copyright: (c) 2018 by dbatools, licensed under MIT
        License: MIT https://opensource.org/licenses/MIT

    .LINK
        https://dbatools.io/Test-DbaLastBackup

    .EXAMPLE
        PS C:\> Test-DbaLastBackup -SqlInstance sql2016

        Determines the last full backup for ALL databases, attempts to restore all databases (with a different name and file structure), then performs a DBCC CHECKDB. Once the test is complete, the test restore will be dropped.

    .EXAMPLE
        PS C:\> Test-DbaLastBackup -SqlInstance sql2016 -Database SharePoint_Config

        Determines the last full backup for SharePoint_Config, attempts to restore it, then performs a DBCC CHECKDB.

    .EXAMPLE
        PS C:\> Get-DbaDatabase -SqlInstance sql2016, sql2017 | Test-DbaLastBackup

        Tests every database backup on sql2016 and sql2017

    .EXAMPLE
        PS C:\> Get-DbaDatabase -SqlInstance sql2016, sql2017 -Database SharePoint_Config | Test-DbaLastBackup

        Tests the database backup for the SharePoint_Config database on sql2016 and sql2017

    .EXAMPLE
       PS C:\> Test-DbaLastBackup -SqlInstance sql2016 -Database model, master -VerifyOnly

       Skips performing an action restore of the database and simply verifies the backup using VERIFYONLY option of the restore.

    .EXAMPLE
        PS C:\> Test-DbaLastBackup -SqlInstance sql2016 -NoCheck -NoDrop

        Skips the DBCC CHECKDB check. This can help speed up the tests but makes it less tested. The test restores will remain on the server.

    .EXAMPLE
        PS C:\> Test-DbaLastBackup -SqlInstance sql2016 -DataDirectory E:\bigdrive -LogDirectory L:\bigdrive -MaxSize 10240

        Restores data and log files to alternative locations and only restores databases that are smaller than 10 GB.

    .EXAMPLE
        PS C:\> Test-DbaLastBackup -SqlInstance sql2014 -Destination sql2016 -CopyFile

        Copies the backup files for sql2014 databases to sql2016 default backup locations and then attempts restore from there.

    .EXAMPLE
        PS C:\> Test-DbaLastBackup -SqlInstance sql2014 -Destination sql2016 -CopyFile -CopyPath "\\BackupShare\TestRestore\"

        Copies the backup files for sql2014 databases to sql2016 default backup locations and then attempts restore from there.

    .EXAMPLE
        PS C:\> Test-DbaLastBackup -SqlInstance sql2016 -NoCheck -MaxTransferSize 4194302 -BufferCount 24

        Determines the last full backup for ALL databases, attempts to restore all databases (with a different name and file structure).
        The Restore will use more memory for reading the backup files. Do not set these values to high or you can get an Out of Memory error!!!
        When running the restore with these additional parameters and there is other server activity it could affect server OLTP performance. Please use with causion.
        Prior to running, you should check memory and server resources before configure it to run automatically.
        More information:
        https://www.mssqltips.com/sqlservertip/4935/optimize-sql-server-database-restore-performance/

    .EXAMPLE
        PS C:\> Test-DbaLastBackup -SqlInstance sql2016 -MaxDop 4

        The use of the MaxDop parameter will limit the number of processors used during the DBCC command
    #>
    [CmdletBinding(SupportsShouldProcess)]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSAvoidUsingPlainTextForPassword", "", Justification = "For Parameters DestinationSqlCredential and AzureCredential")]
    param (
        [DbaInstanceParameter[]]$SqlInstance,
        [PSCredential]$SqlCredential,
        [object[]]$Database,
        [object[]]$ExcludeDatabase,
        [DbaInstanceParameter]$Destination,
        [object]$DestinationSqlCredential,
        [string]$DataDirectory,
        [string]$LogDirectory,
        [string]$FileStreamDirectory,
        [string]$Prefix = "dbatools-testrestore-",
        [switch]$VerifyOnly,
        [switch]$NoCheck,
        [switch]$NoDrop,
        [switch]$CopyFile,
        [string]$CopyPath,
        [int]$MaxSize,
        [string[]]$DeviceType,
        [switch]$IncludeCopyOnly,
        [switch]$IgnoreLogBackup,
        [string]$AzureCredential,
        [parameter(ValueFromPipeline)]
        [Microsoft.SqlServer.Management.Smo.Database[]]$InputObject,
        [int]$MaxTransferSize,
        [int]$BufferCount,
        [switch]$IgnoreDiffBackup,
        [int]$MaxDop,
        [switch]$ReuseSourceFolderStructure,
        [switch]$EnableException
    )
    process {
        if ($SqlInstance) {
            $InputObject += Get-DbaDatabase -SqlInstance $SqlInstance -SqlCredential $SqlCredential -Database $Database -ExcludeDatabase $ExcludeDatabase
        }

        foreach ($db in $InputObject) {
            if ($db.Name -eq "tempdb") {
                continue
            }

            $sourceserver = $db.Parent
            $source = $db.Parent.Name
            $instance = [DbaInstanceParameter]$source
            $copysuccess = $true
            $dbName = $db.Name
            $restoreresult = $null

            if (-not (Test-Bound -ParameterName Destination)) {
                $destination = $sourceserver.Name
                $DestinationSqlCredential = $SqlCredential
            }

            if ($db.LastFullBackup.Year -eq 1) {
                [pscustomobject]@{
                    SourceServer   = $source
                    TestServer     = $destination
                    Database       = $db.name
                    FileExists     = $false
                    Size           = $null
                    RestoreResult  = "Skipped"
                    DbccResult     = "Skipped"
                    RestoreStart   = $null
                    RestoreEnd     = $null
                    RestoreElapsed = $null
                    DbccMaxDop     = $null
                    DbccStart      = $null
                    DbccEnd        = $null
                    DbccElapsed    = $null
                    BackupDates    = $null
                    BackupFiles    = $null
                }
                continue
            }

            try {
                $destserver = Connect-DbaInstance -SqlInstance $Destination -SqlCredential $DestinationSqlCredential
            } catch {
                Stop-Function -Message "Failure" -Category ConnectionError -ErrorRecord $_ -Target $Destination -Continue
            }

            if ($destserver.VersionMajor -lt $sourceserver.VersionMajor) {
                Stop-Function -Message "$Destination is a lower version than $instance. Backups would be incompatible." -Continue
            }

            if ($destserver.VersionMajor -eq $sourceserver.VersionMajor -and $destserver.VersionMinor -lt $sourceserver.VersionMinor) {
                Stop-Function -Message "$Destination is a lower version than $instance. Backups would be incompatible." -Continue
            }

            if ($CopyPath) {
                $testpath = Test-DbaPath -SqlInstance $destserver -Path $CopyPath
                if (-not $testpath) {
                    Stop-Function -Message "$destserver cannot access $CopyPath." -Continue
                }
            } else {
                # If not CopyPath is specified, use the destination server default backup directory
                $copyPath = $destserver.BackupDirectory
            }

            if ($instance -ne $destination -and -not $CopyFile) {
                $sourcerealname = $sourceserver.ComputerNetBiosName
                $destrealname = $destserver.ComputerNetBiosName

                if ($BackupFolder) {
                    if ($BackupFolder.StartsWith("\\") -eq $false -and $sourcerealname -ne $destrealname) {
                        Stop-Function -Message "Backup folder must be a network share if the source and destination servers are not the same." -Continue
                    }
                }
            }

            if ($datadirectory) {
                if (-not (Test-DbaPath -SqlInstance $destserver -Path $datadirectory)) {
                    $serviceAccount = $destserver.ServiceAccount
                    Stop-Function -Message "Can't access $datadirectory Please check if $serviceAccount has permissions." -Continue
                }
            } else {
                $datadirectory = Get-SqlDefaultPaths -SqlInstance $destserver -FileType mdf
            }

            if ($logdirectory) {
                if (-not (Test-DbaPath -SqlInstance $destserver -Path $logdirectory)) {
                    $serviceAccount = $destserver.ServiceAccount
                    Stop-Function -Message "$Destination can't access its local directory $logdirectory. Please check if $serviceAccount has permissions." -Continue
                }
            } else {
                $logdirectory = Get-SqlDefaultPaths -SqlInstance $destserver -FileType ldf
            }

            if ((Test-Bound -ParameterName AzureCredential) -and (Test-Bound -ParameterName CopyFile)) {
                Stop-Function -Message "Cannot use copyfile with Azure backups, set to false." -continue
                $CopyFile = $false
            }

            Write-Message -Level Verbose -Message "Getting recent backup history for $($db.Name) on $instance."

            if (Test-Bound "IgnoreLogBackup") {
                Write-Message -Level Verbose -Message "Skipping Log backups as requested."
                $lastbackup = @()
                $lastbackup += $full = Get-DbaDbBackupHistory -SqlInstance $sourceserver -Database $dbName -IncludeCopyOnly:$IncludeCopyOnly -LastFull -DeviceType $DeviceType -WarningAction SilentlyContinue
                if (-not (Test-Bound "IgnoreDiffBackup")) {
                    $diff = Get-DbaDbBackupHistory -SqlInstance $sourceserver -Database $dbName -IncludeCopyOnly:$IncludeCopyOnly -LastDiff -DeviceType $DeviceType -WarningAction SilentlyContinue
                }
                if ($full.start -le $diff.start) {
                    $lastbackup += $diff
                }
            } else {
                $lastbackup = Get-DbaDbBackupHistory -SqlInstance $sourceserver -Database $dbName -IncludeCopyOnly:$IncludeCopyOnly -Last -DeviceType $DeviceType -WarningAction SilentlyContinue -IgnoreDiffBackup:$IgnoreDiffBackup
            }

            if (-not $lastbackup) {
                Write-Message -Level Verbose -Message "No backups exist for this database."
                # This code should never be executed as there is already a test for databases without backup in line 241.
                continue
            }

            $totalSizeMB = ($lastbackup.TotalSize.Megabyte | Measure-Object -Sum).Sum
            if ($MaxSize -and $MaxSize -lt $totalSizeMB) {
                [pscustomobject]@{
                    SourceServer   = $source
                    TestServer     = $destination
                    Database       = $db.name
                    FileExists     = $null
                    Size           = [dbasize](($lastbackup.TotalSize | Measure-Object -Sum).Sum)
                    RestoreResult  = "The backup size for $dbName ($totalSizeMB MB) exceeds the specified maximum size ($MaxSize MB)."
                    DbccResult     = "Skipped"
                    RestoreStart   = $null
                    RestoreEnd     = $null
                    RestoreElapsed = $null
                    DbccMaxDop     = $null
                    DbccStart      = $null
                    DbccEnd        = $null
                    DbccElapsed    = $null
                    BackupDates    = [String[]]($lastbackup.Start)
                    BackupFiles    = $lastbackup.FullName
                }
                continue
            }

            if ($CopyFile) {
                try {
                    Write-Message -Level Verbose -Message "Gathering information for file copy."
                    $removearray = @()

                    foreach ($backup in $lastbackup) {
                        foreach ($file in $backup) {
                            $filename = Split-Path -Path $file.FullName -Leaf
                            Write-Message -Level Verbose -Message "Processing $filename."

                            $sourcefile = Join-AdminUnc -servername $instance.ComputerName -filepath "$($file.Path)"

                            if ($instance.IsLocalHost) {
                                $remotedestdirectory = Join-AdminUnc -servername $instance.ComputerName -filepath $copyPath
                            } else {
                                $remotedestdirectory = $copyPath
                            }

                            $remotedestfile = "$remotedestdirectory\$filename"
                            $localdestfile = "$copyPath\$filename"
                            Write-Message -Level Verbose -Message "Destination directory is $destdirectory."
                            Write-Message -Level Verbose -Message "Destination filename is $remotedestfile."

                            try {
                                Write-Message -Level Verbose -Message "Copying $sourcefile to $remotedestfile."
                                Copy-Item -Path $sourcefile -Destination $remotedestfile -ErrorAction Stop
                                $backup.Path = $localdestfile
                                $backup.FullName = $localdestfile
                                $removearray += $remotedestfile
                            } catch {
                                $backup.Path = $sourcefile
                                $backup.FullName = $sourcefile
                            }
                        }
                    }
                    $copysuccess = $true
                } catch {
                    Write-Message -Level Warning -Message "Failed to copy backups for $dbName on $instance to $destdirectory - $_."
                    $copysuccess = $false
                }
            }
            if (-not $copysuccess) {
                Write-Message -Level Verbose -Message "Failed to copy backups."
                $lastbackup = @{
                    Path = "Failed to copy backups"
                }
                $fileexists = $false
                $success = $restoreresult = $dbccresult = "Skipped"
            } elseif (-not ($lastbackup | Where-Object { $_.type -eq 'Full' })) {
                Write-Message -Level Verbose -Message "No full backup returned from lastbackup."
                $lastbackup = @{
                    Path = "Not found"
                }
                $fileexists = $false
                $success = $restoreresult = $dbccresult = "Skipped"
            } elseif ($source -ne $destination -and $lastbackup[0].Path.StartsWith('\\') -eq $false -and -not $CopyFile) {
                Write-Message -Level Verbose -Message "Path not UNC and source does not match destination. Use -CopyFile to move the backup file."
                $fileexists = $dbccresult = "Skipped"
                $success = $restoreresult = "Restore not located on shared location"
            } elseif (($lastbackup[0].Path | ForEach-Object { Test-DbaPath -SqlInstance $destserver -Path $_ }) -eq $false) {
                Write-Message -Level Verbose -Message "SQL Server cannot find backup."
                $fileexists = $false
                $success = $restoreresult = $dbccresult = "Skipped"
            }
            if ($restoreresult -ne "Skipped" -or $lastbackup[0].Path -like 'http*') {
                Write-Message -Level Verbose -Message "Looking good."

                $fileexists = $true
                $ogdbname = $dbName
                $dbccElapsed = $restoreElapsed = $startRestore = $endRestore = $startDbcc = $endDbcc = $null
                $dbName = "$prefix$dbName"
                $destdb = $destserver.databases[$dbName]

                if ($destdb) {
                    Stop-Function -Message "$dbName already exists on $destination - skipping." -Continue
                }

                if ($Pscmdlet.ShouldProcess($destination, "Restoring $ogdbname as $dbName.")) {
                    Write-Message -Level Verbose -Message "Performing restore."
                    $startRestore = Get-Date
                    try {
                        if ($ReuseSourceFolderStructure) {
                            $restoreSplat = @{
                                SqlInstance                = $destserver
                                RestoredDatabaseNamePrefix = $prefix
                                DestinationFilePrefix      = $Prefix
                                IgnoreLogBackup            = $IgnoreLogBackup
                                AzureCredential            = $AzureCredential
                                TrustDbBackupHistory       = $true
                                ReuseSourceFolderStructure = $true
                                EnableException            = $true
                            }
                        } else {
                            $restoreSplat = @{
                                SqlInstance                = $destserver
                                RestoredDatabaseNamePrefix = $prefix
                                DestinationFilePrefix      = $Prefix
                                DestinationDataDirectory   = $datadirectory
                                DestinationLogDirectory    = $logdirectory
                                IgnoreLogBackup            = $IgnoreLogBackup
                                AzureCredential            = $AzureCredential
                                TrustDbBackupHistory       = $true
                                EnableException            = $true
                            }
                        }

                        if (Test-Bound "MaxTransferSize") {
                            $restoreSplat.Add('MaxTransferSize', $MaxTransferSize)
                        }
                        if (Test-Bound "BufferCount") {
                            $restoreSplat.Add('BufferCount', $BufferCount)
                        }
                        if (Test-Bound "FileStreamDirectory") {
                            $restoreSplat.Add('DestinationFileStreamDirectory', $FileStreamDirectory)
                        }

                        if ($verifyonly) {
                            $restoreresult = $lastbackup | Restore-DbaDatabase @restoreSplat -VerifyOnly:$VerifyOnly
                        } else {
                            $restoreresult = $lastbackup | Restore-DbaDatabase @restoreSplat
                            Write-Message -Level Verbose -Message " Restore-DbaDatabase -SqlInstance $destserver -RestoredDatabaseNamePrefix $prefix -DestinationFilePrefix $Prefix -DestinationDataDirectory $datadirectory -DestinationLogDirectory $logdirectory -IgnoreLogBackup:$IgnoreLogBackup -AzureCredential $AzureCredential -TrustDbBackupHistory"
                        }
                    } catch {
                        $errormsg = Get-ErrorMessage -Record $_
                    }

                    $endRestore = Get-Date
                    $restorets = New-TimeSpan -Start $startRestore -End $endRestore
                    $ts = [timespan]::fromseconds($restorets.TotalSeconds)
                    $restoreElapsed = "{0:HH:mm:ss}" -f ([datetime]$ts.Ticks)

                    if ($restoreresult.RestoreComplete -eq $true) {
                        $success = "Success"
                    } else {
                        if ($errormsg) {
                            $success = $errormsg
                        } else {
                            $success = "Failure"
                        }
                    }
                }

                $destserver = Connect-DbaInstance -SqlInstance $Destination -SqlCredential $DestinationSqlCredential

                if (-not $NoCheck -and -not $VerifyOnly) {
                    # shouldprocess is taken care of in Start-DbccCheck
                    if ($ogdbname -eq "master") {
                        $dbccresult =
                        "DBCC CHECKDB skipped for restored master ($dbName) database. `
                            The master database cannot be copied off of a server and have a successful DBCC CHECKDB. `
                            See https://www.itprotoday.com/my-master-database-really-corrupt for more information."
                    } else {
                        if ($success -eq "Success") {
                            Write-Message -Level Verbose -Message "Starting DBCC."

                            $startDbcc = Get-Date
                            $dbccresult = Start-DbccCheck -Server $destserver -DbName $dbName -MaxDop $MaxDop 3>$null
                            $endDbcc = Get-Date

                            $dbccts = New-TimeSpan -Start $startDbcc -End $endDbcc
                            $ts = [timespan]::fromseconds($dbccts.TotalSeconds)
                            $dbccElapsed = "{0:HH:mm:ss}" -f ([datetime]$ts.Ticks)
                        } else {
                            $dbccresult = "Skipped"
                        }
                    }
                }

                if ($VerifyOnly) {
                    $dbccresult = "Skipped"
                }

                if (-not $NoDrop -and $null -ne $destserver.databases[$dbName]) {
                    if ($Pscmdlet.ShouldProcess($dbName, "Dropping Database $dbName on $destination")) {
                        Write-Message -Level Verbose -Message "Dropping database."

                        ## Drop the database
                        try {
                            #Variable $removeresult marked as unused by PSScriptAnalyzer replace with $null to catch output
                            $null = Remove-DbaDatabase -SqlInstance $destserver -Database $dbName -Confirm:$false
                            Write-Message -Level Verbose -Message "Dropped $dbName Database on $destination."
                        } catch {
                            $destserver.Databases.Refresh()
                            if ($destserver.databases[$dbName]) {
                                Write-Message -Level Warning -Message "Failed to Drop database $dbName on $destination."
                            }
                        }
                    }
                }

                #Cleanup BackupFiles if -CopyFile and backup was moved to destination

                $destserver.Databases.Refresh()
                if ($destserver.Databases[$dbName] -and -not $NoDrop) {
                    Write-Message -Level Warning -Message "$dbName was not dropped."
                }

                if ($CopyFile) {
                    Write-Message -Level Verbose -Message "Removing copied backup file from $destination."
                    try {
                        $removearray | Remove-Item -ErrorAction Stop
                    } catch {
                        Write-Message -Level Warning -Message $_ -ErrorRecord $_ -Target $instance
                    }
                }
            }

            if ($Pscmdlet.ShouldProcess("console", "Showing results")) {
                [pscustomobject]@{
                    SourceServer   = $source
                    TestServer     = $destination
                    Database       = $db.name
                    FileExists     = $fileexists
                    Size           = [dbasize](($lastbackup.TotalSize | Measure-Object -Sum).Sum)
                    RestoreResult  = $success
                    DbccResult     = $dbccresult
                    RestoreStart   = [dbadatetime]$startRestore
                    RestoreEnd     = [dbadatetime]$endRestore
                    RestoreElapsed = $restoreElapsed
                    DbccMaxDop     = [int]$MaxDop
                    DbccStart      = [dbadatetime]$startDbcc
                    DbccEnd        = [dbadatetime]$endDbcc
                    DbccElapsed    = $dbccElapsed
                    BackupDates    = [String[]]($lastbackup.Start)
                    BackupFiles    = $lastbackup.FullName
                }
            }
        }
    }
}
# SIG # Begin signature block
# MIIjYAYJKoZIhvcNAQcCoIIjUTCCI00CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCD8WHJmpV73Q883
# iONhHEhesPOqfAJY747tMdYyL8xZLqCCHVkwggUaMIIEAqADAgECAhADBbuGIbCh
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
# BgorBgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCAgXSnMIQOe+NTiXM+IOPXupY8L
# 1MNIpmNX8gCpM7rlXzANBgkqhkiG9w0BAQEFAASCAQBAqsDyz8FuE6HXYgcprC2R
# 0JPch4yemcyUG9NI0qraJ11TwTN+kXPV4W6oHexxP3ECBkOeUv0NuDioZ9HqGGHb
# hkv3D4TyYxyxFCrG9ZlEjF5FekD/XtWzc8WUm0LrmYe3+wFVlNgB1zDHa28ZP46J
# 6TlXPbeqOZCiti9O+rc/c6ycLMzyN2YSQqmkladq5OMkl29ji9eBQTFhUZp+H++u
# ZhHnF2Pq4MIubYWFI6TlZ0axHYyac8B+ZOPjTq9G4aqXizqOP+gt5mQKKkrfUn6S
# bYrvrEoQCV2mfjQcXz7bBGhA+eBztR83PD/SuoLdpLIEJKz2lisnOWPpX1XWc8dT
# oYIDIDCCAxwGCSqGSIb3DQEJBjGCAw0wggMJAgEBMHcwYzELMAkGA1UEBhMCVVMx
# FzAVBgNVBAoTDkRpZ2lDZXJ0LCBJbmMuMTswOQYDVQQDEzJEaWdpQ2VydCBUcnVz
# dGVkIEc0IFJTQTQwOTYgU0hBMjU2IFRpbWVTdGFtcGluZyBDQQIQDE1pckuU+jwq
# Sj0pB4A9WjANBglghkgBZQMEAgEFAKBpMBgGCSqGSIb3DQEJAzELBgkqhkiG9w0B
# BwEwHAYJKoZIhvcNAQkFMQ8XDTIyMTExNzA4NTc1MFowLwYJKoZIhvcNAQkEMSIE
# IDyu3sxTMyOmq1MVoOqeLle+o9KpXXmLIlLmB7w66jbgMA0GCSqGSIb3DQEBAQUA
# BIICAHaxgqWYr/A3pxaHifWQOR1U22bibbsjBBflLPg+kXKMbSEWMNe2wtGvbM5t
# 2h1sFEkk/NyDAmIMrnsyJ0ouyyCrv1wVXRNzxLQ9sMG5MkIJXd4BZgx2C/PLLS0D
# +jRoTY87L6GNA8h6ASxqQo4PO1CVchNNTmyP148ceN4SmCuGLfmhM6EA669kfMoD
# CP7b3MgjyqeMw7xnmKCg6h6ko2SkXHgV8x+8ptZ69I6Y1Xkk4RSjyvAN2oYtXRd3
# PzvOfraN4pwTRDWn40RO34CwfKzBOSibbdf2UyxbYqR4EnuX7eFPdn78vUksH2XF
# 0Y4oSSKpC+9/byHzsYXWqcSDknM/ed2x+MU371379JVcdZBJvWY6S2ucjNsN5fFS
# /EjRDCRUzDZGYxsTrRTeA2321PME+QFcgScMuRYKK69ul4dwUnsgqMMvwM7OeNPa
# FT5UAPG/fTlM1iB/zN9BAMk3SPGqP+Uizkb46YqDMcazsmZQFPfkS1K76SzGirWz
# ftO7J4Y0PzZkuOpwU6FKKgmmwb9fkAgUVgPhiUGZrDu/6qSO2psICukZCfTyLaJl
# +yCN50OABQ1KpjcT14vZmnZ0qJ9S9AmY/Cd3WlhLzm3Giqyjm7gs3kQ2Rh/7wA7Z
# COtDUI43v1GUruTpUSuA+UIy/DIIGTAQBlq5o64XeydmBtr8
# SIG # End signature block
