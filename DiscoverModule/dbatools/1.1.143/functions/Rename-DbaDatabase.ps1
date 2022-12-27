function Rename-DbaDatabase {
    <#
    .SYNOPSIS
        Changes database name, logical file names, file group names and physical file names (optionally handling the move). BETA VERSION.

    .DESCRIPTION
        Can change every database metadata that can be renamed.
        The ultimate goal is choosing to have a default template to enforce in your environment
        so your naming convention for every bit can be put in place in no time.
        The process is as follows (it follows the hierarchy of the entities):
        - database name is changed (optionally, forcing users out)
        - filegroup name(s) are changed accordingly
        - logical name(s) are changed accordingly
        - physical file(s) are changed accordingly
        - if Move is specified, the database will be taken offline and the move will initiate, then it will be taken online
        - if Move is not specified, the database remains online (unless SetOffline), and you are in charge of moving files
        If any of the above fails, the process stops.
        Please take a backup of your databases BEFORE using this, and remember to backup AFTER (also a FULL backup of master)

        It returns an object for each database with all the renames done, plus hidden properties showing a "human" representation of them.

        It's better you store the resulting object in a variable so you can inspect it in case of issues, e.g. "$result = Rename-DbaDatabase ....."

        To get a grasp without worrying of what would happen under the hood, use "Rename-DbaDatabase .... -Preview | Select-Object *"

    .PARAMETER SqlInstance
        Target any number of instances, in order to return their build state.

    .PARAMETER SqlCredential
        Login to the target instance using alternative credentials. Accepts PowerShell credentials (Get-Credential).

        Windows Authentication, SQL Server Authentication, Active Directory - Password, and Active Directory - Integrated are all supported.

        For MFA support, please use Connect-DbaInstance.

    .PARAMETER Database
        Targets only specified databases

    .PARAMETER ExcludeDatabase
        Excludes only specified databases

    .PARAMETER AllDatabases
        If you want to apply the naming convention system wide, you need to pass this parameter

    .PARAMETER DatabaseName
        Pass a template to rename the database name. Valid placeholders are:
        - <DBN> current database name
        - <DATE> date (yyyyMMdd)

    .PARAMETER FileGroupName
        Pass a template to rename file group name. Valid placeholders are:
        - <FGN> current filegroup name
        - <DBN> current database name
        - <DATE> date (yyyyMMdd)
        If distinct names cannot be generated, a counter will be appended (0001, 0002, 0003, etc)

    .PARAMETER LogicalName
        Pass a template to rename logical name. Valid placeholders are:
        - <FT> file type (ROWS, LOG)
        - <LGN> current logical name
        - <FGN> current filegroup name
        - <DBN> current database name
        - <DATE> date (yyyyMMdd)
        If distinct names cannot be generated, a counter will be appended (0001, 0002, 0003, etc)

    .PARAMETER FileName
        Pass a template to rename file name. Valid placeholders are:
        - <FNN> current file name (the basename, without directory nor extension)
        - <FT> file type (ROWS, LOG, MMO, FS)
        - <LGN> current logical name
        - <FGN> current filegroup name
        - <DBN> current database name
        - <DATE> date (yyyyMMdd)
        If distinct names cannot be generated, a counter will be appended (0001, 0002, 0003, etc)

    .PARAMETER ReplaceBefore
        If you pass this switch, all upper level "current names" will be inspected and replaced BEFORE doing the
        rename according to the template in the current level (remember the hierarchy):
        Let's say you have a database named "dbatools_HR", composed by 3 files
        - dbatools_HR_Data.mdf
        - dbatools_HR_Index.ndf
        - dbatools_HR_log.ldf
        Rename-DbaDatabase .... -Database "dbatools_HR" -DatabaseName "dbatools_HRARCHIVE" -FileName '<DBN><FNN>'
        would end up with this logic:
        - database --> no placeholders specified
        - dbatools_HR to dbatools_HRARCHIVE
        - filenames placeholders specified
        <DBN><FNN> --> current database name + current filename"
        - dbatools_HR_Data.mdf to dbatools_HRARCHIVEdbatools_HR_Data.mdf
        - dbatools_HR_Index.mdf to dbatools_HRARCHIVEdbatools_HR_Data.mdf
        - dbatools_HR_log.ldf to dbatools_HRARCHIVEdbatools_HR_log.ldf
        Passing this switch, instead, e.g.
        Rename-DbaDatabase .... -Database "dbatools_HR" -DatabaseName "dbatools_HRARCHIVE" -FileName '<DBN><FNN>' -ReplaceBefore
        end up with this logic instead:
        - database --> no placeholders specified
        - dbatools_HR to dbatools_HRARCHIVE
        - filenames placeholders specified,
        <DBN><FNN>, plus -ReplaceBefore --> current database name + replace OLD "upper level" names inside the current filename
        - dbatools_HR_Data.mdf to dbatools_HRARCHIVE_Data.mdf
        - dbatools_HR_Index.mdf to dbatools_HRARCHIVE_Data.mdf
        - dbatools_HR_log.ldf to dbatools_HRARCHIVE_log.ldf

    .PARAMETER Force
        Kills any open session to be able to do renames.

    .PARAMETER SetOffline
        Kills any open session and sets the database offline to be able to move files

    .PARAMETER Move
        If you want this function to move files, else you're the one in charge of it.
        This enables the same functionality as SetOffline, killing open transactions and putting the database
        offline, then do the actual rename and setting it online again afterwards

    .PARAMETER Preview
        Shows the renames without performing any operation (recommended to find your way around this function parameters ;-) )

    .PARAMETER WhatIf
        If this switch is enabled, no actions are performed but informational messages will be displayed that explain what would happen if the command were to run.

    .PARAMETER Confirm
        If this switch is enabled, you will be prompted for confirmation before executing any operations that change state.

    .PARAMETER InputObject
        Accepts piped database objects

    .PARAMETER EnableException
        By default, when something goes wrong we try to catch it, interpret it and give you a friendly warning message.
        This avoids overwhelming you with "sea of red" exceptions, but is inconvenient because it basically disables advanced scripting.
        Using this switch turns this "nice by default" feature off and enables you to catch exceptions with your own try/catch.

    .NOTES
        Tags: Database, Rename
        Author: Simone Bizzotto (@niphold)

        Website: https://dbatools.io
        Copyright: (c) 2018 by dbatools, licensed under MIT
        License: MIT https://opensource.org/licenses/MIT

    .LINK
        https://dbatools.io/Rename-DbaDatabase

    .EXAMPLE
        PS C:\> Rename-DbaDatabase -SqlInstance sqlserver2014a -Database HR -DatabaseName HR2 -Preview | Select-Object *

        Shows the detailed result set you'll get renaming the HR database to HR2 without doing anything

    .EXAMPLE
        PS C:\> Rename-DbaDatabase -SqlInstance sqlserver2014a -Database HR -DatabaseName HR2

        Renames the HR database to HR2

    .EXAMPLE
        PS C:\> Get-DbaDatabase -SqlInstance sqlserver2014a -Database HR | Rename-DbaDatabase -DatabaseName HR2

        Same as before, but with a piped database (renames the HR database to HR2)

    .EXAMPLE
        PS C:\> Rename-DbaDatabase -SqlInstance sqlserver2014a -Database HR -DatabaseName "dbatools_<DBN>"

        Renames the HR database to dbatools_HR

    .EXAMPLE
        PS C:\> Rename-DbaDatabase -SqlInstance sqlserver2014a -Database HR -DatabaseName "dbatools_<DBN>_<DATE>"

        Renames the HR database to dbatools_HR_20170807 (if today is 07th Aug 2017)

    .EXAMPLE
        PS C:\> Rename-DbaDatabase -SqlInstance sqlserver2014a -Database HR -FileGroupName "dbatools_<FGN>"

        Renames every FileGroup within HR to "dbatools_[the original FileGroup name]"

    .EXAMPLE
        PS C:\> Rename-DbaDatabase -SqlInstance sqlserver2014a -Database HR -DatabaseName "dbatools_<DBN>" -FileGroupName "<DBN>_<FGN>"

        Renames the HR database to "dbatools_HR", then renames every FileGroup within to "dbatools_HR_[the original FileGroup name]"

    .EXAMPLE
        PS C:\> Rename-DbaDatabase -SqlInstance sqlserver2014a -Database HR -FileGroupName "dbatools_<DBN>_<FGN>"
        PS C:\> Rename-DbaDatabase -SqlInstance sqlserver2014a -Database HR -DatabaseName "dbatools_<DBN>"

        Renames the HR database to "dbatools_HR", then renames every FileGroup within to "dbatools_HR_[the original FileGroup name]"

    .EXAMPLE
        PS C:\> Rename-DbaDatabase -SqlInstance sqlserver2014a -Database HR -DatabaseName "dbatools_<DBN>" -FileName "<DBN>_<FGN>_<FNN>"

        Renames the HR database to "dbatools_HR" and then all filenames as "dbatools_HR_[Name of the FileGroup]_[original_filename]"
        The db stays online (watch out!). You can then proceed manually to move/copy files by hand, set the db offline and then online again to finish the rename process

    .EXAMPLE
        PS C:\> Rename-DbaDatabase -SqlInstance sqlserver2014a -Database HR -DatabaseName "dbatools_<DBN>" -FileName "<DBN>_<FGN>_<FNN>" -SetOffline

        Renames the HR database to "dbatools_HR" and then all filenames as "dbatools_HR_[Name of the FileGroup]_[original_filename]"
        The db is then set offline (watch out!). You can then proceed manually to move/copy files by hand and then set it online again to finish the rename process

    .EXAMPLE
        PS C:\> Rename-DbaDatabase -SqlInstance sqlserver2014a -Database HR -DatabaseName "dbatools_<DBN>" -FileName "<DBN>_<FGN>_<FNN>" -Move

        Renames the HR database to "dbatools_HR" and then all filenames as "dbatools_HR_[Name of the FileGroup]_[original_filename]"
        The db is then set offline (watch out!). The function tries to do a simple rename and then sets the db online again to finish the rename process

    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = "Medium")]
    param (
        [parameter(Mandatory, ParameterSetName = "Server")]
        [DbaInstanceParameter[]]$SqlInstance,
        [PSCredential]
        $SqlCredential,
        [parameter(ParameterSetName = "Server")]
        [object[]]$Database,
        [object[]]$ExcludeDatabase,
        [switch]$AllDatabases,
        [string]$DatabaseName,
        [string]$FileGroupName,
        [string]$LogicalName,
        [string]$FileName,
        [switch]$ReplaceBefore,
        [switch]$Force,
        [switch]$Move,
        [switch]$SetOffline,
        [switch]$Preview,
        [parameter(Mandatory, ValueFromPipeline, ParameterSetName = "Pipe")]
        [Microsoft.SqlServer.Management.Smo.Database[]]$InputObject,
        [switch]$EnableException
    )

    begin {
        if ($Force) { $ConfirmPreference = 'none' }

        $CurrentDate = Get-Date -Format 'yyyyMMdd'

        function Get-DbaNameStructure($database) {
            $obj = @()
            # db name
            $obj += "- Database : $database"
            # FileGroups
            foreach ($fg in $database.FileGroups) {
                $obj += "  - FileGroup: $($fg.Name)"
                # LogicalNames
                foreach ($ln in $fg.Files) {
                    $obj += "    - Logical: $($ln.Name)"
                    $obj += "      - FileName: $($ln.FileName)"
                }
            }
            $obj += "  - Logfiles"
            foreach ($log in $database.LogFiles) {
                $obj += "    - Logical: $($log.Name)"
                $obj += "      - FileName: $($log.FileName)"
            }
            return $obj -Join "`n"
        }


        function Get-DbaKeyByValue($hashtable, $Value) {
            ($hashtable.GetEnumerator() | Where-Object Value -eq $Value).Name
        }

        if ((Test-Bound -ParameterName SetOffline) -and (-not(Test-Bound -ParameterName FileName))) {
            Stop-Function -Category InvalidArgument -Message "-SetOffline is only useful when -FileName is passed. Quitting."
        }
    }
    process {
        if (Test-FunctionInterrupt) { return }
        if (!$Database -and !$AllDatabases -and !$InputObject -and !$ExcludeDatabase) {
            Stop-Function -Message "You must specify a -AllDatabases or -Database/ExcludeDatabase to continue"
            return
        }
        if (!$DatabaseName -and !$FileGroupName -and !$LogicalName -and !$FileName) {
            Stop-Function -Message "You must specify at least one of -DatabaseName,-FileGroupName,-LogicalName or -Filename to continue"
            return
        }
        $dbs = @()
        if ($InputObject) {
            if ($InputObject.Name) {
                # comes from Get-DbaDatabase
                $dbs += $InputObject
            }
        } else {
            foreach ($instance in $SqlInstance) {
                try {
                    $server = Connect-DbaInstance -SqlInstance $instance -SqlCredential $sqlCredential
                } catch {
                    Stop-Function -Message "Failure" -Category ConnectionError -ErrorRecord $_ -Target $instance -Continue
                }
                $all_dbs = $server.Databases | Where-Object IsAccessible
                $dbs += $all_dbs | Where-Object { @('master', 'model', 'msdb', 'tempdb', 'distribution') -notcontains $_.Name }
                if ($Database) {
                    $dbs = $dbs | Where-Object { $Database -contains $_.Name }
                }
                if ($ExcludeDatabase) {
                    $dbs = $dbs | Where-Object { $ExcludeDatabase -notcontains $_.Name }
                }
            }
        }

        # holds all dbs per instance to avoid naming clashes
        $InstanceDbs = @{ }

        # holds all db file enumerations (used for -Move only)
        $InstanceFiles = @{ }

        #region db loop
        foreach ($db in $dbs) {
            # used to stop futher operations on database
            $failed = $false

            # pending renames initialized at db level
            $Pending_Renames = @()

            $Entities_Before = @{ }

            $server = $db.Parent
            if ($db.Name -in @('master', 'model', 'msdb', 'tempdb', 'distribution')) {
                Write-Message -Level Warning -Message "Database $($db.Name) is a system one, skipping..."
                continue
            }
            if (!$db.IsAccessible) {
                Write-Message -Level Warning -Message "Database $($db.Name) is not accessible, skipping..."
                continue
            }
            if ($db.IsMirroringEnabled -eq $true -or $db.AvailabilityGroupName.Length -gt 0) {
                Write-Message -Level Warning -Message "Database $($db.Name) is either mirrored or in an AG, skipping..."
                continue
            }
            $Server_Id = $server.DomainInstanceName
            if ( !$InstanceDbs.ContainsKey($Server_Id) ) {
                $InstanceDbs[$Server_Id] = @{ }
                foreach ($dn in $server.Databases.Name) {
                    $InstanceDbs[$Server_Id][$dn] = 1
                }
            }

            $Entities_Before['DBN'] = @{ }
            $Entities_Before['FGN'] = @{ }
            $Entities_Before['LGN'] = @{ }
            $Entities_Before['FNN'] = @{ }
            $Entities_Before['DBN'][$db.Name] = $db.Name
            #region databasename
            if ($DatabaseName) {
                $Orig_DBName = $db.Name
                # fixed replacements
                $NewDBName = $DatabaseName.Replace('<DBN>', $Orig_DBName).Replace('<DATE>', $CurrentDate)
                if ($Orig_DBName -eq $NewDBName) {
                    Write-Message -Level VeryVerbose -Message "Database name unchanged, skipping"
                } else {
                    if ($InstanceDbs[$Server_Id].ContainsKey($NewDBName)) {
                        Write-Message -Level Warning -Message "Database $NewDBName exists already, skipping this rename"
                        $failed = $true
                    } else {
                        if ($PSCmdlet.ShouldProcess($db, "Renaming Database $db to $NewDBName")) {
                            if ($Force) {
                                $server.KillAllProcesses($Orig_DBName)
                            }
                            try {
                                if (!$Preview) {
                                    $db.Rename($NewDBName)
                                }
                                $InstanceDbs[$Server_Id].Remove($Orig_DBName)
                                $InstanceDbs[$Server_Id][$NewDBName] = 1
                                $Entities_Before['DBN'][$Orig_DBName] = $NewDBName
                                #$db.Refresh()
                            } catch {
                                Stop-Function -Message "Failed to rename Database : $($_.Exception.InnerException.InnerException.InnerException)" -ErrorRecord $_ -Target $server.DomainInstanceName -OverrideExceptionMessage
                                # stop any further renames
                                $failed = $true
                            }
                        }
                    }
                }
            }
            #endregion databasename
            #region filegroupname
            if ($ReplaceBefore) {
                #backfill PRIMARY
                $Entities_Before['FGN']['PRIMARY'] = 'PRIMARY'
                foreach ($fg in $db.FileGroups.Name) {
                    $Entities_Before['FGN'][$fg] = $fg
                }
            }

            if (!$failed -and $FileGroupName) {
                $Editable_FGs = $db.FileGroups | Where-Object Name -ne 'PRIMARY'
                $New_FGNames = @{ }
                foreach ($fg in $db.FileGroups.Name) {
                    $New_FGNames[$fg] = 1
                }
                $FGCounter = 0
                foreach ($fg in $Editable_FGs) {
                    $Orig_FGName = $fg.Name
                    $Orig_Placeholder = $Orig_FGName
                    if ($ReplaceBefore) {
                        # at Filegroup level, we need to worry about database name
                        $Orig_Placeholder = $Orig_Placeholder.Replace($Entities_Before['DBN'][$Orig_DBName], '')
                    }
                    $NewFGName = $FileGroupName.Replace('<DBN>', $Entities_Before['DBN'][$db.Name]).Replace('<DATE>', $CurrentDate).Replace('<FGN>', $Orig_Placeholder)
                    $FinalFGName = $NewFGName
                    while ($fg.Name -ne $FinalFGName) {
                        if ($FinalFGName -in $New_FGNames.Keys) {
                            $FGCounter += 1
                            $FinalFGName = "$NewFGName$($FGCounter.ToString('000'))"
                        } else {
                            break
                        }
                    }
                    if ($fg.Name -eq $FinalFGName) {
                        Write-Message -Level VeryVerbose -Message "No rename necessary for FileGroup $($fg.Name) (on $db)"
                        continue
                    }
                    if ($PSCmdlet.ShouldProcess($db, "Renaming FileGroup $($fg.Name) to $FinalFGName")) {
                        try {
                            if (!$Preview) {
                                $fg.Rename($FinalFGName)
                            }
                            $New_FGNames.Remove($Orig_FGName)
                            $New_FGNames[$FinalFGName] = 1
                            $Entities_Before['FGN'][$Orig_FGName] = $FinalFGName
                        } catch {
                            Stop-Function -Message "Failed to rename FileGroup : $($_.Exception.InnerException.InnerException.InnerException)" -ErrorRecord $_ -Target $server.DomainInstanceName -OverrideExceptionMessage
                            # stop any further renames
                            $failed = $true
                            break
                        }
                    }
                }
                #$db.FileGroups.Refresh()
            }

            #endregion filegroupname
            #region logicalname
            if ($ReplaceBefore) {
                foreach ($fn in $db.FileGroups.Files.Name) {
                    $Entities_Before['LGN'][$fn] = $fn
                }
                foreach ($fn in $db.Logfiles.Name) {
                    $Entities_Before['LGN'][$fn] = $fn
                }
            }
            if (!$failed -and $LogicalName) {
                $New_LogicalNames = @{ }
                foreach ($fn in $db.FileGroups.Files.Name) {
                    $New_LogicalNames[$fn] = 1
                }
                foreach ($fn in $db.Logfiles.Name) {
                    $New_LogicalNames[$fn] = 1
                }
                $LNCounter = 0
                foreach ($fg in $db.FileGroups) {
                    $logicalfiles = @($fg.Files)
                    for ($i = 0; $i -lt $logicalfiles.Count; $i++) {
                        $logical = $logicalfiles[$i]
                        $FileType = switch ($fg.FileGroupType) {
                            'RowsFileGroup' { 'ROWS' }
                            'MemoryOptimizedDataFileGroup' { 'MMO' }
                            'FileStreamDataFileGroup' { 'FS' }
                            default { 'STD' }
                        }
                        $Orig_LGName = $logical.Name
                        $Orig_Placeholder = $Orig_LGName
                        if ($ReplaceBefore) {
                            # at Logical Name level, we need to worry about database name and filegroup name
                            $Orig_Placeholder = $Orig_Placeholder.Replace((Get-DbaKeyByValue -HashTable $Entities_Before['DBN'] -Value $db.Name), '').Replace(
                                (Get-DbaKeyByValue -HashTable $Entities_Before['FGN'] -Value $fg.Name), '')
                        }
                        $NewLGName = $LogicalName.Replace('<DBN>', $db.Name).Replace('<DATE>', $CurrentDate).Replace('<FGN>', $fg.Name).Replace(
                            '<FT>', $FileType).Replace('<LGN>', $Orig_Placeholder)
                        $FinalLGName = $NewLGName
                        while ($logical.Name -ne $FinalLGName) {
                            if ($FinalLGName -in $New_LogicalNames.Keys) {
                                $LNCounter += 1
                                $FinalLGName = "$NewLGName$($LNCounter.ToString('000'))"
                            } else {
                                break
                            }
                        }
                        if ($logical.Name -eq $FinalLGName) {
                            Write-Message -Level VeryVerbose -Message "No rename necessary for LogicalFile $($logical.Name) (on FileGroup $($fg.Name) (on $db))"
                            continue
                        }
                        if ($PSCmdlet.ShouldProcess($db, "Renaming LogicalFile $($logical.Name) to $FinalLGName (on FileGroup $($fg.Name))")) {
                            try {
                                if (!$Preview) {
                                    $logical.Rename($FinalLGName)
                                }
                                $New_LogicalNames.Remove($Orig_LGName)
                                $New_LogicalNames[$FinalLGName] = 1
                                $Entities_Before['LGN'][$Orig_LGName] = $FinalLGName
                            } catch {
                                Stop-Function -Message "Failed to Rename Logical File : $($_.Exception.InnerException.InnerException.InnerException)" -ErrorRecord $_ -Target $server.DomainInstanceName -OverrideExceptionMessage
                                # stop any further renames
                                $failed = $true
                                break
                            }
                        }
                    }
                }
                #$fg.Files.Refresh()
                if (!$failed) {
                    $logfiles = @($db.LogFiles)
                    for ($i = 0; $i -lt $logfiles.Count; $i++) {
                        $logicallog = $logfiles[$i]
                        $Orig_LGName = $logicallog.Name
                        $Orig_Placeholder = $Orig_LGName
                        if ($ReplaceBefore) {
                            # at Logical Name level, we need to worry about database name and filegroup name, but for logfiles filegroup is not there
                            $Orig_Placeholder = $Orig_Placeholder.Replace((Get-DbaKeyByValue -HashTable $Entities_Before['DBN'] -Value $db.Name), '').Replace(
                                (Get-DbaKeyByValue -HashTable $Entities_Before['FGN'] -Value $fg.Name), '')
                        }
                        $NewLGName = $LogicalName.Replace('<DBN>', $db.Name).Replace('<DATE>', $CurrentDate).Replace('<FGN>', '').Replace(
                            '<FT>', 'LOG').Replace('<LGN>', $Orig_Placeholder)
                        $FinalLGName = $NewLGName
                        if ($FinalLGName.Length -eq 0) {
                            #someone passed in -LogicalName '<FGN>'.... but we don't have FGN here
                            $FinalLGName = $Orig_LGName
                        }
                        while ($logicallog.Name -ne $FinalLGName) {
                            if ($FinalLGName -in $New_LogicalNames.Keys) {
                                $LNCounter += 1
                                $FinalLGName = "$NewLGName$($LNCounter.ToString('000'))"
                            } else {
                                break
                            }
                        }
                        if ($logicallog.Name -eq $FinalLGName) {
                            Write-Message -Level VeryVerbose -Message "No Rename necessary for LogicalFile log $($logicallog.Name) (LOG on (on $db))"
                            continue
                        }
                        if ($PSCmdlet.ShouldProcess($db, "Renaming LogicalFile log $($logicallog.Name) to $FinalLGName (LOG)")) {
                            try {
                                if (!$Preview) {
                                    $logicallog.Rename($FinalLGName)
                                }
                                $New_LogicalNames.Remove($Orig_LGName)
                                $New_LogicalNames[$FinalLGName] = 1
                                $Entities_Before['LGN'][$Orig_LGName] = $FinalLGName
                            } catch {
                                Stop-Function -Message "Failed to Rename Logical File : $($_.Exception.InnerException.InnerException.InnerException)" -ErrorRecord $_ -Target $server.DomainInstanceName -OverrideExceptionMessage
                                # stop any further renames
                                $failed = $true
                                break
                            }
                        }
                    }
                    #$db.Logfiles.Refresh()
                }
            }
            #endregion logicalname
            #region filename
            if ($ReplaceBefore) {
                foreach ($fn in $db.FileGroups.Files.FileName) {
                    $Entities_Before['FNN'][$fn] = $fn
                }
                foreach ($fn in $db.Logfiles.FileName) {
                    $Entities_Before['FNN'][$fn] = $fn
                }
            }
            if (!$failed -and $FileName) {

                $New_FileNames = @{ }
                foreach ($fn in $db.FileGroups.Files.FileName) {
                    $New_FileNames[$fn] = 1
                }
                foreach ($fn in $db.Logfiles.FileName) {
                    $New_FileNames[$fn] = 1
                }
                # we need to inspect what files are in the same directory
                # to avoid failing the process because the move won't work
                # here we have a dict keyed by instance and then keyed by path
                if ( !$InstanceFiles.ContainsKey($Server_Id) ) {
                    $InstanceFiles[$Server_Id] = @{ }
                }
                foreach ($fn in $New_FileNames.Keys) {
                    $dirname = [IO.Path]::GetDirectoryName($fn)
                    if ( !$InstanceFiles[$Server_Id].ContainsKey($dirname) ) {
                        $InstanceFiles[$Server_Id][$dirname] = @{ }
                        try {
                            $dirfiles = Get-DbaFile -SqlInstance $server -Path $dirname -EnableException
                        } catch {
                            Write-Message -Level Warning -Message "Failed to enumerate existing files at $dirname, move could go wrong"
                        }
                        foreach ($f in $dirfiles) {
                            $InstanceFiles[$Server_Id][$dirname][$f.Filename] = 1
                        }
                    }
                }
                $FNCounter = 0
                foreach ($fg in $db.FileGroups) {
                    $FG_Files = @($fg.Files)
                    foreach ($logical in $FG_Files) {
                        $FileType = switch ($fg.FileGroupType) {
                            'RowsFileGroup' { 'ROWS' }
                            'MemoryOptimizedDataFileGroup' { 'MMO' }
                            'FileStreamDataFileGroup' { 'FS' }
                            default { 'STD' }
                        }
                        $FNName = $logical.FileName
                        $FNNameDir = [IO.Path]::GetDirectoryName($FNName)
                        $Orig_FNNameLeaf = [IO.Path]::GetFileNameWithoutExtension($logical.FileName)
                        $Orig_Placeholder = $Orig_FNNameLeaf
                        if ($ReplaceBefore) {
                            # at Filename level, we need to worry about database name, filegroup name and logical file name
                            $Orig_Placeholder = $Orig_Placeholder.Replace((Get-DbaKeyByValue -HashTable $Entities_Before['DBN'] -Value $db.Name), '').Replace(
                                (Get-DbaKeyByValue -HashTable $Entities_Before['FGN'] -Value $fg.Name), '').Replace(
                                (Get-DbaKeyByValue -HashTable $Entities_Before['LGN'] -Value $logical.Name), '')
                        }
                        $NewFNName = $FileName.Replace('<DBN>', $db.Name).Replace('<DATE>', $CurrentDate).Replace('<FGN>', $fg.Name).Replace(
                            '<FT>', $FileType).Replace('<LGN>', $logical.Name).Replace('<FNN>', $Orig_Placeholder)
                        $FinalFNName = [IO.Path]::Combine($FNNameDir, "$NewFNName$([IO.Path]::GetExtension($FNName))")

                        while ($logical.FileName -ne $FinalFNName) {
                            if ($InstanceFiles[$Server_Id][$FNNameDir].ContainsKey($FinalFNName)) {
                                $FNCounter += 1
                                $FinalFNName = [IO.Path]::Combine($FNNameDir, "$NewFNName$($FNCounter.ToString('000'))$([IO.Path]::GetExtension($FNName))"
                                )
                            } else {
                                break
                            }
                        }
                        if ($logical.FileName -eq $FinalFNName) {
                            Write-Message -Level VeryVerbose -Message "No rename necessary (on FileGroup $($fg.Name) (on $db))"
                            continue
                        }
                        if ($PSCmdlet.ShouldProcess($db, "Renaming FileName $($logical.FileName) to $FinalFNName (on FileGroup $($fg.Name))")) {
                            try {
                                if (!$Preview) {
                                    $logical.FileName = $FinalFNName
                                    $db.Alter()
                                }
                                $InstanceFiles[$Server_Id][$FNNameDir].Remove($FNName)
                                $InstanceFiles[$Server_Id][$FNNameDir][$FinalFNName] = 1
                                $Entities_Before['FNN'][$FNName] = $FinalFNName
                                $Pending_Renames += [pscustomobject]@{
                                    Source      = $FNName
                                    Destination = $FinalFNName
                                }
                            } catch {
                                Stop-Function -Message "Failed to Rename FileName : $($_.Exception.InnerException.InnerException.InnerException)" -ErrorRecord $_ -Target $server.DomainInstanceName -OverrideExceptionMessage
                                # stop any further renames
                                $failed = $true
                                break
                            }
                        }
                    }
                    if (!$failed) {
                        $FG_Files = @($db.Logfiles)
                        foreach ($logical in $FG_Files) {
                            $FNName = $logical.FileName
                            $FNNameDir = [IO.Path]::GetDirectoryName($FNName)
                            $Orig_FNNameLeaf = [IO.Path]::GetFileNameWithoutExtension($logical.FileName)
                            $Orig_Placeholder = $Orig_FNNameLeaf
                            if ($ReplaceBefore) {
                                # at Filename level, we need to worry about database name, filegroup name and logical file name
                                $Orig_Placeholder = $Orig_Placeholder.Replace((Get-DbaKeyByValue -HashTable $Entities_Before['DBN'] -Value $db.Name), '').Replace(
                                    (Get-DbaKeyByValue -HashTable $Entities_Before['FGN'] -Value $fg.Name), '').Replace(
                                    (Get-DbaKeyByValue -HashTable $Entities_Before['LGN'] -Value $logical.Name), '')
                            }
                            $NewFNName = $FileName.Replace('<DBN>', $db.Name).Replace('<DATE>', $CurrentDate).Replace('<FGN>', '').Replace(
                                '<FT>', 'LOG').Replace('<LGN>', $logical.Name).Replace('<FNN>', $Orig_Placeholder)
                            $FinalFNName = [IO.Path]::Combine($FNNameDir, "$NewFNName$([IO.Path]::GetExtension($FNName))")
                            while ($logical.FileName -ne $FinalFNName) {
                                if ($InstanceFiles[$Server_Id][$FNNameDir].ContainsKey($FinalFNName)) {
                                    $FNCounter += 1
                                    $FinalFNName = [IO.Path]::Combine($FNNameDir, "$NewFNName$($FNCounter.ToString('000'))$([IO.Path]::GetExtension($FNName))")
                                } else {
                                    break
                                }
                            }
                            if ($logical.FileName -eq $FinalFNName) {
                                Write-Message -Level VeryVerbose -Message "No rename necessary for $($logical.FileName) (LOG on (on $db))"
                                continue
                            }

                            if ($PSCmdlet.ShouldProcess($db, "Renaming FileName $($logical.FileName) to $FinalFNName (LOG)")) {
                                try {
                                    if (!$Preview) {
                                        $logical.FileName = $FinalFNName
                                        $db.Alter()
                                    }
                                    $InstanceFiles[$Server_Id][$FNNameDir].Remove($FNName)
                                    $InstanceFiles[$Server_Id][$FNNameDir][$FinalFNName] = 1
                                    $Entities_Before['FNN'][$FNName] = $FinalFNName
                                    $Pending_Renames += [pscustomobject]@{
                                        Source      = $FNName
                                        Destination = $FinalFNName
                                    }
                                } catch {
                                    Stop-Function -Message "Failed to Rename FileName : $($_.Exception.InnerException.InnerException.InnerException)" -ErrorRecord $_ -Target $server.DomainInstanceName -OverrideExceptionMessage
                                    # stop any further renames
                                    $failed = $true
                                    break
                                }
                            }
                        }
                    }

                }
                #endregion filename
                #region move
                $ComputerName = $null
                $Final_Renames = New-Object System.Collections.ArrayList
                if ([DbaValidate]::IsLocalhost($server.ComputerName)) {
                    # locally ran so we can just use rename-item
                    $ComputerName = $server.ComputerName
                } else {
                    # let's start checking if we can access .ComputerName
                    $testPS = $false
                    if ($SqlCredential) {
                        # why does Test-PSRemoting require a Credential param ? this is ugly...
                        $testPS = Test-PSRemoting -ComputerName $server.ComputerName -Credential $SqlCredential -ErrorAction Stop
                    } else {
                        $testPS = Test-PSRemoting -ComputerName $server.ComputerName -ErrorAction Stop
                    }
                    if (!($testPS)) {
                        # let's try to resolve it to a more qualified name, without "cutting" knowledge about the domain (only $server.Name possibly holds the complete info)
                        $Resolved = (Resolve-DbaNetworkName -ComputerName $server.Name).FullComputerName
                        if ($SqlCredential) {
                            $testPS = Test-PSRemoting -ComputerName $Resolved -Credential $SqlCredential -ErrorAction Stop
                        } else {
                            $testPS = Test-PSRemoting -ComputerName $Resolved -ErrorAction Stop
                        }
                        if ($testPS) {
                            $ComputerName = $Resolved
                        }
                    } else {
                        $ComputerName = $server.ComputerName
                    }
                }
                foreach ($op in $pending_renames) {
                    if ([DbaValidate]::IsLocalhost($server.ComputerName)) {
                        $null = $Final_Renames.Add([pscustomobject]@{
                                Source       = $op.Source
                                Destination  = $op.Destination
                                ComputerName = $ComputerName
                            })
                    } else {
                        if ($null -eq $ComputerName) {
                            # if we don't have remote access ($ComputerName is null) we can fallback to admin shares if they're available
                            if (Test-Path (Join-AdminUnc -ServerName $server.ComputerName -filepath $op.Source)) {
                                $null = $Final_Renames.Add([pscustomobject]@{
                                        Source       = Join-AdminUnc -ServerName $server.ComputerName -filepath $op.Source
                                        Destination  = Join-AdminUnc -ServerName $server.ComputerName -filepath $op.Destination
                                        ComputerName = $server.ComputerName
                                    })
                            } else {
                                # flag the impossible rename ($ComputerName is $null)
                                $null = $Final_Renames.Add([pscustomobject]@{
                                        Source       = $op.Source
                                        Destination  = $op.Destination
                                        ComputerName = $ComputerName
                                    })
                            }
                        } else {
                            # we can do renames in a remote pssession
                            $null = $Final_Renames.Add([pscustomobject]@{
                                    Source       = $op.Source
                                    Destination  = $op.Destination
                                    ComputerName = $ComputerName
                                })
                        }
                    }
                }
                $Status = 'FULL'
                if (!$failed -and ($SetOffline -or $Move) -and $Final_Renames) {
                    if (!$Move) {
                        Write-Message -Level VeryVerbose -Message "Setting the database offline. You are in charge of moving the files to the new location"
                        # because renames still need to be dealt with
                        $Status = 'PARTIAL'
                    } else {
                        if ($PSCmdlet.ShouldProcess($db, "File Rename required, setting db offline")) {
                            $SetState = Set-DbaDbState -SqlInstance $server -Database $db.Name -Offline -Force
                            if ($SetState.Status -ne 'OFFLINE') {
                                Write-Message -Level Warning -Message "Setting db offline failed, You are in charge of moving the files to the new location"
                                # because it was impossible to set the database offline
                                $Status = 'PARTIAL'
                            } else {
                                try {
                                    while ($Final_Renames.Count -gt 0) {
                                        $op = $Final_Renames.Item(0)
                                        if ($null -eq $op.ComputerName) {
                                            Stop-Function -Message "No access to physical files for renames"
                                        } else {
                                            Write-Message -Level VeryVerbose -Message "Moving file $($op.Source) to $($op.Destination)"
                                            if (!$Preview) {
                                                $scriptBlock = {
                                                    $op = $args[0]
                                                    Rename-Item -Path $op.Source -NewName $op.Destination
                                                }
                                                Invoke-Command2 -ComputerName $op.ComputerName -Credential $sqlCredential -ScriptBlock $scriptBlock -ArgumentList $op
                                            }
                                        }
                                        $null = $Final_Renames.RemoveAt(0)
                                    }
                                } catch {
                                    $failed = $true
                                    # because a rename operation failed
                                    $Status = 'PARTIAL'
                                    Stop-Function -Message "Failed to rename $($op.Source) to $($op.Destination), you are in charge of moving the files to the new location" -ErrorRecord $_ -Target $instance -Exception $_.Exception -Continue
                                }
                                if (!$failed) {
                                    if ($PSCmdlet.ShouldProcess($db, "Setting database online")) {
                                        $SetState = Set-DbaDbState -SqlInstance $server -Database $db.Name -Online -Force
                                        if ($SetState.Status -ne 'ONLINE') {
                                            Write-Message -Level Warning -Message "Setting db online failed"
                                            # because renames were done, but the database didn't wake up
                                            $Status = 'PARTIAL'
                                        } else {
                                            $Status = 'FULL'
                                        }
                                    }
                                }
                            }
                        }
                    }
                } else {
                    # because of a previous error with renames to do
                    $Status = 'PARTIAL'
                }
            } else {
                if (!$failed) {
                    # because no previous error and not filename
                    $Status = 'FULL'
                } else {
                    # because previous errors and not filename
                    $Status = 'PARTIAL'
                }
            }
            #endregion move
            # remove entities that match for the output
            foreach ($k in $Entities_Before.Keys) {
                $ToRemove = $Entities_Before[$k].GetEnumerator() | Where-Object { $_.Name -eq $_.Value } | Select-Object -ExpandProperty Name
                foreach ($el in $ToRemove) {
                    $Entities_Before[$k].Remove($el)
                }
            }
            [pscustomobject]@{
                ComputerName       = $server.ComputerName
                InstanceName       = $server.ServiceName
                SqlInstance        = $server.DomainInstanceName
                Database           = $db
                DBN                = $Entities_Before['DBN']
                DatabaseRenames    = ($Entities_Before['DBN'].GetEnumerator() | ForEach-Object { "$($_.Name) --> $($_.Value)" }) -Join "`n"
                FGN                = $Entities_Before['FGN']
                FileGroupsRenames  = ($Entities_Before['FGN'].GetEnumerator() | ForEach-Object { "$($_.Name) --> $($_.Value)" }) -Join "`n"
                LGN                = $Entities_Before['LGN']
                LogicalNameRenames = ($Entities_Before['LGN'].GetEnumerator() | ForEach-Object { "$($_.Name) --> $($_.Value)" }) -Join "`n"
                FNN                = $Entities_Before['FNN']
                FileNameRenames    = ($Entities_Before['FNN'].GetEnumerator() | ForEach-Object { "$($_.Name) --> $($_.Value)" }) -Join "`n"
                PendingRenames     = $Final_Renames
                Status             = $Status
            } | Select-DefaultView -ExcludeProperty DatabaseRenames, FileGroupsRenames, LogicalNameRenames, FileNameRenames
        }
        #endregion db loop
    }
}
# SIG # Begin signature block
# MIIjYAYJKoZIhvcNAQcCoIIjUTCCI00CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCAbWZobs/3Vr11U
# 4atVehGQBrdhju6CtAtGwqNJ7ta7vKCCHVkwggUaMIIEAqADAgECAhADBbuGIbCh
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
# BgorBgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCACQS82i7BUYkRGTG+wl57SuhNj
# RwWTu2UtTzstMtZH5zANBgkqhkiG9w0BAQEFAASCAQAlNxAiRGpKzeXrJMTjBkNW
# Dw4rxH3ybk7yJImsD0zth8PFz0u4hE2ZDnXGlKZRs9rmJzsux+UGFyYwim12HKgx
# wXLj2aqLH0JlqAPjzbYGwiuQA8DSh0LPXyNRY+syyh67oxdROEiYBrlOqajexU2X
# cOnAuw4rMRtIpOfSIx2WxK8ykYlql9EmEqrBD3VuuVpg3TZMv5ErlZh/+s1gBoIg
# /Fy/MzKEVBnp1k+DBVF4m7reuuOJD3SWktkUFew4CYTlwx4+mcKVl0GAJ2fw1JEU
# /3nuTUswuipRysFK29JMp7yIVFhV9e7UVa/NCXIsXVsOf0ajnMmnO0iOuSfXKGOw
# oYIDIDCCAxwGCSqGSIb3DQEJBjGCAw0wggMJAgEBMHcwYzELMAkGA1UEBhMCVVMx
# FzAVBgNVBAoTDkRpZ2lDZXJ0LCBJbmMuMTswOQYDVQQDEzJEaWdpQ2VydCBUcnVz
# dGVkIEc0IFJTQTQwOTYgU0hBMjU2IFRpbWVTdGFtcGluZyBDQQIQDE1pckuU+jwq
# Sj0pB4A9WjANBglghkgBZQMEAgEFAKBpMBgGCSqGSIb3DQEJAzELBgkqhkiG9w0B
# BwEwHAYJKoZIhvcNAQkFMQ8XDTIyMTExNzA4NTcyMVowLwYJKoZIhvcNAQkEMSIE
# IHMUxUU0F4FpAAgNWMIrlbxtjjd8Kc+m52tjqMTXhB+VMA0GCSqGSIb3DQEBAQUA
# BIICAFzRaGI+/cEQHUjVSQn/B20cw5BomhKce8d9jt7oSRwJpo+LMvfpk3HVBGwa
# 2hW6KZhwmo4xtz1w4lZxy8CZf3qS/3tThe9pV9C1NZwWKxsmL1AdNtgKNgNbcwi8
# 8Li3xNs9a1yq+uGjbM89NPnBwTPCDyDH2CfP4mwIB5XcgcEc9oaGwBKMoA0xceM8
# 02R7UV6qOZlSvByeQJibPeL4kSsrwja5365EcKz9PfC0XxXyAUZ5rcMyoE+Ns+hI
# okFGqKkAyJjsaciLLT9RQ6CjV9TMG0SS4JcBDOrQhHz84kXg7HKj4t8kyqYboe39
# eImacPqCc4oRplziDKTc+U2s51NwlmqbPpNEsGqu+/AeT4h6Hp91zXqm6WSsrQFt
# GWqrWKOpHxfiVifzHTLm2Wi13EEBitHvr51iaBtOx2f3f0/AM2lANSFP1fUfxj8r
# pppI94lzPGkOyz94cHc6GpdY3dsgUF+fp7ctQEu4LukZNVw9Bl90CzCIOdJQT28w
# Rh1uNiW7SZF5zBzqHDFaYe08p1zh5TQXHkbr7d5CKuC4h9nQhlRB15zLGlZjp6tK
# GEuvxJWw/kFya6tZgGbOyEzT0UwViqxi1DKaAPtiFEJsxCN3TnSBKCI192nIesNm
# JGT2gcj5f0gAcsQAR+AV+64waJPIpbPMG0WVIKJMjJKCJyn7
# SIG # End signature block
