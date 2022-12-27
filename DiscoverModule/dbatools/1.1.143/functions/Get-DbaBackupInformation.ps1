function Get-DbaBackupInformation {
    <#
    .SYNOPSIS
        Scan backup files and creates a set, compatible with Restore-DbaDatabase

    .DESCRIPTION
        Upon being passed a list of potential backups files this command will scan the files, select those that contain SQL Server
        backup sets. It will then filter those files down to a set

        The function defaults to working on a remote instance. This means that all paths passed in must be relative to the remote instance.
        XpDirTree will be used to perform the file scans

        Various means can be used to pass in a list of files to be considered. The default is to non recursively scan the folder
        passed in.

    .PARAMETER Path
        Path to SQL Server backup files.

        Paths passed in as strings will be scanned using the desired method, default is a non recursive folder scan
        Accepts multiple paths separated by ','

        Or it can consist of FileInfo objects, such as the output of Get-ChildItem or Get-Item. This allows you to work with
        your own file structures as needed

    .PARAMETER SqlInstance
        The SQL Server instance to be used to read the headers of the backup files

    .PARAMETER SqlCredential
        Login to the target instance using alternative credentials. Accepts PowerShell credentials (Get-Credential).

        Windows Authentication, SQL Server Authentication, Active Directory - Password, and Active Directory - Integrated are all supported.

        For MFA support, please use Connect-DbaInstance.

    .PARAMETER DatabaseName
        An array of Database Names to filter by. If empty all databases are returned.

    .PARAMETER SourceInstance
        If provided only backup originating from this destination will be returned. This SQL instance will not be connected to or involved in this work

    .PARAMETER NoXpDirTree
        If specified, this switch will cause the files to be parsed as local files to the SQL Server Instance provided. Errors may be observed when the SQL Server Instance cannot access the files being parsed.

    .PARAMETER NoXpDirRecurse
        If specified, this switch changes xp_dirtree behavior to not recurse the folder structure.

    .PARAMETER DirectoryRecurse
        If specified the provided path/directory will be traversed (only applies if not using XpDirTree)

    .PARAMETER Anonymise
        If specified we will output the results with ComputerName, InstanceName, Database, UserName, Paths, and Logical and Physical Names hashed out
        This options is mainly for use if we need you to submit details for fault finding to the dbatools team

    .PARAMETER ExportPath
        If specified the output will export via CliXml format to the specified file. This allows you to store the backup history object for later usage, or move it between computers

    .PARAMETER NoClobber
        If specified will stop Export from overwriting an existing file, the default is to overwrite

    .PARAMETER PassThru
        When data is exported the cmdlet will return no other output, this switch means it will also return the normal output which can be then piped into another command

    .PARAMETER MaintenanceSolution
        This switch tells the function that the folder is the root of a Ola Hallengren backup folder

    .PARAMETER IgnoreLogBackup
        This switch only works with the MaintenanceSolution switch. With an Ola Hallengren style backup we can be sure that the LOG folder contains only log backups and skip it.
        For all other scenarios we need to read the file headers to be sure.

    .PARAMETER IgnoreDiffBackup
        This switch only works with the MaintenanceSolution switch. With an Ola Hallengren style backup we can be sure that the DIFF folder contains only differential backups and skip it.
        For all other scenarios we need to read the file headers to be sure.

    .PARAMETER AzureCredential
        The name of the SQL Server credential to be used if restoring from an Azure hosted backup

    .PARAMETER Import
        When specified along with a path the command will import a previously exported BackupHistory object from an xml file.

    .PARAMETER EnableException
        Replaces user friendly yellow warnings with bloody red exceptions of doom!
        Use this if you want the function to throw terminating errors you want to catch.

    .NOTES
        Tags: DisasterRecovery, Backup, Restore
        Author: Chrissy LeMaire (@cl) | Stuart Moore (@napalmgram)

        Website: https://dbatools.io
        Copyright: (c) 2018 by dbatools, licensed under MIT
        License: MIT https://opensource.org/licenses/MIT

    .LINK
        https://dbatools.io/Get-DbaBackupInformation

    .EXAMPLE
        PS C:\> Get-DbaBackupInformation -SqlInstance Server1 -Path c:\backups\ -DirectoryRecurse

        Will use the Server1 instance to recursively read all backup files under c:\backups, and return a dbatools BackupHistory object

    .EXAMPLE
        PS C:\> Get-DbaBackupInformation -SqlInstance Server1 -Path c:\backups\ -DirectoryRecurse -ExportPath c:\store\BackupHistory.xml
        PS C:\> robocopy c:\store\ \\remoteMachine\C$\store\ BackupHistory.xml
        PS C:\> Get-DbaBackupInformation -Import -Path  c:\store\BackupHistory.xml | Restore-DbaDatabase -SqlInstance Server2 -TrustDbBackupHistory

        This example creates backup history output from server1 and copies the file to the remote machine in order to preserve backup history. It is then used to restore the databases onto server2.

    .EXAMPLE
        PS C:\> Get-DbaBackupInformation -SqlInstance Server1 -Path c:\backups\ -DirectoryRecurse -ExportPath C:\store\BackupHistory.xml -PassThru | Restore-DbaDatabase -SqlInstance Server2 -TrustDbBackupHistory

        In this example we gather backup information, export it to an xml file, and then pass it on through to Restore-DbaDatabase.
        This allows us to repeat the restore without having to scan all the backup files again

    .EXAMPLE
        PS C:\> Get-ChildItem c:\backups\ -recurse -files | Where-Object {$_.extension -in ('.bak','.trn') -and $_.LastWriteTime -gt (get-date).AddMonths(-1)} | Get-DbaBackupInformation -SqlInstance Server1 -ExportPath C:\backupHistory.xml

        This lets you keep a record of all backup history from the last month on hand to speed up refreshes

    .EXAMPLE
        PS C:\> $Backups = Get-DbaBackupInformation -SqlInstance Server1 -Path \\network\backups
        PS C:\> $Backups += Get-DbaBackupInformation -SqlInstance Server2 -NoXpDirTree -Path c:\backups

        Scan the unc folder \\network\backups with Server1, and then scan the C:\backups folder on
        Server2 not using xp_dirtree, adding the results to the first set.

    .EXAMPLE
        PS C:\> $Backups = Get-DbaBackupInformation -SqlInstance Server1 -Path \\network\backups -MaintenanceSolution

        When MaintenanceSolution is indicated we know we are dealing with the output from Ola Hallengren backup scripts. So we make sure that a FULL folder exists in the first level of Path, if not we shortcut scanning all the files as we have nothing to work with

    .EXAMPLE
        PS C:\> $Backups = Get-DbaBackupInformation -SqlInstance Server1 -Path \\network\backups -MaintenanceSolution -IgnoreLogBackup

        As we know we are dealing with an Ola Hallengren style backup folder from the MaintenanceSolution switch, when IgnoreLogBackup is also included we can ignore the LOG folder to skip any scanning of log backups. Note this also means they WON'T be restored

    #>
    [CmdletBinding( DefaultParameterSetName = "Create")]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSAvoidUsingPlainTextForPassword", "", Justification = "For Parameter AzureCredential")]
    param (
        [parameter(Mandatory, ValueFromPipeline)]
        [object[]]$Path,
        [parameter(Mandatory, ParameterSetName = "Create")]
        [DbaInstanceParameter]$SqlInstance,
        [parameter(ParameterSetName = "Create")]
        [PSCredential]$SqlCredential,
        [string[]]$DatabaseName,
        [string[]]$SourceInstance,
        [parameter(ParameterSetName = "Create")]
        [Switch]$NoXpDirTree,
        [parameter(ParameterSetName = "Create")]
        [Switch]$NoXpDirRecurse = $false,
        [parameter(ParameterSetName = "Create")]
        [switch]$DirectoryRecurse,
        [switch]$EnableException,
        [switch]$MaintenanceSolution,
        [switch]$IgnoreLogBackup,
        [switch]$IgnoreDiffBackup,
        [string]$ExportPath,
        [string]$AzureCredential,
        [parameter(ParameterSetName = "Import")]
        [switch]$Import,
        [switch][Alias('Anonymize')]$Anonymise,
        [Switch]$NoClobber,
        [Switch]$PassThru

    )
    begin {
        function Get-HashString {
            param(
                [String]$InString
            )

            $StringBuilder = New-Object System.Text.StringBuilder
            [System.Security.Cryptography.HashAlgorithm]::Create("md5").ComputeHash([System.Text.Encoding]::UTF8.GetBytes($InString)) | ForEach-Object {
                [Void]$StringBuilder.Append($_.ToString("x2"))
            }
            return $StringBuilder.ToString()
        }
        Write-Message -Level InternalComment -Message "Starting"
        Write-Message -Level Debug -Message "Parameters bound: $($PSBoundParameters.Keys -join ", ")"

        if (Test-Bound -ParameterName ExportPath) {
            if ($true -eq $NoClobber) {
                if (Test-Path $ExportPath) {
                    Stop-Function -Message "$ExportPath exists and NoClobber set"
                    return
                }
            }
        }
        if ($PSCmdlet.ParameterSetName -eq "Create") {
            try {
                $server = Connect-DbaInstance -SqlInstance $SqlInstance -SqlCredential $SqlCredential
            } catch {
                Stop-Function -Message "Failure" -Category ConnectionError -ErrorRecord $_ -Target $SqlInstance
                return
            }
        }

        if ($true -eq $IgnoreLogBackup -and $true -ne $MaintenanceSolution) {
            Write-Message -Message "IgnoreLogBackup can only by used with MaintenanceSolution. Will not be used" -Level Warning
        }
    }
    process {
        if (Test-FunctionInterrupt) { return }
        if ((Test-Bound -Parameter Import) -and ($true -eq $Import)) {
            foreach ($f in $Path) {
                if (Test-Path -Path $f) {
                    $groupResults += Import-Clixml -Path $f
                    foreach ($group in  $groupResults) {
                        $group.FirstLsn = [BigInt]$group.FirstLSN.ToString()
                        $group.CheckpointLSN = [BigInt]$group.CheckpointLSN.ToString()
                        $group.DatabaseBackupLsn = [BigInt]$group.DatabaseBackupLsn.ToString()
                        $group.LastLsn = [BigInt]$group.LastLsn.ToString()
                    }
                } else {
                    Write-Message -Message "$f does not exist or is unreadable" -Level Warning
                }
            }
        } else {
            $Files = @()
            $groupResults = @()
            if ($Path[0] -match 'http') { $NoXpDirTree = $true }
            if ($NoXpDirTree -ne $true) {
                foreach ($f in $path) {
                    if ([System.IO.Path]::GetExtension($f).Length -gt 1) {
                        if ("FullName" -notin $f.PSObject.Properties.name) {
                            $f = $f | Select-Object *, @{ Name = "FullName"; Expression = { $f } }
                        }
                        Write-Message -Message "Testing a single file $f " -Level Verbose
                        if ((Test-DbaPath -Path $f.FullName -SqlInstance $server)) {
                            $files += $f
                        } else {
                            Write-Message -Level Verbose -Message "$server cannot 'see' file $($f.FullName)"
                        }
                    } elseif ($True -eq $MaintenanceSolution) {
                        if ($true -eq $IgnoreLogBackup -and [System.IO.Path]::GetDirectoryName($f) -like '*LOG') {
                            Write-Message -Level Verbose -Message "Skipping Log Backups as requested"
                        } else {
                            Write-Message -Level Verbose -Message "OLA - Getting folder contents"
                            try {
                                $Files += Get-XpDirTreeRestoreFile -Path $f -SqlInstance $server -NoRecurse:$NoXpDirRecurse
                            } catch {
                                Stop-Function -Message "Failure on $($server.Name)" -ErrorRecord $PSItem -Target $server.Name -Continue
                            }
                        }
                    } else {
                        Write-Message -Message "Testing a folder $f" -Level Verbose
                        try {
                            $Files += $Check = Get-XpDirTreeRestoreFile -Path $f -SqlInstance $server -NoRecurse:$NoXpDirRecurse -EnableException
                        } catch {
                            Stop-Function -Message "Failure on $($server.Name)" -ErrorRecord $PSItem -Target $server.Name -Continue
                        }
                        if ($null -eq $check) {
                            Write-Message -Message "Nothing returned from $f" -Level Verbose
                        }
                    }
                }
            } else {
                ForEach ($f in $path) {
                    Write-Message -Level VeryVerbose -Message "Not using sql for $f"
                    if ($f -is [System.IO.FileSystemInfo]) {
                        if ($f.PsIsContainer -eq $true -and $true -ne $MaintenanceSolution) {
                            Write-Message -Level VeryVerbose -Message "folder $($f.FullName)"
                            $Files += Get-ChildItem -Path $f.FullName -File -Recurse:$DirectoryRecurse
                        } elseif ($f.PsIsContainer -eq $true -and $true -eq $MaintenanceSolution) {
                            if ($IgnoreLogBackup -and $f -notlike '*LOG' ) {
                                Write-Message -Level Verbose -Message "Skipping Log backups for Maintenance backups"
                            } else {
                                $Files += Get-ChildItem -Path $f.FullName -File -Recurse:$DirectoryRecurse
                            }
                        } elseif ($true -eq $MaintenanceSolution) {
                            $Files += Get-ChildItem -Path $f.FullName -Recurse:$DirectoryRecurse
                        } else {
                            Write-Message -Level VeryVerbose -Message "File"
                            $Files += $f.FullName
                        }
                    } else {
                        if ($true -eq $MaintenanceSolution) {
                            $Files += Get-XpDirTreeRestoreFile -Path $f\FULL -SqlInstance $server -NoRecurse
                            $Files += Get-XpDirTreeRestoreFile -Path $f\DIFF -SqlInstance $server -NoRecurse
                            $Files += Get-XpDirTreeRestoreFile -Path $f\LOG -SqlInstance $server -NoRecurse
                        } else {
                            Write-Message -Level VeryVerbose -Message "File"
                            $Files += $f
                        }
                    }
                }
            }

            if ($True -eq $MaintenanceSolution -and $True -eq $IgnoreLogBackup) {
                Write-Message -Level Verbose -Message "Skipping Log Backups as requested"
                $Files = $Files | Where-Object { $_.FullName -notlike '*\LOG\*' }
            }

            if ($True -eq $MaintenanceSolution -and $True -eq $IgnoreDiffBackup) {
                Write-Message -Level Verbose -Message "Skipping Differential Backups as requested"
                $Files = $Files | Where-Object { $_.FullName -notlike '*\DIFF\*' }
            }

            if ($Files.Count -gt 0) {
                Write-Message -Level Verbose -Message "Reading backup headers of $($Files.Count) files"
                try {
                    $FileDetails = Read-DbaBackupHeader -SqlInstance $server -Path $Files -AzureCredential $AzureCredential -EnableException
                } catch {
                    Stop-Function -Message "Failure on $($server.Name)" -ErrorRecord $PSItem -Target $server.Name -Continue
                }
            }

            $groupDetails = $FileDetails | Group-Object -Property BackupSetGUID

            foreach ($group in $groupDetails) {
                $dbLsn = $group.Group[0].DatabaseBackupLSN
                if (-not $dbLsn) {
                    $dbLsn = 0
                }
                $description = $group.Group[0].BackupTypeDescription
                if (-not $description) {
                    try {
                        $header = Read-DbaBackupHeader -SqlInstance $server -Path $Path -EnableException | Select-Object -First 1
                    } catch {
                        Stop-Function -Message "Failure on $($server.Name)" -ErrorRecord $PSItem -Target $server.Name -Continue
                    }
                    $description = switch ($header.BackupType) {
                        1 { "Full" }
                        2 { "Differential" }
                        3 { "Log" }
                    }
                }
                $historyObject = New-Object Sqlcollaborative.Dbatools.Database.BackupHistory
                $historyObject.ComputerName = $group.Group[0].MachineName
                $historyObject.InstanceName = $group.Group[0].ServiceName
                $historyObject.SqlInstance = $group.Group[0].ServerName
                $historyObject.Database = $group.Group[0].DatabaseName
                $historyObject.UserName = $group.Group[0].UserName
                $historyObject.Start = [DateTime]$group.Group[0].BackupStartDate
                $historyObject.End = [DateTime]$group.Group[0].BackupFinishDate
                $historyObject.Duration = ([DateTime]$group.Group[0].BackupFinishDate - [DateTime]$group.Group[0].BackupStartDate)
                $historyObject.Path = [string[]]$group.Group.BackupPath
                $historyObject.FileList = ($group.Group.FileList | Select-Object Type, LogicalName, PhysicalName, @{
                        Name       = "Size"
                        Expression = { [dbasize]$PSItem.Size }
                    } -Unique)
                $historyObject.TotalSize = $group.Group[0].BackupSize.Byte
                $HistoryObject.CompressedBackupSize = $group.Group[0].CompressedBackupSize.Byte
                $historyObject.Type = $description
                $historyObject.BackupSetId = $group.group[0].BackupSetGUID
                $historyObject.DeviceType = 'Disk'
                $historyObject.FullName = $group.Group.BackupPath
                $historyObject.Position = $group.Group[0].Position
                $historyObject.FirstLsn = $group.Group[0].FirstLSN
                $historyObject.DatabaseBackupLsn = $dbLsn
                $historyObject.CheckpointLSN = $group.Group[0].CheckpointLSN
                $historyObject.LastLsn = $group.Group[0].LastLsn
                $historyObject.SoftwareVersionMajor = $group.Group[0].SoftwareVersionMajor
                $historyObject.RecoveryModel = $group.Group.RecoveryModel
                $groupResults += $historyObject
            }
        }
        if (Test-Bound 'SourceInstance') {
            $groupResults = $groupResults | Where-Object { $_.InstanceName -in $SourceInstance }
        }

        if (Test-Bound 'DatabaseName') {
            $groupResults = $groupResults | Where-Object { $_.Database -in $DatabaseName }
        }
        if ($true -eq $Anonymise) {
            foreach ($group in $groupResults) {
                $group.ComputerName = Get-HashString -InString $group.ComputerName
                $group.InstanceName = Get-HashString -InString $group.InstanceName
                $group.SqlInstance = Get-HashString -InString $group.SqlInstance
                $group.Database = Get-HashString -InString $group.Database
                $group.UserName = Get-HashString -InString $group.UserName
                $group.Path = Get-HashString -InString  $group.Path
                $group.FullName = Get-HashString -InString $group.FullName
                $group.FileList = ($group.FileList | Select-Object Type,
                    @{Name = "LogicalName"; Expression = { Get-HashString -InString $_."LogicalName" } },
                    @{Name = "PhysicalName"; Expression = { Get-HashString -InString $_."PhysicalName" } })
            }
        }
        if ((Test-Bound -parameterName ExportPath) -and $null -ne $ExportPath) {
            $groupResults | Export-Clixml -Path $ExportPath -Depth 5 -NoClobber:$NoClobber
            if ($true -ne $PassThru) {
                return
            }
        }
        $groupResults | Sort-Object -Property End -Descending
    }
}

# SIG # Begin signature block
# MIIjYAYJKoZIhvcNAQcCoIIjUTCCI00CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCCknNMzWyUbyAhN
# oiRQV8NQ2Z0/Rhso+cY5o1kGvxOM7KCCHVkwggUaMIIEAqADAgECAhADBbuGIbCh
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
# BgorBgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCBnOxxBjsdOhlvTNKtkbbrs6LYz
# USHuTWHyGrHUbIO5MTANBgkqhkiG9w0BAQEFAASCAQAE4RJeojcm5+MPskaTa62v
# eDzRbbnJjD0Xkc+DYEfWC370o51RgKgWVATE8xjWWJB3X/u1QZ+8cGD7EKiu+CMw
# 9i15pD1B2hkPSFjCTvmROj3O76IIveivzmheIO0a95JziYlhG1dUOEvTeDMmXa5y
# o4oH/HDzmoEKrn0UcQPLEDuoij1UOimC7Vr5xhVMUBrOZqqAt3av0LzXPn1XfP1H
# wAVguCw7HuQAcVd81a9KShYeNtlKjqPrkwW0c9/RfHT+GE9ZnZ5ISOwIIuX+1von
# QO5//CJ/7wJNaAs+rQjHew18+sNPk5f+7trSTge+n0aD89r2Y7Uc3c635rjOZFRu
# oYIDIDCCAxwGCSqGSIb3DQEJBjGCAw0wggMJAgEBMHcwYzELMAkGA1UEBhMCVVMx
# FzAVBgNVBAoTDkRpZ2lDZXJ0LCBJbmMuMTswOQYDVQQDEzJEaWdpQ2VydCBUcnVz
# dGVkIEc0IFJTQTQwOTYgU0hBMjU2IFRpbWVTdGFtcGluZyBDQQIQDE1pckuU+jwq
# Sj0pB4A9WjANBglghkgBZQMEAgEFAKBpMBgGCSqGSIb3DQEJAzELBgkqhkiG9w0B
# BwEwHAYJKoZIhvcNAQkFMQ8XDTIyMTExNzA4NTU0MlowLwYJKoZIhvcNAQkEMSIE
# IEsaJ3U5yGwmQWz/h4fZ3qJjQsoQneRNwuDtgYgNN9vRMA0GCSqGSIb3DQEBAQUA
# BIICAFEiBT1e+ydZf8bWdDGitG0aRwQfgwLWUh+brD5w+6KNwnNsPCe9D84kCDmR
# Zc2EQbH0WuSv2fExSSG9KS61aoiK8tHda3swpMdrjTwf7+V/Qdyb50FAP/Z0elpK
# qIHA4y6vB6DdIL38nLm3Dh9VBYm95d5m44V5l64fPCeRfeBRq9teNhn4+1NxKNh1
# tHnX9cFvD4Hd6eIBWoGUzIDfUo8F01ge/tE2Y0MhgrBCwrjU8M1jNIagA2ni4HdO
# qatYDs89hG/wmClDuvExjpAlTuy2EcJqKWKSIadB78t8RhutMj1Oykq9rtKIz2w2
# GZMbLXLqVFK1UcRWwity1pLzFZQkyUn90d93xuqjR93kfsgcWEmWubz7uz3Oq84U
# FZNtie1g6+i1O6FaV0uBKEd1utc+WatUeLM5XDwVlwoECfSSzEWSvnFW5tgR3KIq
# b95nJ3CdsVHG25R5UBgb1heakjWWKk0qT5wA8TzixwT3Ba5/F3lUjYpROeTMPG3l
# mKXCyc2DqDtaLKxDWN/KYRcIBQPTcGdZ7KqqRosL86653QxkYNwwZPMDYgEhtvpH
# BIlVeEd3iBFEK2ChhUlO3hapVI4nxR+uwl+f/4HOYTN6YHMlw4R2s7Pgw3TkmhRc
# d8tenkjqRIpAQd98Bd3RX+feiWMIe3WwbIbyFZhZZ14n7FBU
# SIG # End signature block
