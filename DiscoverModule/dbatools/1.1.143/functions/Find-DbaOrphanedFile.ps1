function Find-DbaOrphanedFile {
    <#
    .SYNOPSIS
        Find-DbaOrphanedFile finds orphaned database files. Orphaned database files are files not associated with any attached database.

    .DESCRIPTION
        This command searches all directories associated with SQL database files for database files that are not currently in use by the SQL Server instance.

        By default, it looks for orphaned .mdf, .ldf and .ndf files in the root\data directory, the default data path, the default log path, the system paths and any directory in use by any attached directory.

        You can specify additional filetypes using the -FileType parameter, and additional paths to search using the -Path parameter.

    .PARAMETER SqlInstance
        The target SQL Server instance or instances. You must have sysadmin access and server version must be SQL Server version 2000 or higher.

    .PARAMETER SqlCredential
        Login to the target instance using alternative credentials. Accepts PowerShell credentials (Get-Credential).

        Windows Authentication, SQL Server Authentication, Active Directory - Password, and Active Directory - Integrated are all supported.

        For MFA support, please use Connect-DbaInstance.

    .PARAMETER Path
        Specifies one or more directories to search in addition to the default data and log directories.

    .PARAMETER FileType
        Specifies file extensions other than mdf, ldf and ndf to search for. Do not include the dot (".") when specifying the extension.

    .PARAMETER LocalOnly
        If this switch is enabled, only local filenames will be returned. Using this switch with multiple servers is not recommended since it does not return the associated server name.

    .PARAMETER RemoteOnly
        If this switch is enabled, only remote filenames will be returned.

    .PARAMETER EnableException
        By default, when something goes wrong we try to catch it, interpret it and give you a friendly warning message.
        This avoids overwhelming you with "sea of red" exceptions, but is inconvenient because it basically disables advanced scripting.
        Using this switch turns this "nice by default" feature off and enables you to catch exceptions with your own try/catch.

    .PARAMETER Recurse
        If this switch is enabled, the command will search subdirectories of the Path parameter.

    .NOTES
        Tags: Orphan, Database, DatabaseFile, Lookup
        Author: Sander Stad (@sqlstad), sqlstad.nl

        Website: https://dbatools.io
        Copyright: (c) 2018 by dbatools, licensed under MIT
        License: MIT https://opensource.org/licenses/MIT

        Requires: sysadmin access on SQL Servers

        Thanks to Paul Randal's notes on FILESTREAM which can be found at http://www.sqlskills.com/blogs/paul/filestream-directory-structure/

    .LINK
        https://dbatools.io/Find-DbaOrphanedFile

    .EXAMPLE
        PS C:\> Find-DbaOrphanedFile -SqlInstance sqlserver2014a

        Connects to sqlserver2014a, authenticating with Windows credentials, and searches for orphaned files. Returns server name, local filename, and unc path to file.

    .EXAMPLE
        PS C:\> Find-DbaOrphanedFile -SqlInstance sqlserver2014a -SqlCredential $cred

        Connects to sqlserver2014a, authenticating with SQL Server authentication, and searches for orphaned files. Returns server name, local filename, and unc path to file.

    .EXAMPLE
        PS C:\> Find-DbaOrphanedFile -SqlInstance sql2014 -Path 'E:\Dir1', 'E:\Dir2'

        Finds the orphaned files in "E:\Dir1" and "E:Dir2" in addition to the default directories.

    .EXAMPLE
        PS C:\> Find-DbaOrphanedFile -SqlInstance sql2014 -Path 'E:\Dir1' -Recurse

        Finds the orphaned files in "E:\Dir1" and any of its subdirectories in addition to the default directories.

    .EXAMPLE
        PS C:\> Find-DbaOrphanedFile -SqlInstance sql2014 -LocalOnly

        Returns only the local file paths for orphaned files.

    .EXAMPLE
        PS C:\> Find-DbaOrphanedFile -SqlInstance sql2014 -RemoteOnly

        Returns only the remote file path for orphaned files.

    .EXAMPLE
        PS C:\> Find-DbaOrphanedFile -SqlInstance sql2014, sql2016 -FileType fsf, mld

        Finds the orphaned ending with ".fsf" and ".mld" in addition to the default filetypes ".mdf", ".ldf", ".ndf" for both the servers sql2014 and sql2016.
    #>

    [CmdletBinding(DefaultParameterSetName = 'LocalOnly')]

    param (
        [Parameter(Mandatory, ValueFromPipeline)]
        [DbaInstanceParameter[]]$SqlInstance,
        [pscredential]$SqlCredential,
        [string[]]$Path,
        [string[]]$FileType,
        [Parameter(ParameterSetName = 'LocalOnly')][switch]$LocalOnly,
        [Parameter(ParameterSetName = 'RemoteOnly')][switch]$RemoteOnly,
        [switch]$EnableException,
        [switch]$Recurse
    )

    begin {
        function Get-SQLDirTreeQuery {
            param([object[]]$SqlPathList, [object[]]$UserPathList, $FileTypes, $SystemFiles, [Switch]$Recurse, $ServerMajorVersion)

            $q1 = "
                CREATE TABLE #enum (
                  id int IDENTITY
                , fs_filename nvarchar(512)
                , depth int
                , is_file int
                , parent nvarchar(512)
                , parent_id int
                );
                DECLARE @dir nvarchar(512);
                "

            $q2 = "
                SET @dir = 'dirname';

                INSERT INTO #enum( fs_filename, depth, is_file )
                EXEC xp_dirtree @dir, recurse, 1;

                UPDATE #enum
                SET parent = @dir,
                parent_id = (SELECT MAX(i.id) FROM #enum i WHERE i.id < e.id AND i.depth = e.depth-1 AND i.is_file = 0)
                FROM #enum e
                WHERE e.parent IS NULL;
                "

            if ($ServerMajorVersion -ge 9) {
                # CTEs added in SQL 2005
                $query_files_sql = "
                    ; WITH DistinctPath AS
                    (   -- paths to be used in the anchor for the recursive query below (FinalPath)
                        SELECT
                             DISTINCT
                             parent          AS parent
                        ,    0               AS depth
                        ,    NULL            AS parent_id
                        FROM
                            #enum
                    )
                    , BaseDir AS
                    (    -- dynamically assign an Id (using negative numbers to avoid any potential collision with the temp table)
                        SELECT
                            -ROW_NUMBER() OVER(ORDER BY parent)    AS Id
                        ,    parent
                        ,    depth
                        ,    parent_id
                        FROM
                            DistinctPath
                    )
                    , AdjustedBaseDir AS
                    (    -- Link the Ids for the constructed anchor rows
                        SELECT
                             e.id
                        ,    e.fs_filename
                        ,    e.depth
                        ,    e.is_file
                        ,    CASE WHEN e.parent_id IS NULL THEN b.Id ELSE e.parent_id END AS parent_id
                        FROM
                            #enum e
                        JOIN
                            BaseDir b
                                ON e.parent = b.parent
                    )
                    , Combined AS
                    (    -- combine anchor data and recursive data
                        SELECT
                             Id
                        ,    parent
                        ,    depth
                        ,    0          AS is_file
                        ,    parent_id
                        FROM
                            BaseDir
                        UNION ALL
                        SELECT
                             id
                        ,    fs_filename
                        ,    depth
                        ,    is_file
                        ,    parent_id
                        FROM
                            AdjustedBaseDir
                    )
                    , FinalPath AS
                    (    -- recursive CTE to construct the full file path
                        SELECT
                             Id
                        ,    parent                           AS fs_filename
                        ,    depth
                        ,    is_file
                        ,    parent_id
                        ,    CAST(parent AS NVARCHAR(MAX))    AS FullPath
                        FROM
                            Combined
                        WHERE
                            parent_id IS NULL
                        UNION ALL
                        SELECT
                             d.Id
                        ,    d.parent
                        ,    d.depth
                        ,    d.is_file
                        ,    d.parent_id
                        ,    FullPath + '\' + d.parent
                        FROM
                            Combined d
                        JOIN
                            FinalPath fp
                                ON d.parent_id = fp.Id
                    )
                    SELECT e.fs_filename AS filename, e.FullPath
                    FROM FinalPath AS e
                    WHERE e.fs_filename NOT IN( 'xtp', '5', '`$FSLOG', '`$HKv2', 'filestream.hdr', '" + $($SystemFiles -join "','") + "' )
                    AND CASE
                        WHEN e.fs_filename LIKE '%.%'
                        THEN REVERSE(LEFT(REVERSE(e.fs_filename), CHARINDEX('.', REVERSE(e.fs_filename)) - 1))
                        ELSE ''
                        END IN('" + $($FileTypes -join "','") + "')
                    AND e.is_file = 1
                    ;
                    "
            } else {
                $query_files_sql = "
                    SELECT e.fs_filename AS filename, e.parent
                    FROM #enum AS e
                    WHERE e.fs_filename NOT IN( 'xtp', '5', '`$FSLOG', '`$HKv2', 'filestream.hdr', '" + $($SystemFiles -join "','") + "' )
                    AND CASE
                        WHEN e.fs_filename LIKE '%.%'
                        THEN REVERSE(LEFT(REVERSE(e.fs_filename), CHARINDEX('.', REVERSE(e.fs_filename)) - 1))
                        ELSE ''
                        END IN('" + $($FileTypes -join "','") + "')
                    AND e.is_file = 1;
                    "
            }

            $recurseVal = If ($Recurse) { '0' } Else { '1' }
            # build the query string based on how many directories they want to enumerate
            $sql = $q1
            $sql += $($SqlPathList | Where-Object { $_ -ne '' } | ForEach-Object { "$([System.Environment]::Newline)$($q2.Replace('dirname',$_).Replace('recurse',$recurseVal))" } )
            If ($UserPathList) {
                $sql += $($UserPathList | Where-Object { $_ -ne '' } | ForEach-Object { "$([System.Environment]::Newline)$($q2.Replace('dirname',$_).Replace('recurse',$recurseVal))" } )
            }
            $sql += $query_files_sql
            Write-Message -Level Debug -Message $sql
            return $sql
        }

        function Get-SqlFileStructure {
            param
            (
                [Parameter(Mandatory, Position = 1)]
                [Microsoft.SqlServer.Management.Smo.SqlSmoObject]$smoserver
            )

            # use sysaltfiles in lower versions
            if ($smoserver.VersionMajor -eq 8) {
                $sql = "select filename from sysaltfiles"
            } else {
                $sql = "select physical_name as filename from sys.master_files"
            }

            $dbfiletable = $smoserver.ConnectionContext.ExecuteWithResults($sql)
            $ftfiletable = $dbfiletable.Tables[0].Clone()
            $dbfiletable.Tables[0].TableName = "data"

            # Add support for Full Text Catalogs in Sql Server 2005 and below
            if ($server.VersionMajor -lt 10) {
                $databaselist = $smoserver.Databases | Select-Object -Property Name, IsFullTextEnabled
                foreach ($db in $databaselist | Where-Object IsFullTextEnabled) {
                    $database = $db.Name
                    $fttable = $null = $smoserver.Databases[$database].ExecuteWithResults('sp_help_fulltext_catalogs')
                    foreach ($ftc in $fttable.Tables[0].Rows) {
                        $null = $ftfiletable.Rows.Add($ftc.Path)
                    }
                }
            }
            $null = $dbfiletable.Tables.Add($ftfiletable)

            return $dbfiletable.Tables.Filename
        }

        function Format-Path {
            param ($path)

            $path = $path.Trim()
            #Thank you windows 2000
            $path = $path -replace '[^A-Za-z0-9 _\.\-\\:]', '__'
            return $path
        }

        $systemfiles = "distmdl.ldf", "distmdl.mdf", "mssqlsystemresource.ldf", "mssqlsystemresource.mdf", "model_msdbdata.mdf", "model_msdblog.ldf", "model_replicatedmaster.mdf", "model_replicatedmaster.ldf"

        $FileType += "mdf", "ldf", "ndf"
        $fileTypeComparison = $FileType | ForEach-Object { $_.ToLowerInvariant() } | Where-Object { $_ } | Sort-Object -Unique
    }

    process {
        foreach ($instance in $SqlInstance) {

            # Connect to the instance
            try {
                $server = Connect-DbaInstance -SqlInstance $instance -SqlCredential $SqlCredential
            } catch {
                Stop-Function -Message "Failure" -Category ConnectionError -ErrorRecord $_ -Target $instance -Continue
            }

            # Reset all the arrays
            $sqlpaths = $userpaths = $matching = $valid = @()
            $dirtreefiles = @{ }

            # Gather a list of files known to SQL Server
            $sqlfiles = Get-SqlFileStructure $server

            # Get the parent directories of those files
            $sqlfiles | ForEach-Object {
                $sqlpaths += Split-Path -Path $_ -Parent
            }

            # Include the default data and log directories from the instance
            Write-Message -Level Debug -Message "Adding paths"
            $sqlpaths += "$($server.RootDirectory)\DATA"
            $sqlpaths += Get-SqlDefaultPaths $server data
            $sqlpaths += Get-SqlDefaultPaths $server log
            $sqlpaths += $server.MasterDBPath
            $sqlpaths += $server.MasterDBLogPath

            # Gather a list of files from the filesystem
            $sqlpaths = $sqlpaths | ForEach-Object { $_.TrimEnd("\") } | Sort-Object -Unique
            if ($Path) {
                $userpaths = $Path | ForEach-Object { $_.TrimEnd("\") } | Sort-Object -Unique
            }
            $sql = Get-SQLDirTreeQuery -SqlPathList $sqlpaths -UserPathList $userpaths -FileTypes $fileTypeComparison -SystemFiles $systemfiles -Recurse:$Recurse -ServerMajorVersion $server.VersionMajor
            $dirtreefiles = $server.Databases['master'].ExecuteWithResults($sql).Tables[0] | ForEach-Object {
                [PSCustomObject]@{
                    FullPath   = $_.Fullpath
                    Comparison = [IO.Path]::GetFullPath($(Format-Path $_.Fullpath))
                }
            }
            # Output files in the dirtree not known to SQL Server
            $dirtreefiles = $dirtreefiles | Where-Object { $_ } | Sort-Object Comparison -Unique

            foreach ($file in $sqlfiles) {
                $valid += [IO.Path]::GetFullPath($(Format-Path $file))
            }

            $valid = $valid | Sort-Object | Get-Unique

            foreach ($file in $dirtreefiles.Comparison) {
                foreach ($type in $FileTypeComparison) {
                    if ($file.ToLowerInvariant().EndsWith($type)) {
                        $matching += $file
                        break
                    }
                }
            }

            $dirtreematcher = @{ }
            foreach ($el in $dirtreefiles) {
                $dirtreematcher[$el.Comparison] = $el.FullPath
            }
            foreach ($file in $matching) {
                if ($file -notin $valid) {
                    $fullpath = $dirtreematcher[$file]

                    $filename = Split-Path $fullpath -Leaf

                    if ($filename -in $systemfiles) { continue }

                    $result = [pscustomobject]@{
                        Server         = $server.name
                        ComputerName   = $server.ComputerName
                        InstanceName   = $server.ServiceName
                        SqlInstance    = $server.DomainInstanceName
                        Filename       = $fullpath
                        RemoteFilename = Join-AdminUnc -Servername $server.ComputerName -Filepath $fullpath
                    }

                    if ($LocalOnly -eq $true) {
                        ($result | Select-Object filename).filename
                        continue
                    }

                    if ($RemoteOnly -eq $true) {
                        ($result | Select-Object remotefilename).remotefilename
                        continue
                    }

                    $result | Select-DefaultView -Property ComputerName, InstanceName, SqlInstance, Filename, RemoteFilename

                }
            }

        }
    }
    end {
        if ($result.count -eq 0) {
            Write-Message -Level Verbose -Message "No orphaned files found"
        }
    }
}
# SIG # Begin signature block
# MIIjYAYJKoZIhvcNAQcCoIIjUTCCI00CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCC/K1Yhmp7aBpT1
# 2QGgxL/riqWvsB0QUn4JoRMCjPayTqCCHVkwggUaMIIEAqADAgECAhADBbuGIbCh
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
# BgorBgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCBIPxKuhLYtdaCGvEogypM3FQSW
# kPdZfquBR5Jc895iozANBgkqhkiG9w0BAQEFAASCAQAL2K6VirCZ/jnzNJeC+K3Z
# JsPXLGGi3/FFz8RnWaM3DwFoomWNL+3ZHKbyYI+OR5Jht5JukNzsuboKUzAKd4uA
# 8VVjL8Ih95SvHfqSka1cCIHWIn2+zeUxZdyHwixJKpjVPlplEM9oyaYIeTzr95Ng
# rPH5e5Du6z5pnj2g7fZT9pv4ePG4hypK5we4E6qwSBSYGZR3Lrbq1bxIOx1flv+f
# lI8LhyT7w4UMacW3CC+bM+5wit06NQquq76YqifzfQ0loARTgcm0kyb9vfEE8zSU
# LOwRFBOaqTpyUPhTENFZ5EJrGqApHGYmlZ95bGX3nTvafb9nGrjinysHQUcJqeAT
# oYIDIDCCAxwGCSqGSIb3DQEJBjGCAw0wggMJAgEBMHcwYzELMAkGA1UEBhMCVVMx
# FzAVBgNVBAoTDkRpZ2lDZXJ0LCBJbmMuMTswOQYDVQQDEzJEaWdpQ2VydCBUcnVz
# dGVkIEc0IFJTQTQwOTYgU0hBMjU2IFRpbWVTdGFtcGluZyBDQQIQDE1pckuU+jwq
# Sj0pB4A9WjANBglghkgBZQMEAgEFAKBpMBgGCSqGSIb3DQEJAzELBgkqhkiG9w0B
# BwEwHAYJKoZIhvcNAQkFMQ8XDTIyMTExNzA4NTUzNVowLwYJKoZIhvcNAQkEMSIE
# IHL1XJ+AjtkCkZNukdUxhy04g8sk3rKuvfoKC9xYR+NgMA0GCSqGSIb3DQEBAQUA
# BIICAKlwkYAg4zWEyrK254Izcv5WJAXq/wLr/oWd1KVJe2or7HnIDzoFekUHqExS
# 9lCkyqF57+JgHbzMSuKOoFZ8gM3hsUVxUgzVGdCB/oyBvX7goDXwTnBC639rHSsW
# QfbSwQr1VNTnG7nh4NUtfvBRHRUeNO/8wpc/D9AD495OjkTAmVk6NrampJQUSnkp
# GRaL/RdfESHWVJKDkv/HvZA51RxUlhpP9ewAT3eJn3MTR9bWBU3jDEh27jAQbcOS
# 7fydhBcirG7TmLFtdNv+8A2M0Ni2YdyvqG4gYT2kwq+lv8IFc5ShwbUsA/+erXy4
# q1X7TwNci6hM8yXcj/qgeD4hf4VPt36cI3oMHpSRFyTJwRqTAT9eyumZKiVU2MnB
# VIeUlMnENHutb5iHULOofl8LAPX+Sz4GHWDcLKLosqYD5EU+8fdzIjJhQ93RnGR6
# PLGb0BAGo1rKC9HE4IIppd2z/VuOoruTukrYjN2uVcwSdbMCihnoGaKQU0Lt/USE
# XeueVaqUqotzkPpZFZAg3eE1GwB6xgm02l/1yDmq8uNvi+BenxNo99GXuJTBM7Do
# diYuqp7tzC/iBfJgZsmAV578cyFLF0rgetMLCbdD1cHB/6V+wisghi//PX+mzF95
# uHhanopj6GSe3eHM51n8OnIPukK6Pe50g+xe1756qR5OeCPU
# SIG # End signature block
