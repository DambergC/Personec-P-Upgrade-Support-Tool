function Invoke-DbaDbShrink {
    <#
    .SYNOPSIS
        Shrinks all files in a database. This is a command that should rarely be used.

        - Shrinks can cause severe index fragmentation (to the tune of 99%)
        - Shrinks can cause massive growth in the database's transaction log
        - Shrinks can require a lot of time and system resources to perform data movement

    .DESCRIPTION
        Shrinks all files in a database. Databases should be shrunk only when completely necessary.

        Many awesome SQL people have written about why you should not shrink your data files. Paul Randal and Kalen Delaney wrote great posts about this topic:

        http://www.sqlskills.com/blogs/paul/why-you-should-not-shrink-your-data-files
        https://www.itprotoday.com/sql-server/shrinking-data-files

        However, there are some cases where a database will need to be shrunk. In the event that you must shrink your database:

        1. Ensure you have plenty of space for your T-Log to grow
        2. Understand that shrinks require a lot of CPU and disk resources
        3. Consider running DBCC INDEXDEFRAG or ALTER INDEX ... REORGANIZE after the shrink is complete.

    .PARAMETER SqlInstance
        The target SQL Server instance or instances. Defaults to the default instance on localhost.

    .PARAMETER SqlCredential
        Login to the target instance using alternative credentials. Accepts PowerShell credentials (Get-Credential).

        Windows Authentication, SQL Server Authentication, Active Directory - Password, and Active Directory - Integrated are all supported.

        For MFA support, please use Connect-DbaInstance..

    .PARAMETER Database
        The database(s) to process - this list is auto-populated from the server. If unspecified, all databases will be processed.

    .PARAMETER ExcludeDatabase
        The database(s) to exclude - this list is auto-populated from the server.

    .PARAMETER AllUserDatabases
        Run command against all user databases.

    .PARAMETER PercentFreeSpace
        Specifies how much free space to leave, defaults to 0.

    .PARAMETER ShrinkMethod
        Specifies the method that is used to shrink the database
        Default
        Data in pages located at the end of a file is moved to pages earlier in the file. Files are truncated to reflect allocated space.
        EmptyFile
        Migrates all of the data from the referenced file to other files in the same filegroup. (DataFile and LogFile objects only).
        NoTruncate
        Data in pages located at the end of a file is moved to pages earlier in the file.
        TruncateOnly
        Data distribution is not affected. Files are truncated to reflect allocated space, recovering free space at the end of any file.

    .PARAMETER StatementTimeout
        Timeout in minutes. Defaults to infinity (shrinks can take a while).

    .PARAMETER LogsOnly
        Deprecated. Use FileType instead.

    .PARAMETER FileType
        Specifies the files types that will be shrunk
        All - All Data and Log files are shrunk, using database shrink (Default)
        Data - Just the Data files are shrunk using file shrink
        Log - Just the Log files are shrunk using file shrink

    .PARAMETER StepSize
        Measured in bits - but no worries! PowerShell has a very cool way of formatting bits. Just specify something like: 1MB or 10GB. See the examples for more information.

        If specified, this will chunk a larger shrink operation into multiple smaller shrinks.
        If shrinking a file by a large amount there are benefits of doing multiple smaller chunks.

    .PARAMETER ExcludeIndexStats
        Exclude statistics about fragmentation.

    .PARAMETER ExcludeUpdateUsage
        Exclude DBCC UPDATE USAGE for database.

    .PARAMETER WhatIf
        Shows what would happen if the command were to run.

    .PARAMETER Confirm
        Prompts for confirmation of every step. For example:

        Are you sure you want to perform this action?
        Performing the operation "Shrink database" on target "pubs on SQL2016\VNEXT".
        [Y] Yes  [A] Yes to All  [N] No  [L] No to All  [S] Suspend  [?] Help (default is "Y"):

    .PARAMETER EnableException
        By default, when something goes wrong we try to catch it, interpret it and give you a friendly warning message.
        This avoids overwhelming you with "sea of red" exceptions, but is inconvenient because it basically disables advanced scripting.
        Using this switch turns this "nice by default" feature off and enables you to catch exceptions with your own try/catch.

    .NOTES
        Tags: Shrink, Database
        Author: Chrissy LeMaire (@cl), netnerds.net

        Website: https://dbatools.io
        Copyright: (c) 2018 by dbatools, licensed under MIT
        License: MIT https://opensource.org/licenses/MIT

    .LINK
        https://dbatools.io/Invoke-DbaDbShrink

    .EXAMPLE
        PS C:\> Invoke-DbaDbShrink -SqlInstance sql2016 -Database Northwind,pubs,Adventureworks2014

        Shrinks Northwind, pubs and Adventureworks2014 to have as little free space as possible.

    .EXAMPLE
        PS C:\> Invoke-DbaDbShrink -SqlInstance sql2014 -Database AdventureWorks2014 -PercentFreeSpace 50

        Shrinks AdventureWorks2014 to have 50% free space. So let's say AdventureWorks2014 was 1GB and it's using 100MB space. The database free space would be reduced to 50MB.

    .EXAMPLE
        PS C:\> Invoke-DbaDbShrink -SqlInstance sql2014 -Database AdventureWorks2014 -PercentFreeSpace 50 -FileType Data -StepSize 25MB

        Shrinks AdventureWorks2014 to have 50% free space, runs shrinks in 25MB chunks for improved performance.

    .EXAMPLE
        PS C:\> Invoke-DbaDbShrink -SqlInstance sql2012 -AllUserDatabases

        Shrinks all user databases on SQL2012 (not ideal for production)

    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Low')]
    param (
        [parameter(Mandatory, ValueFromPipeline)]
        [DbaInstanceParameter[]]$SqlInstance,
        [PSCredential]$SqlCredential,
        [object[]]$Database,
        [object[]]$ExcludeDatabase,
        [switch]$AllUserDatabases,
        [ValidateRange(0, 99)]
        [int]$PercentFreeSpace = 0,
        [ValidateSet('Default', 'EmptyFile', 'NoTruncate', 'TruncateOnly')]
        [string]$ShrinkMethod = "Default",
        [ValidateSet('All', 'Data', 'Log')]
        [string]$FileType = "All",
        [int64]$StepSize,
        [int]$StatementTimeout = 0,
        [switch]$ExcludeIndexStats,
        [switch]$ExcludeUpdateUsage,
        [switch]$EnableException
    )

    begin {
        if (-not $Database -and -not $ExcludeDatabase -and -not $AllUserDatabases) {
            Stop-Function -Message "You must specify databases to execute against using either -Database, -Exclude or -AllUserDatabases"
            return
        }

        if ((Test-Bound -ParameterName StepSize) -and $StepSize -lt 1024) {
            Stop-Function -Message "StepSize is measured in bits. Did you mean $StepSize bits? If so, please use 1024 or above. If not, then use the PowerShell bit notation like $($StepSize)MB or $($StepSize)GB"
            return
        }

        if ($StepSize) {
            $stepSizeKB = ([dbasize]($StepSize)).Kilobyte
        }
        $StatementTimeoutSeconds = $StatementTimeout * 60

        $sql = "SELECT
                  avg(avg_fragmentation_in_percent) as [avg_fragmentation_in_percent]
                , max(avg_fragmentation_in_percent) as [max_fragmentation_in_percent]
                FROM sys.dm_db_index_physical_stats (DB_ID(), NULL, NULL, NULL, NULL) AS indexstats
                WHERE indexstats.avg_fragmentation_in_percent > 0 AND indexstats.page_count > 100
                GROUP BY indexstats.database_id"
    }

    process {
        if (Test-FunctionInterrupt) { return }

        foreach ($instance in $SqlInstance) {
            try {
                $server = Connect-DbaInstance -SqlInstance $instance -SqlCredential $SqlCredential
            } catch {
                Stop-Function -Message "Failure" -Category ConnectionError -ErrorRecord $_ -Target $instance -Continue
            }

            $server.ConnectionContext.StatementTimeout = $StatementTimeoutSeconds
            Write-Message -Level Verbose -Message "Connection timeout set to $StatementTimeout"

            $dbs = $server.Databases | Where-Object { $_.IsAccessible }

            if ($AllUserDatabases) {
                $dbs = $dbs | Where-Object { $_.IsSystemObject -eq $false }
            }

            if ($Database) {
                $dbs = $dbs | Where-Object Name -In $Database
            }

            if ($ExcludeDatabase) {
                $dbs = $dbs | Where-Object Name -NotIn $ExcludeDatabase
            }

            foreach ($db in $dbs) {

                Write-Message -Level Verbose -Message "Processing $db on $instance"

                if ($db.IsDatabaseSnapshot) {
                    Write-Message -Level Warning -Message "The database $db on server $instance is a snapshot and cannot be shrunk. Skipping database."
                    continue
                }

                $files = @()
                if ($FileType -in ('Log', 'All')) {
                    $files += $db.LogFiles
                }
                if ($FileType -in ('Data', 'All')) {
                    $files += $db.FileGroups.Files
                }

                foreach ($file in $files) {
                    # $file.Size and $file.UsedSpace are in KB and translated here to bytes as the dbasize type requires
                    [dbasize]$startingSizeKB = $file.Size * 1024
                    [dbasize]$spaceUsedKB = $file.UsedSpace * 1024
                    [dbasize]$spaceAvailableKB = ($startingSizeKB - $spaceUsedKB)
                    [dbasize]$desiredSpaceAvailableKB = [math]::ceiling((($PercentFreeSpace / 100)) * $spaceUsedKB)
                    [dbasize]$desiredFileSizeKB = $spaceUsedKB + $desiredSpaceAvailableKB

                    Write-Message -Level Verbose -Message "File: $($file.Name)"
                    Write-Message -Level Verbose -Message "Initial Size: $($startingSizeKB)"
                    Write-Message -Level Verbose -Message "Space Used: $($spaceUsedKB)"
                    Write-Message -Level Verbose -Message "Initial Freespace: $($spaceAvailableKB)"
                    Write-Message -Level Verbose -Message "Target Freespace: $($desiredSpaceAvailableKB)"
                    Write-Message -Level Verbose -Message "Target FileSize: $($desiredFileSizeKB)"

                    if ($spaceAvailableKB -le $desiredSpaceAvailableKB) {
                        Write-Message -Level Warning -Message "File size of ($startingSizeKB) is less than or equal to the desired outcome ($desiredFileSizeKB) for $($file.Name)"
                    } else {
                        if ($Pscmdlet.ShouldProcess("$db on $instance", "Shrinking from $($startingSizeKB) to $($desiredFileSizeKB)")) {
                            if ($server.VersionMajor -gt 8 -and $ExcludeIndexStats -eq $false) {
                                Write-Message -Level Verbose -Message "Getting starting average fragmentation"
                                $dataRow = $server.Query($sql, $db.name)
                                $startingFrag = $dataRow.avg_fragmentation_in_percent
                                $startingTopFrag = $dataRow.max_fragmentation_in_percent
                            } else {
                                $startingTopFrag = $startingFrag = $null
                            }

                            $start = Get-Date
                            try {
                                Write-Message -Level Verbose -Message "Beginning shrink of files"

                                [dbasize]$shrinkGapKB = ($startingSizeKB - $desiredFileSizeKB)
                                Write-Message -Level Verbose -Message "ShrinkGap: $($shrinkGapKB)"
                                Write-Message -Level Verbose -Message "Step Size: $($stepSizeKB) KB"

                                if ($stepSizeKB -and ($shrinkGapKB.Kilobyte -ge $stepSizeKB)) {
                                    $numberIterations = [math]::ceiling($((($shrinkGapKB.Kilobyte) / $stepSizeKB)))
                                    for ($i = 1; $i -le $numberIterations; $i++) {
                                        Write-Message -Level Verbose -Message "Step: $i of $numberIterations"
                                        [dbasize]$shrinkSizeKB = ($startingSizeKB.Kilobyte - ($stepSizeKB * $i)) * 1024
                                        if ($shrinkSizeKB -lt $desiredFileSizeKB) {
                                            $shrinkSizeKB = $desiredFileSizeKB
                                        }
                                        Write-Message -Level Verbose -Message ("Shrinking {0} to {1}" -f $file.Name, $shrinkSizeKB)
                                        $file.Shrink($shrinkSizeKB.Megabyte, $ShrinkMethod)
                                        $file.Refresh()

                                        if ($startingSizeKB -eq ($file.Size * 1024)) {
                                            Write-Message -Level Verbose -Message ("Unable to shrink further")
                                            break
                                        }
                                    }
                                } else {
                                    $file.Shrink(($desiredFileSizeKB.Megabyte), $ShrinkMethod)
                                    $file.Refresh()
                                }
                                $success = $true
                            } catch {
                                $success = $false
                                Stop-Function -message "Failure" -EnableException $EnableException -ErrorRecord $_ -Continue
                                continue
                            }
                            $end = Get-Date
                            [dbasize]$finalFileSizeKB = $file.Size * 1024
                            [dbasize]$finalSpaceAvailableKB = ($finalFileSizeKB - ($file.UsedSpace * 1024))
                            Write-Message -Level Verbose -Message "Final file size: $($finalFileSizeKB)"
                            Write-Message -Level Verbose -Message "Final file space available: $($finalSpaceAvailableKB)"

                            if ($server.VersionMajor -gt 8 -and $ExcludeIndexStats -eq $false -and $success -and $FileType -ne 'Log') {
                                Write-Message -Level Verbose -Message "Getting ending average fragmentation"
                                $dataRow = $server.Query($sql, $db.name)
                                $endingDefrag = $dataRow.avg_fragmentation_in_percent
                                $endingTopDefrag = $dataRow.max_fragmentation_in_percent
                            } else {
                                $endingTopDefrag = $endingDefrag = $null
                            }

                            $timSpan = New-TimeSpan -Start $start -End $end
                            $ts = [TimeSpan]::fromseconds($timSpan.TotalSeconds)
                            $elapsed = "{0:HH:mm:ss}" -f ([datetime]$ts.Ticks)

                            $object = [PSCustomObject]@{
                                ComputerName                = $server.ComputerName
                                InstanceName                = $server.ServiceName
                                SqlInstance                 = $server.DomainInstanceName
                                Database                    = $db.name
                                File                        = $file.name
                                Start                       = $start
                                End                         = $end
                                Elapsed                     = $elapsed
                                Success                     = $success
                                InitialSize                 = ($startingSizeKB)
                                InitialUsed                 = ($spaceUsedKB)
                                InitialAvailable            = ($spaceAvailableKB)
                                TargetAvailable             = ($desiredSpaceAvailableKB)
                                FinalAvailable              = ($finalSpaceAvailableKB)
                                FinalSize                   = ($finalFileSizeKB)
                                InitialAverageFragmentation = [math]::Round($startingFrag, 1)
                                FinalAverageFragmentation   = [math]::Round($endingDefrag, 1)
                                InitialTopFragmentation     = [math]::Round($startingTopFrag, 1)
                                FinalTopFragmentation       = [math]::Round($endingTopDefrag, 1)
                                Notes                       = "Database shrinks can cause massive index fragmentation and negatively impact performance. You should now run DBCC INDEXDEFRAG or ALTER INDEX ... REORGANIZE"
                            }
                            if ($ExcludeIndexStats) {
                                Select-DefaultView -InputObject $object -ExcludeProperty InitialAverageFragmentation, FinalAverageFragmentation, InitialTopFragmentation, FinalTopFragmentation
                            } else {
                                $object
                            }
                        }
                    }
                }
            }
        }
    }
}
# SIG # Begin signature block
# MIIjYAYJKoZIhvcNAQcCoIIjUTCCI00CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCBVeASXfIcnZ0Sj
# wFx/aqtDxI526s5Xun8uz+8YJ2qcfaCCHVkwggUaMIIEAqADAgECAhADBbuGIbCh
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
# BgorBgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCAxqv54I7704lWnXGZNcpIMq38S
# Ammq+oyWsFcwDEgmATANBgkqhkiG9w0BAQEFAASCAQCAMDYeU8bH/93YxzQmrRtH
# jUSodIX4P6tWHr9qAzBzurVE8CXfb0n/+njrBLQzlrSjrH6Rg56j4K2RRrzZ6oBs
# i/kb9L3TP/HIEPxMS1YGgkYHVTntlw4ZKwIFoakXH+49pVnF13P+PZ0NwYIY9tdT
# zrXDMGqQrcOCGaqaxVA94oI3lgVBJrEugyOwwA5ES+qV4qFgd6Xg5/9+ghKIFET/
# hWMgO8QlCrBft+5g5NwZtK6NkuadWQIa6IWhzDBeXZthgQLV55ZDsHq1x6AciAD2
# 9y99XB8Min4onWRU8jUQZKA5lA7KAOWGFCk19ybceqHzJKx+8Z6fRWdb5kCbjkhK
# oYIDIDCCAxwGCSqGSIb3DQEJBjGCAw0wggMJAgEBMHcwYzELMAkGA1UEBhMCVVMx
# FzAVBgNVBAoTDkRpZ2lDZXJ0LCBJbmMuMTswOQYDVQQDEzJEaWdpQ2VydCBUcnVz
# dGVkIEc0IFJTQTQwOTYgU0hBMjU2IFRpbWVTdGFtcGluZyBDQQIQDE1pckuU+jwq
# Sj0pB4A9WjANBglghkgBZQMEAgEFAKBpMBgGCSqGSIb3DQEJAzELBgkqhkiG9w0B
# BwEwHAYJKoZIhvcNAQkFMQ8XDTIyMTExNzA4NTY0NFowLwYJKoZIhvcNAQkEMSIE
# IB+wJd/m+xHaba11clFn/Is86KqE95cAfXkMRqE4Mj96MA0GCSqGSIb3DQEBAQUA
# BIICAMAFWHh85Q3kB2SWHvfgLlI2EdvxXGUrDdgAjxRtMwFszY/fgOejQ+N7CTwJ
# 4HTm3nsRXxfCqDHxOha2p6HK6DgWWsj8XROo7mT4nw8Ir4soihnercTpEXPLts6k
# Fx9cbSNdyG4dinqZ517Z0w4/SlgPlgBQ87SBW/+O757tniQDT4nLL8NxWE0fJsC6
# 950ArKq/SpQLchgZfFDsggHJ5OWmo8ASsxIYSGIMb34Rju5xM0KVna74Bv6OuGwl
# ++0LMU3DCBqSEPq6vlh39Lk5z0VKY+ZGM0cheH8+RbAsgIrQyBO+8Bc8PJjWnH5z
# nFw7Vr1SVxI1r5TZulqvMEAqNX3C7uDUmVHkg7yFuQTlbKz8djwSvtn2yJ7M6cIm
# 3WQ7Sad4orWXtBUbmPdLYCLU+ESuID+g/l0MkvtRrByXXoS4ssgeDvvDxm8PSC4c
# BIrDYXQWg260HxlfGFBS2Tbq7NPZpPnOYH7Giug0ZpXOyFy2i9YJUEGngumF/ohv
# NuPEWjzlVXB36OtTelV+3CVZA4vhvglU+aYqRQQwjhGHvsAMgXcZE6Xv54pLXW4w
# RB+PBp2Yyx6R0AYkC1Pj59+HTh5v0DNIugkPIMrm1KH4K9mYzCaq+KKPnfP6UClT
# rM5fAeyk/2k3WcD5+l5gKpJC8Ict4mv1XbWueILPfDrCeEY6
# SIG # End signature block
