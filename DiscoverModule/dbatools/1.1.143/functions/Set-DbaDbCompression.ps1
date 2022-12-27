function Set-DbaDbCompression {
    <#
    .SYNOPSIS
        Sets tables and indexes with preferred compression setting.

    .DESCRIPTION
        This function sets the appropriate compression recommendation, determined either by using the Tiger Team's query or set to the CompressionType parameter.

        Remember Uptime is critical for the Tiger Team query, the longer uptime, the more accurate the analysis is.
        You would probably be best if you utilized Get-DbaUptime first, before running this command.

        Set-DbaDbCompression script derived from GitHub and the tigertoolbox
        (https://github.com/Microsoft/tigertoolbox/tree/master/Evaluate-Compression-Gains)

    .PARAMETER SqlInstance
        The target SQL Server instance or instances. This can be a collection and receive pipeline input to allow the function to be executed against multiple SQL Server instances.

    .PARAMETER SqlCredential
        Login to the target instance using alternative credentials. Accepts PowerShell credentials (Get-Credential).

        Windows Authentication, SQL Server Authentication, Active Directory - Password, and Active Directory - Integrated are all supported.

        For MFA support, please use Connect-DbaInstance.

    .PARAMETER Database
        The database(s) to process - this list is auto populated from the server. If unspecified, all databases will be processed.

    .PARAMETER ExcludeDatabase
        The database(s) to exclude - this list is auto populated from the server.

    .PARAMETER Table
        The table(s) to process. If unspecified, all tables will be processed.

    .PARAMETER CompressionType
        Control the compression type applied. Default is 'Recommended' which uses the Tiger Team query to use the most appropriate setting per object. Other option is to compress all objects to either Row or Page.

    .PARAMETER MaxRunTime
        Will continue to alter tables and indexes for the given amount of minutes.

    .PARAMETER PercentCompression
        Will only work on the tables/indexes that have the calculated savings at and higher for the given number provided.

    .PARAMETER InputObject
        Takes the output of Test-DbaDbCompression as an object and applied compression based on those recommendations.

    .PARAMETER WhatIf
        If this switch is enabled, no actions are performed but informational messages will be displayed that explain what would happen if the command were to run.

    .PARAMETER Confirm
        If this switch is enabled, you will be prompted for confirmation before executing any operations that change state.

    .PARAMETER EnableException
        By default, when something goes wrong we try to catch it, interpret it and give you a friendly warning message.
        This avoids overwhelming you with "sea of red" exceptions, but is inconvenient because it basically disables advanced scripting.
        Using this switch turns this "nice by default" feature off and enables you to catch exceptions with your own try/catch.

    .NOTES
        Tags: Compression, Table, Database
        Author: Jason Squires (@js_0505), jstexasdba@gmail.com

        Website: https://dbatools.io
        Copyright: (c) 2018 by dbatools, licensed under MIT
        License: MIT https://opensource.org/licenses/MIT

    .LINK
        https://dbatools.io/Set-DbaDbCompression

    .EXAMPLE
        PS C:\> Set-DbaDbCompression -SqlInstance localhost -MaxRunTime 60 -PercentCompression 25

        Set the compression run time to 60 minutes and will start the compression of tables/indexes that have a difference of 25% or higher between current and recommended.

    .EXAMPLE
        PS C:\> Set-DbaDbCompression -SqlInstance ServerA -Database DBName -CompressionType Page -Table table1, table2

        Utilizes Page compression for tables table1 and table2 in DBName on ServerA with no time limit.

    .EXAMPLE
        PS C:\> Set-DbaDbCompression -SqlInstance ServerA -Database DBName -PercentCompression 25 | Out-GridView

        Will compress tables/indexes within the specified database that would show any % improvement with compression and with no time limit. The results will be piped into a nicely formatted GridView.

    .EXAMPLE
        PS C:\> $testCompression = Test-DbaDbCompression -SqlInstance ServerA -Database DBName
        PS C:\> Set-DbaDbCompression -SqlInstance ServerA -Database DBName -InputObject $testCompression

        Gets the compression suggestions from Test-DbaDbCompression into a variable, this can then be reviewed and passed into Set-DbaDbCompression.

    .EXAMPLE
        PS C:\> $cred = Get-Credential sqladmin
        PS C:\> Set-DbaDbCompression -SqlInstance ServerA -ExcludeDatabase Database -SqlCredential $cred -MaxRunTime 60 -PercentCompression 25

        Set the compression run time to 60 minutes and will start the compression of tables/indexes for all databases except the specified excluded database. Only objects that have a difference of 25% or higher between current and recommended will be compressed.

    .EXAMPLE
        PS C:\> $servers = 'Server1','Server2'
        PS C:\> foreach ($svr in $servers) {
        >> Set-DbaDbCompression -SqlInstance $svr -MaxRunTime 60 -PercentCompression 25 | Export-Csv -Path C:\temp\CompressionAnalysisPAC.csv -Append
        >> }

        Set the compression run time to 60 minutes and will start the compression of tables/indexes across all listed servers that have a difference of 25% or higher between current and recommended. Output of command is exported to a csv.

    #>
    [CmdletBinding(DefaultParameterSetName = "Default", SupportsShouldProcess)]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSUseOutputTypeCorrectly", "", Justification = "PSSA Rule Ignored by BOH")]
    param (
        [parameter(Mandatory, ValueFromPipeline)]
        [DbaInstanceParameter[]]$SqlInstance,
        [PSCredential]$SqlCredential,
        [string[]]$Database,
        [string[]]$ExcludeDatabase,
        [string[]]$Table,
        [ValidateSet("Recommended", "Page", "Row", "None")]
        [string]$CompressionType = "Recommended",
        [int]$MaxRunTime = 0,
        [int]$PercentCompression = 0,
        $InputObject,
        [switch]$EnableException
    )

    process {
        $starttime = Get-Date
        foreach ($instance in $SqlInstance) {
            try {
                $server = Connect-DbaInstance -SqlInstance $instance -SqlCredential $SqlCredential -MinimumVersion 10 -StatementTimeout 0
            } catch {
                Stop-Function -Message "Failure" -Category ConnectionError -ErrorRecord $_ -Target $instance -Continue
            }

            #The reason why we do this is because of SQL 2016 and they now allow for compression on standard edition.
            if ($server.EngineEdition -notmatch 'Enterprise' -and $server.VersionMajor -lt '13') {
                Stop-Function -Message "Only SQL Server Enterprise Edition supports compression on $server" -Target $server -Continue
            }

            $dbs = $server.Databases | Where-Object { $_.IsAccessible -and $_.IsSystemObject -eq 0 }
            if ($Database) {
                $dbs = $dbs | Where-Object { $_.Name -in $Database }
            }
            if ($ExcludeDatabase) {
                $dbs = $dbs | Where-Object { $_.Name -NotIn $ExcludeDatabase }
            }

            foreach ($db in $dbs) {
                Write-Message -Level Verbose -Message "Querying $instance - $db"
                if ($db.Status -ne 'Normal') {
                    Write-Message -Level Warning -Message "$db has status $($db.Status) and will be skipped." -Target $db
                    continue
                }
                if ($db.CompatibilityLevel -lt 'Version100') {
                    Write-Message -Level Warning -Message "$db has a compatibility level lower than Version100 and will be skipped."
                    continue
                }
                if ($CompressionType -eq "Recommended") {
                    if (Test-Bound "InputObject") {
                        Write-Message -Level Verbose -Message "Using passed in compression suggestions"
                        $compressionSuggestion = $InputObject | Where-Object { $_.Database -eq $db.Name }
                    } else {
                        if ($Pscmdlet.ShouldProcess($db, "Testing database for compression suggestions on $instance")) {
                            try {
                                $compressionSuggestion = Test-DbaDbCompression -SqlInstance $server -Database $db.Name -Table $Table -EnableException
                            } catch {
                                Stop-Function -Message "Unable to test database compression suggestions for $instance - $db" -Target $db -ErrorRecord $_ -Continue
                            }
                        }
                    }

                    if ($Pscmdlet.ShouldProcess($db, "Applying suggested compression using results from Test-DbaDbCompression")) {
                        $objects = $compressionSuggestion | Select-Object *, @{l = 'AlreadyProcessed'; e = { "False" } }
                        foreach ($obj in ($objects | Where-Object { $_.CompressionTypeRecommendation -notin @('NO_GAIN', '?') -and $_.PercentCompression -ge $PercentCompression } | Sort-Object PercentCompression -Descending)) {
                            if ($MaxRunTime -ne 0 -and ($(Get-Date) - $starttime).TotalMinutes -ge $MaxRunTime) {
                                Write-Message -Level Warning -Message "Reached max run time of $MaxRunTime"
                                break
                            }
                            if ($obj.indexId -le 1) {
                                ##heaps and clustered indexes
                                Write-Message -Level Verbose -Message "Applying $($obj.CompressionTypeRecommendation) compression to $($obj.Database).$($obj.Schema).$($obj.TableName)"
                                try {
                                    ($server.Databases[$obj.Database].Tables[$obj.TableName, $obj.Schema].PhysicalPartitions | Where-Object { $_.PartitionNumber -eq $obj.Partition }).DataCompression = $obj.CompressionTypeRecommendation
                                    $server.Databases[$obj.Database].Tables[$obj.TableName, $obj.Schema].Rebuild()
                                } catch {
                                    Stop-Function -Message "Compression failed for $instance - $db - table $($obj.Schema).$($obj.TableName) - partition $($obj.Partition)" -Target $db -ErrorRecord $_ -Continue
                                }
                            } else {
                                ##nonclustered indexes
                                Write-Message -Level Verbose -Message "Applying $($obj.CompressionTypeRecommendation) compression to $($obj.Database).$($obj.Schema).$($obj.TableName).$($obj.IndexName)"
                                try {
                                    ($server.Databases[$obj.Database].Tables[$obj.TableName, $obj.Schema].Indexes[$obj.IndexName].PhysicalPartitions | Where-Object { $_.PartitionNumber -eq $obj.Partition }).DataCompression = $obj.CompressionTypeRecommendation
                                    $server.Databases[$obj.Database].Tables[$obj.TableName, $obj.Schema].Indexes[$obj.IndexName].Rebuild()
                                } catch {
                                    Stop-Function -Message "Compression failed for $instance - $db - table $($obj.Schema).$($obj.TableName) - index $($obj.IndexName) - partition $($obj.Partition)" -Target $db -ErrorRecord $_ -Continue
                                }
                            }
                            $obj.AlreadyProcessed = "True"
                            $obj
                        }
                    }
                } else {
                    if ($Pscmdlet.ShouldProcess($db, "Applying $CompressionType compression")) {
                        $tables = $server.Databases[$($db.name)].Tables
                        if ($Table) {
                            $tables = $tables | Where-Object Name -in $Table
                        }

                        foreach ($obj in $tables | Where-Object { !$_.IsMemoryOptimized -and !$_.HasSparseColumn }) {
                            if ($MaxRunTime -ne 0 -and ($(Get-Date) - $starttime).TotalMinutes -ge $MaxRunTime) {
                                Write-Message -Level Warning -Message "Reached max run time of $MaxRunTime"
                                break
                            }
                            foreach ($p in $($obj.PhysicalPartitions | Where-Object { $_.DataCompression -notin ($CompressionType, 'ColumnStore', 'ColumnStoreArchive') })) {
                                Write-Message -Level Verbose -Message "Compressing table $($obj.Schema).$($obj.Name)"
                                try {
                                    $($obj.PhysicalPartitions | Where-Object { $_.PartitionNumber -eq $p.PartitionNumber }).DataCompression = $CompressionType
                                    $obj.Rebuild()
                                } catch {
                                    Stop-Function -Message "Compression failed for $instance - $db - table $($obj.Schema).$($obj.Name) - partition $($p.PartitionNumber)" -Target $db -ErrorRecord $_ -Continue
                                }
                                [pscustomobject]@{
                                    ComputerName                  = $server.ComputerName
                                    InstanceName                  = $server.ServiceName
                                    SqlInstance                   = $server.DomainInstanceName
                                    Database                      = $db.Name
                                    Schema                        = $obj.Schema
                                    TableName                     = $obj.Name
                                    IndexName                     = $null
                                    Partition                     = $p.PartitionNumber
                                    IndexID                       = 0
                                    IndexType                     = Switch ($obj.HasHeapIndex) { $false { "ClusteredIndex" } $true { "Heap" } }
                                    PercentScan                   = $null
                                    PercentUpdate                 = $null
                                    RowEstimatePercentOriginal    = $null
                                    PageEstimatePercentOriginal   = $null
                                    CompressionTypeRecommendation = $CompressionType.ToUpper()
                                    SizeCurrent                   = $null
                                    SizeRequested                 = $null
                                    PercentCompression            = $null
                                    AlreadyProcessed              = "True"
                                }
                            }

                            foreach ($index in $($obj.Indexes | Where-Object { !$_.IsMemoryOptimized -and $_.IndexType -notmatch 'Columnstore' })) {
                                if ($MaxRunTime -ne 0 -and ($(Get-Date) - $starttime).TotalMinutes -ge $MaxRunTime) {
                                    Write-Message -Level Warning -Message "Reached max run time of $MaxRunTime"
                                    break
                                }
                                foreach ($p in $($index.PhysicalPartitions | Where-Object { $_.DataCompression -ne $CompressionType })) {
                                    Write-Message -Level Verbose -Message "Compressing $($Index.IndexType) $($Index.Name) Partition $($p.PartitionNumber)"
                                    try {
                                        ## There is a bug in SMO where setting compression to None at the index level doesn't work
                                        ## Once this UserVoice item is fixed the workaround can be removed
                                        ## https://feedback.azure.com/forums/908035-sql-server/suggestions/34080112-data-compression-smo-bug
                                        if ($CompressionType -eq "None") {
                                            $query = "ALTER INDEX [$($index.Name)] ON $($index.Parent) REBUILD PARTITION = ALL WITH (DATA_COMPRESSION = $CompressionType)"
                                            $Server.Query($query, $db.Name)
                                        } else {
                                            $($index.PhysicalPartitions | Where-Object { $_.PartitionNumber -eq $P.PartitionNumber }).DataCompression = $CompressionType
                                            $index.Rebuild()
                                        }
                                    } catch {
                                        Stop-Function -Message "Compression failed for $instance - $db - table $($obj.Schema).$($obj.Name) - index $($index.Name) - partition $($p.PartitionNumber)" -Target $db -ErrorRecord $_ -Continue
                                    }
                                    [pscustomobject]@{
                                        ComputerName                  = $server.ComputerName
                                        InstanceName                  = $server.ServiceName
                                        SqlInstance                   = $server.DomainInstanceName
                                        Database                      = $db.Name
                                        Schema                        = $obj.Schema
                                        TableName                     = $obj.Name
                                        IndexName                     = $index.Name
                                        Partition                     = $p.PartitionNumber
                                        IndexID                       = $index.Id
                                        IndexType                     = $index.IndexType
                                        PercentScan                   = $null
                                        PercentUpdate                 = $null
                                        RowEstimatePercentOriginal    = $null
                                        PageEstimatePercentOriginal   = $null
                                        CompressionTypeRecommendation = $CompressionType.ToUpper()
                                        SizeCurrent                   = $null
                                        SizeRequested                 = $null
                                        PercentCompression            = $null
                                        AlreadyProcessed              = "True"
                                    }
                                }
                            }
                        }
                        foreach ($index in $($server.Databases[$($db.name)].Views | Where-Object { $_.Indexes }).Indexes) {
                            foreach ($p in $($index.PhysicalPartitions | Where-Object { $_.DataCompression -ne $CompressionType })) {
                                Write-Message -Level Verbose -Message "Compressing $($index.IndexType) $($index.Name) Partition $($p.PartitionNumber)"
                                try {
                                    ## There is a bug in SMO where setting compression to None at the index level doesn't work
                                    ## Once this UserVoice item is fixed the workaround can be removed
                                    ## https://feedback.azure.com/forums/908035-sql-server/suggestions/34080112-data-compression-smo-bug
                                    if ($CompressionType -eq "None") {
                                        $query = "ALTER INDEX [$($index.Name)] ON $($index.Parent) REBUILD PARTITION = ALL WITH (DATA_COMPRESSION = $CompressionType)"
                                        $query
                                        $Server.Query($query, $db.Name)
                                    } else {
                                        $($index.PhysicalPartitions | Where-Object { $_.PartitionNumber -eq $P.PartitionNumber }).DataCompression = $CompressionType
                                        $index.Rebuild()
                                    }
                                } catch {
                                    Stop-Function -Message "Compression failed for $instance - $db - table $($obj.Schema).$($obj.Name) - index $($index.Name) - partition $($p.PartitionNumber)" -Target $db -ErrorRecord $_ -Continue
                                }
                                [pscustomobject]@{
                                    ComputerName                  = $server.ComputerName
                                    InstanceName                  = $server.ServiceName
                                    SqlInstance                   = $server.DomainInstanceName
                                    Database                      = $db.Name
                                    Schema                        = $obj.Schema
                                    TableName                     = $obj.Name
                                    IndexName                     = $index.Name
                                    Partition                     = $p.PartitionNumber
                                    IndexID                       = $index.Id
                                    IndexType                     = $index.IndexType
                                    PercentScan                   = $null
                                    PercentUpdate                 = $null
                                    RowEstimatePercentOriginal    = $null
                                    PageEstimatePercentOriginal   = $null
                                    CompressionTypeRecommendation = $CompressionType.ToUpper()
                                    SizeCurrent                   = $null
                                    SizeRequested                 = $null
                                    PercentCompression            = $null
                                    AlreadyProcessed              = "True"
                                }
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
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCA0vpxG33jWWtsm
# RIdEfxoOjaWtAbOXEPRkJFs4PZc+lqCCHVkwggUaMIIEAqADAgECAhADBbuGIbCh
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
# BgorBgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCCBk7NM5wdskXc50kIHaVr6aHQ6
# cwbeKQXI9t4ztqYSqjANBgkqhkiG9w0BAQEFAASCAQC8qSioMW8VEQpZrA5U03uD
# AWNERtkjcUHZiq7kpRpgZYjxFkyE4j4p/wM6q6hlEo8f+BOLqi1IMM3AfBHgQxIK
# MnoCrZAYRWFtjtF+hms7XKLTbUk+V2Sy8gzAQwazk3Rnb2TEiM00uffD2OYDlkIx
# 7VWd1Pfs59VZ/iKMppeUKPmhkXjcoioG3pa0/fUc59uJQtICTXctrz1oEWdh5hcy
# JVeSl3Yf+jKjc3NE7WUGTX7O/s1RIEgNSta76xVZZ3JWuAXzWZTCXsAjFTCTD4em
# PdrGuWwu6gr3vJiwNyrCQBtW3tDEvJtFIh/3qthFi3cMnDt4B0lOMlAuB0/MouVt
# oYIDIDCCAxwGCSqGSIb3DQEJBjGCAw0wggMJAgEBMHcwYzELMAkGA1UEBhMCVVMx
# FzAVBgNVBAoTDkRpZ2lDZXJ0LCBJbmMuMTswOQYDVQQDEzJEaWdpQ2VydCBUcnVz
# dGVkIEc0IFJTQTQwOTYgU0hBMjU2IFRpbWVTdGFtcGluZyBDQQIQDE1pckuU+jwq
# Sj0pB4A9WjANBglghkgBZQMEAgEFAKBpMBgGCSqGSIb3DQEJAzELBgkqhkiG9w0B
# BwEwHAYJKoZIhvcNAQkFMQ8XDTIyMTExNzA4NTczMFowLwYJKoZIhvcNAQkEMSIE
# IIct59Gm17iMyt0bsFcM1/F1QJGdtW3cJGRuyjHE1X+wMA0GCSqGSIb3DQEBAQUA
# BIICAGsfgLXZlYD0VSSEJupkWUX2Dvw1YHe5uByZJzmj1OTiZee3WEcXzDohjxBo
# 29jHGlyQ64Em7ND3+eu4deIUjBLzmTYvVSdOfvmJ6wT24mpuAhbh+hb5Q7KBvNp9
# 6aNSgibX2rSSG8ZxflOdNvZEv783IIJGklioAr+xceGSFWqfi9KcrksDwLiCLyOd
# YOpdAuMqwVvv3YzQEj//BjLVXfrscUSANThrLCc+EJ//V5e1yHzuIXqtDWdOktBy
# ll28ky9+5FRJ6/EXzayk5g2rcENUbd1nibHut0mmBuYuFk05mEBDYyn5aU+qvthH
# hiN8Dk89vNOq4SNuQY14k5cB00JDtxAJ30brcXBFoawCgpYm2ihDJKD8yu1nOADd
# vLQv5y72PUEC8fIEwxptWpC3xQaN7O2xLECWKGaxuvACpJq9KQQVA1MVhq2rghUv
# aiFJUkIl+/4PON2P0fKav33nUwDLB9zzIobijsawTeLdBycfJBCd6EkLmFC2bNox
# MAlJ39epBbrXRp44alvv3VCQnzjkZhmviWRNTN6AFTrdXwQZiaPmMhQw2zTI1OMc
# eDTu6dVTZiGbA56clX9DADcd9WCEIxWTbx+OsoehLnrDLKQ9zEoly90YHJUIkVFF
# cz8QrW+b6oMnRsxNvLu9hrpBC9leq2Qg0H1mdKkc+MH4kKPq
# SIG # End signature block
