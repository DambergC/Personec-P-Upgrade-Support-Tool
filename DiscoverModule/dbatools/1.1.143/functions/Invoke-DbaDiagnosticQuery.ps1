function Invoke-DbaDiagnosticQuery {
    <#
    .SYNOPSIS
        Invoke-DbaDiagnosticQuery runs the scripts provided by Glenn Berry's DMV scripts on specified servers

    .DESCRIPTION
        This is the main function of the Sql Server Diagnostic Queries related functions in dbatools.
        The diagnostic queries are developed and maintained by Glenn Berry and they can be found here along with a lot of documentation:
        https://glennsqlperformance.com/resources/

        The most recent version of the diagnostic queries are included in the dbatools module.
        But it is possible to download a newer set or a specific version to an alternative location and parse and run those scripts.
        It will run all or a selection of those scripts on one or multiple servers and return the result as a PowerShell Object

    .PARAMETER SqlInstance
        The target SQL Server instance or instances. Can be either a string or SMO server

    .PARAMETER SqlCredential
        Login to the target instance using alternative credentials. Accepts PowerShell credentials (Get-Credential).

        Windows Authentication, SQL Server Authentication, Active Directory - Password, and Active Directory - Integrated are all supported.

        For MFA support, please use Connect-DbaInstance.

    .PARAMETER Path
        Alternate path for the diagnostic scripts

    .PARAMETER Database
        The database(s) to process. If unspecified, all databases will be processed

    .PARAMETER ExcludeDatabase
        The database(s) to exclude

    .PARAMETER ExcludeQuery
        The Queries to exclude

    .PARAMETER UseSelectionHelper
        Provides a grid view with all the queries to choose from and will run the selection made by the user on the Sql Server instance specified.

    .PARAMETER QueryName
        Only run specific query

    .PARAMETER InstanceOnly
        Run only instance level queries

    .PARAMETER DatabaseSpecific
        Run only database level queries

    .PARAMETER ExcludeQueryTextColumn
        Use this switch to exclude the [Complete Query Text] column from relevant queries

    .PARAMETER ExcludePlanColumn
        Use this switch to exclude the [Query Plan] column from relevant queries

    .PARAMETER NoColumnParsing
        Does not parse the [Complete Query Text] and [Query Plan] columns and disregards the ExcludeQueryTextColumn and NoColumnParsing switches

    .PARAMETER EnableException
        By default, when something goes wrong we try to catch it, interpret it and give you a friendly warning message.
        This avoids overwhelming you with "sea of red" exceptions, but is inconvenient because it basically disables advanced scripting.
        Using this switch turns this "nice by default" feature off and enables you to catch exceptions with your own try/catch.

    .PARAMETER Confirm
        Prompts to confirm certain actions

    .PARAMETER WhatIf
        Shows what would happen if the command would execute, but does not actually perform the command

    .PARAMETER OutputPath
        Directory to parsed diagnostics queries to. This will split them based on server, database name, and query.

    .PARAMETER ExportQueries
        Use this switch to export the diagnostic queries to sql files. Instead of running the queries, the server will be evaluated to find the appropriate queries to run based on SQL Version.
        These sql files will then be created in the OutputDirectory

    .NOTES
        Tags: Community, GlennBerry
        Author: Andre Kamman (@AndreKamman), andrekamman.com

        Website: https://dbatools.io
        Copyright: (c) 2018 by dbatools, licensed under MIT
        License: MIT https://opensource.org/licenses/MIT

    .LINK
        https://dbatools.io/Invoke-DbaDiagnosticQuery

    .EXAMPLE
        PS C:\>Invoke-DbaDiagnosticQuery -SqlInstance sql2016

        Run the selection made by the user on the Sql Server instance specified.

    .EXAMPLE
        PS C:\>Invoke-DbaDiagnosticQuery -SqlInstance sql2016 -UseSelectionHelper | Export-DbaDiagnosticQuery -Path C:\temp\gboutput

        Provides a grid view with all the queries to choose from and will run the selection made by the user on the SQL Server instance specified.
        Then it will export the results to Export-DbaDiagnosticQuery.

    .EXAMPLE
        PS C:\> Invoke-DbaDiagnosticQuery -SqlInstance localhost -ExportQueries -OutputPath "C:\temp\DiagnosticQueries"

        Export All Queries to Disk

    .EXAMPLE
        PS C:\> Invoke-DbaDiagnosticQuery -SqlInstance localhost -DatabaseSpecific -ExportQueries -OutputPath "C:\temp\DiagnosticQueries"

        Export Database Specific Queries for all User Dbs

    .EXAMPLE
        PS C:\> Invoke-DbaDiagnosticQuery -SqlInstance localhost -DatabaseSpecific -DatabaseName 'tempdb' -ExportQueries -OutputPath "C:\temp\DiagnosticQueries"

        Export Database Specific Queries For One Target Database

    .EXAMPLE
        PS C:\> Invoke-DbaDiagnosticQuery -SqlInstance localhost -DatabaseSpecific -DatabaseName 'tempdb' -ExportQueries -OutputPath "C:\temp\DiagnosticQueries" -QueryName 'Database-scoped Configurations'

        Export Database Specific Queries For One Target Database and One Specific Query

    .EXAMPLE
        PS C:\> Invoke-DbaDiagnosticQuery -SqlInstance localhost -UseSelectionHelper

        Choose Queries To Export

    .EXAMPLE
        PS C:\> [PSObject[]]$results = Invoke-DbaDiagnosticQuery -SqlInstance localhost -WhatIf

        Parse the appropriate diagnostic queries by connecting to server, and instead of running them, return as [PSCustomObject[]] to work with further

    .EXAMPLE
        PS C:\> $results = Invoke-DbaDiagnosticQuery -SqlInstance Sql2017 -DatabaseSpecific -QueryName 'Database-scoped Configurations' -DatabaseName TestStuff

        Run diagnostic queries targeted at specific database, and only run database level queries against this database.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([pscustomobject[]])]
    param (
        [parameter(Mandatory, ValueFromPipeline, Position = 0)]
        [DbaInstanceParameter[]]$SqlInstance,
        [Alias('DatabaseName')]
        [object[]]$Database,
        [object[]]$ExcludeDatabase,
        [object[]]$ExcludeQuery,
        [Alias('Credential')]
        [PSCredential]$SqlCredential,
        [System.IO.FileInfo]$Path,
        [string[]]$QueryName,
        [switch]$UseSelectionHelper,
        [switch]$InstanceOnly,
        [switch]$DatabaseSpecific,
        [Switch]$ExcludeQueryTextColumn,
        [Switch]$ExcludePlanColumn,
        [Switch]$NoColumnParsing,
        [string]$OutputPath,
        [switch]$ExportQueries,
        [switch]
        [switch]$EnableException
    )
    begin {
        $ProgressId = Get-Random

        function Invoke-DiagnosticQuerySelectionHelper {
            [CmdletBinding()]
            param (
                [parameter(Mandatory)]
                $ParsedScript
            )

            $ParsedScript | Select-Object QueryNr, QueryName, DBSpecific, Description | Out-GridView -Title "Diagnostic Query Overview" -OutputMode Multiple | Sort-Object QueryNr | Select-Object -ExpandProperty QueryName

        }

        Write-Message -Level Verbose -Message "Interpreting DMV Script Collections"

        if (!$Path) {
            $Path = Join-Path -Path "$script:PSModuleRoot" -ChildPath "bin\diagnosticquery"
        }

        $scriptversions = @()
        $scriptfiles = Get-ChildItem -Path "$Path\SQLServerDiagnosticQueries_*.sql"

        if (!$scriptfiles) {
            Write-Message -Level Warning -Message "Diagnostic scripts not found in $Path. Using the ones within the module."

            $Path = Join-Path -Path $base -ChildPath "\bin\diagnosticquery"

            $scriptfiles = Get-ChildItem "$base\bin\diagnosticquery\SQLServerDiagnosticQueries_*.sql"
            if (!$scriptfiles) {
                Stop-Function -Message "Unable to download scripts, do you have an internet connection? $_" -ErrorRecord $_
                return
            }
        }

        [int[]]$filesort = $null

        foreach ($file in $scriptfiles) {
            $filesort += $file.BaseName.Split("_")[2]
        }

        $currentdate = $filesort | Sort-Object -Descending | Select-Object -First 1

        foreach ($file in $scriptfiles) {
            if ($file.BaseName.Split("_")[2] -eq $currentdate) {
                $parsedscript = Invoke-DbaDiagnosticQueryScriptParser -filename $file.fullname -ExcludeQueryTextColumn:$ExcludeQueryTextColumn -ExcludePlanColumn:$ExcludePlanColumn -NoColumnParsing:$NoColumnParsing

                $newscript = [pscustomobject]@{
                    Version = $file.Basename.Split("_")[1]
                    Script  = $parsedscript
                }
                $scriptversions += $newscript
            }
        }
    }
    process {
        if (Test-FunctionInterrupt) { return }

        foreach ($instance in $SqlInstance) {
            $counter = 0
            try {
                $server = Connect-DbaInstance -SqlInstance $instance -SqlCredential $SqlCredential
            } catch {
                Stop-Function -Message "Failure" -Category ConnectionError -ErrorRecord $_ -Target $instance -Continue
            }

            Write-Message -Level Verbose -Message "Collecting diagnostic query data from server: $instance"

            if ($server.VersionMinor -eq 50) {
                $version = "2008R2"
            } else {
                $version = switch ($server.VersionMajor) {
                    9 { "2005" }
                    10 { "2008" }
                    11 { "2012" }
                    12 { "2014" }
                    13 { "2016" }
                    14 { "2017" }
                    15 { "2019" }
                }
            }

            if ($version -eq "2016" -and $server.VersionMinor -gt 5026 ) {
                $version = "2016SP2"
            }

            if ($server.DatabaseEngineType -eq "SqlAzureDatabase") {
                $version = "AzureSQLDatabase"
            }

            if (!$instanceOnly) {
                if (-not $Database) {
                    $databases = (Get-DbaDatabase -SqlInstance $server -ExcludeSystem -ExcludeDatabase $ExcludeDatabase).Name
                } else {
                    $databases = (Get-DbaDatabase -SqlInstance $server -ExcludeSystem -Database $Database -ExcludeDatabase $ExcludeDatabase).Name
                }
            }

            $parsedscript = $scriptversions | Where-Object -Property Version -eq $version | Select-Object -ExpandProperty Script

            if ($null -eq $first) { $first = $true }
            if ($UseSelectionHelper -and $first) {
                $QueryName = Invoke-DiagnosticQuerySelectionHelper $parsedscript
                $first = $false
                if ($QueryName.Count -eq 0) {
                    Write-Message -Level Output -Message "No query selected through SelectionHelper, halting script execution"
                    return
                }
            }

            if ($QueryName.Count -eq 0) {
                $QueryName = $parsedscript | Select-Object -ExpandProperty QueryName
            }

            if ($ExcludeQuery) {
                $QueryName = Compare-Object -ReferenceObject $QueryName -DifferenceObject $ExcludeQuery | Where-Object SideIndicator -eq "<=" | Select-Object -ExpandProperty InputObject
            }

            #since some database level queries can take longer (such as fragmentation) calculate progress with database specific queries * count of databases to run against into context
            $CountOfDatabases = ($databases).Count

            if ($QueryName.Count -ne 0) {
                #if running all queries, then calculate total to run by instance queries count + (db specific count * databases to run each against)
                $countDBSpecific = @($parsedscript | Where-Object { $_.QueryName -in $QueryName -and $_.DBSpecific -eq $true }).Count
                $countInstanceSpecific = @($parsedscript | Where-Object { $_.QueryName -in $QueryName -and $_.DBSpecific -eq $false }).Count
            } else {
                #if narrowing queries to database specific, calculate total to process based on instance queries count + (db specific count * databases to run each against)
                $countDBSpecific = @($parsedscript | Where-Object DBSpecific).Count
                $countInstanceSpecific = @($parsedscript | Where-Object DBSpecific -eq $false).Count

            }
            if (!$instanceonly -and !$DatabaseSpecific -and !$QueryName) {
                $scriptcount = $countInstanceSpecific + ($countDBSpecific * $CountOfDatabases )
            } elseif ($instanceOnly) {
                $scriptcount = $countInstanceSpecific
            } elseif ($DatabaseSpecific) {
                $scriptcount = $countDBSpecific * $CountOfDatabases
            } elseif ($QueryName.Count -ne 0) {
                $scriptcount = $countInstanceSpecific + ($countDBSpecific * $CountOfDatabases )


            }

            foreach ($scriptpart in $parsedscript) {
                # ensure results are null with each part, otherwise duplicated information may be returned
                $result = $null
                if (($QueryName.Count -ne 0) -and ($QueryName -notcontains $scriptpart.QueryName)) { continue }
                if (!$scriptpart.DBSpecific -and !$DatabaseSpecific) {
                    if ($ExportQueries) {
                        $null = New-Item -Path $OutputPath -ItemType Directory -Force
                        $FileName = Remove-InvalidFileNameChars ('{0}.sql' -f $Scriptpart.QueryName)
                        $FullName = Join-Path $OutputPath $FileName
                        Write-Message -Level Verbose -Message  "Creating file: $FullName"
                        $scriptPart.Text | Out-File -FilePath $FullName -Encoding UTF8 -force
                        continue
                    }

                    if ($PSCmdlet.ShouldProcess($instance, $scriptpart.QueryName)) {

                        if (-not $EnableException) {
                            $Counter++
                            Write-Progress -Id $ProgressId -ParentId 0 -Activity "Collecting diagnostic query data from $instance" -Status "Processing $counter of $scriptcount" -CurrentOperation $scriptpart.QueryName -PercentComplete (($counter / $scriptcount) * 100)
                        }

                        try {
                            $result = $server.Query($scriptpart.Text)
                            Write-Message -Level Verbose -Message "Processed $($scriptpart.QueryName) on $instance"
                            if (-not $result) {
                                [pscustomobject]@{
                                    ComputerName     = $server.ComputerName
                                    InstanceName     = $server.ServiceName
                                    SqlInstance      = $server.DomainInstanceName
                                    Number           = $scriptpart.QueryNr
                                    Name             = $scriptpart.QueryName
                                    Description      = $scriptpart.Description
                                    DatabaseSpecific = $scriptpart.DBSpecific
                                    Database         = $null
                                    Notes            = "Empty Result for this Query"
                                    Result           = $null
                                }
                                Write-Message -Level Verbose -Message ("Empty result for Query {0} - {1} - {2}" -f $scriptpart.QueryNr, $scriptpart.QueryName, $scriptpart.Description)
                            }
                        } catch {
                            Write-Message -Level Verbose -Message ('Some error has occurred on Server: {0} - Script: {1}, result unavailable' -f $instance, $scriptpart.QueryName) -Target $instance -ErrorRecord $_
                        }
                        if ($result) {
                            [pscustomobject]@{
                                ComputerName     = $server.ComputerName
                                InstanceName     = $server.ServiceName
                                SqlInstance      = $server.DomainInstanceName
                                Number           = $scriptpart.QueryNr
                                Name             = $scriptpart.QueryName
                                Description      = $scriptpart.Description
                                DatabaseSpecific = $scriptpart.DBSpecific
                                Database         = $null
                                Notes            = $null
                                #Result           = Select-DefaultView -InputObject $result -Property *
                                #Not using Select-DefaultView because excluding the fields below doesn't seem to work
                                Result           = $result | Select-Object * -ExcludeProperty 'Item', 'RowError', 'RowState', 'Table', 'ItemArray', 'HasErrors'
                            }

                        }
                    } else {
                        # if running WhatIf, then return the queries that would be run as an object, not just whatif output

                        [pscustomobject]@{
                            ComputerName     = $server.ComputerName
                            InstanceName     = $server.ServiceName
                            SqlInstance      = $server.DomainInstanceName
                            Number           = $scriptpart.QueryNr
                            Name             = $scriptpart.QueryName
                            Description      = $scriptpart.Description
                            DatabaseSpecific = $scriptpart.DBSpecific
                            Database         = $null
                            Notes            = "WhatIf - Bypassed Execution"
                            Result           = $null
                        }
                    }

                } elseif ($scriptpart.DBSpecific -and !$instanceOnly) {

                    foreach ($currentdb in $databases) {
                        if ($ExportQueries) {
                            $null = New-Item -Path $OutputPath -ItemType Directory -Force
                            $FileName = Remove-InvalidFileNameChars ('{0}-{1}-{2}.sql' -f $server.DomainInstanceName, $currentDb, $Scriptpart.QueryName)
                            $FullName = Join-Path $OutputPath $FileName
                            Write-Message -Level Verbose -Message  "Creating file: $FullName"
                            $scriptPart.Text | Out-File -FilePath $FullName -encoding UTF8 -force
                            continue
                        }


                        if ($PSCmdlet.ShouldProcess(('{0} ({1})' -f $instance, $currentDb), $scriptpart.QueryName)) {

                            if (-not $EnableException) {
                                $Counter++
                                Write-Progress -Id $ProgressId -ParentId 0 -Activity "Collecting diagnostic query data from $($currentDb) on $instance" -Status ('Processing {0} of {1}' -f $counter, $scriptcount) -CurrentOperation $scriptpart.QueryName -PercentComplete (($Counter / $scriptcount) * 100)
                            }

                            Write-Message -Level Verbose -Message "Collecting diagnostic query data from $($currentDb) for $($scriptpart.QueryName) on $instance"
                            try {
                                $result = $server.Query($scriptpart.Text, $currentDb)
                                if (-not $result) {
                                    [pscustomobject]@{
                                        ComputerName     = $server.ComputerName
                                        InstanceName     = $server.ServiceName
                                        SqlInstance      = $server.DomainInstanceName
                                        Number           = $scriptpart.QueryNr
                                        Name             = $scriptpart.QueryName
                                        Description      = $scriptpart.Description
                                        DatabaseSpecific = $scriptpart.DBSpecific
                                        Database         = $currentdb
                                        Notes            = "Empty Result for this Query"
                                        Result           = $null
                                    }
                                    Write-Message -Level Verbose -Message ("Empty result for Query {0} - {1} - {2}" -f $scriptpart.QueryNr, $scriptpart.QueryName, $scriptpart.Description) -Target $scriptpart -ErrorRecord $_
                                }
                            } catch {
                                Write-Message -Level Verbose -Message ('Some error has occurred on Server: {0} - Script: {1} - Database: {2}, result will not be saved' -f $instance, $scriptpart.QueryName, $currentDb) -Target $currentdb -ErrorRecord $_
                            }

                            if ($result) {
                                [pscustomobject]@{
                                    ComputerName     = $server.ComputerName
                                    InstanceName     = $server.ServiceName
                                    SqlInstance      = $server.DomainInstanceName
                                    Number           = $scriptpart.QueryNr
                                    Name             = $scriptpart.QueryName
                                    Description      = $scriptpart.Description
                                    DatabaseSpecific = $scriptpart.DBSpecific
                                    Database         = $currentDb
                                    Notes            = $null
                                    #Result           = Select-DefaultView -InputObject $result -Property *
                                    #Not using Select-DefaultView because excluding the fields below doesn't seem to work
                                    Result           = $result | Select-Object * -ExcludeProperty 'Item', 'RowError', 'RowState', 'Table', 'ItemArray', 'HasErrors'
                                }
                            }
                        } else {
                            # if running WhatIf, then return the queries that would be run as an object, not just whatif output

                            [pscustomobject]@{
                                ComputerName     = $server.ComputerName
                                InstanceName     = $server.ServiceName
                                SqlInstance      = $server.DomainInstanceName
                                Number           = $scriptpart.QueryNr
                                Name             = $scriptpart.QueryName
                                Description      = $scriptpart.Description
                                DatabaseSpecific = $scriptpart.DBSpecific
                                Database         = $null
                                Notes            = "WhatIf - Bypassed Execution"
                                Result           = $null
                            }
                        }
                    }
                }
            }
        }
    }
    end {
        Write-Progress -Id $ProgressId -Activity 'Invoke-DbaDiagnosticQuery' -Completed
    }
}
# SIG # Begin signature block
# MIIjYAYJKoZIhvcNAQcCoIIjUTCCI00CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCB3cPDQeeW3qp9f
# gHeh0om96Yash/mCdel3npx8ZD4wlqCCHVkwggUaMIIEAqADAgECAhADBbuGIbCh
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
# BgorBgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCDcJqEJZZbf5IDe1AGNK6N4W6J5
# cr/9ZGXZ+xIa5UnQvjANBgkqhkiG9w0BAQEFAASCAQA9tI7S1rWGGXHmGN/nNcC/
# p4xu9i13Qc2PD4zeCdM2ih3IwHz4V2f0Hwlr4/MIWdy07q4ILLPrfe9zyWdoNFi8
# o5M9fGkDI5olKUNTa/o6V9vIffDiWV+274xvyk/7vN0od5g1PBW2o8H4pwrG8Bk5
# IVUxn0dsv4Idq+3O9qV2zlTM56vhYwX1xt4LNtYCWNkTegaRJpX3LjSDRi7wSvkg
# ZwJC/b3RK8GTcKN2ZMHyjA4omNj93oKsF3qcyhl3KFCAo8yIdtNphyyi13xJHKgK
# nBdUeNv8M2q3rA9bX1Yc0wF4QWAJJojS1q9dsaeKvL6ri8rWgyG1Lay8oXx52VVa
# oYIDIDCCAxwGCSqGSIb3DQEJBjGCAw0wggMJAgEBMHcwYzELMAkGA1UEBhMCVVMx
# FzAVBgNVBAoTDkRpZ2lDZXJ0LCBJbmMuMTswOQYDVQQDEzJEaWdpQ2VydCBUcnVz
# dGVkIEc0IFJTQTQwOTYgU0hBMjU2IFRpbWVTdGFtcGluZyBDQQIQDE1pckuU+jwq
# Sj0pB4A9WjANBglghkgBZQMEAgEFAKBpMBgGCSqGSIb3DQEJAzELBgkqhkiG9w0B
# BwEwHAYJKoZIhvcNAQkFMQ8XDTIyMTExNzA4NTY0NVowLwYJKoZIhvcNAQkEMSIE
# IMo7tb/jABlv62oGriFpXoMaTuJv3dHBmZ7lzf6C6svLMA0GCSqGSIb3DQEBAQUA
# BIICAEjBxwnMPOgm0ydmuE/Ip6x1xi+Ex6A5HPV/uVdM2sbHBnclCLDD9yaoVzyy
# dvzlSCeQJWq9x+CtCxoOHHz1FaWDj/i2wMgopTp3/URdrh6jfu3WdGAyk1D+Uw9F
# aWqCwmxJIldNr03ru0DPOk4JNVkQ+hg01rn8Y6fE7/F9DBIkz7p/HadtHp0Fe7eV
# ZV3hDyPCAXFPVodjXKG9YqJ3s65sxaR5bE+BvZWRFmUd81w8h2Fc9x4HLJS9Hr+n
# W+juJXrNZyYd0gTYczRmAPVdErAgN3PO8OXa5F36aNdWL+7sXLmtiM2tDxAY29b6
# og/uxdTJ8UBEE6XADWDSw188gIzrfOh7mv+V00abYgPMs9FYGHAR7pv+TVgqMRul
# JVkuxtdldPxVyG7rYFLodxib9PDDMduX0aywjPpn9qZuRYzV624Ts8B0V5NKOG0x
# X5Xs7w2W2op2JbWHQmlTzmmmWIYhlW5edVi2nEp2D9kjDXgXxefU7QqKP6uwZzoR
# lpF+iED33nGhYh7oEnKNiawwcSR5AumIWk7xGeXQpKAptOggCG9h0EWpspr6PFtH
# 25aIp/lKnoo++6pAqGLJDfw8hV/aspG2uWPKAe86NpWaA6hw98ewvNbSa1dEVaQJ
# +LPkhrG1shboiziv/g5SPaXU65RsiSUo7eBJu2BTfgFi2lj7
# SIG # End signature block
