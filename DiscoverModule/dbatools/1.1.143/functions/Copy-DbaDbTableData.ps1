function Copy-DbaDbTableData {
    <#
    .SYNOPSIS
        Copies data between SQL Server tables.

    .DESCRIPTION
        Copies data between SQL Server tables using SQL Bulk Copy.
        The same can be achieved also using Invoke-DbaQuery and Write-DbaDbTableData but it will buffer the contents of that table in memory of the machine running the commands.
        This function prevents that by streaming a copy of the data in the most speedy and least resource-intensive way.

    .PARAMETER SqlInstance
        Source SQL Server.You must have sysadmin access and server version must be SQL Server version 2000 or greater.

    .PARAMETER SqlCredential
        Login to the source instance using alternative credentials. Accepts PowerShell credentials (Get-Credential).

        Windows Authentication, SQL Server Authentication, Active Directory - Password, and Active Directory - Integrated are all supported.

        For MFA support, please use Connect-DbaInstance.

    .PARAMETER Destination
        Destination Sql Server. You must have sysadmin access and server version must be SQL Server version 2000 or greater.

    .PARAMETER DestinationSqlCredential
        Login to the destination instance using alternative credentials. Accepts PowerShell credentials (Get-Credential).

        Windows Authentication, SQL Server Authentication, Active Directory - Password, and Active Directory - Integrated are all supported.

        For MFA support, please use Connect-DbaInstance.

    .PARAMETER Database
        The database to copy the table from.

    .PARAMETER DestinationDatabase
        The database to copy the table to. If not specified, it is assumed to be the same of Database

    .PARAMETER Table
        Specify a table to use as a source. You can specify a 2 or 3 part name.
        If the object has special characters please wrap them in square brackets.

        Note: Cannot specify a view if a table value is provided

    .PARAMETER View
        Specify a view to use as a source. You can specify a 2 or 3 part name (see examples).
        If the object has special characters please wrap them in square brackets.

        Note: Cannot specify a table if a view value is provided

    .PARAMETER DestinationTable
        The table you want to use as destination. If not specified, it is assumed to be the same of Table

    .PARAMETER Query
        Define a query to use as a source. Note: 3 or 4 part object names may be used (see examples)
        Ensure to select all required columns.
        Calculated Columns or columns with default values may be excluded.

        Note: The workflow in the command requires that a valid -Table or -View parameter value be specified.

    .PARAMETER AutoCreateTable
        Creates the destination table if it does not already exist, based off of the "Export..." script of the source table.

    .PARAMETER BatchSize
        The BatchSize for the import defaults to 50000.

    .PARAMETER NotifyAfter
        Sets the option to show the notification after so many rows of import. The default is 5000 rows.

    .PARAMETER NoTableLock
        If this switch is enabled, a table lock (TABLOCK) will not be placed on the destination table. By default, this operation will lock the destination table while running.

    .PARAMETER CheckConstraints
        If this switch is enabled, the SqlBulkCopy option to process check constraints will be enabled.

        Per Microsoft "Check constraints while data is being inserted. By default, constraints are not checked."

    .PARAMETER FireTriggers
        If this switch is enabled, the SqlBulkCopy option to fire insert triggers will be enabled.

        Per Microsoft "When specified, cause the server to fire the insert triggers for the rows being inserted into the Database."

    .PARAMETER KeepIdentity
        If this switch is enabled, the SqlBulkCopy option to preserve source identity values will be enabled.

        Per Microsoft "Preserve source identity values. When not specified, identity values are assigned by the destination."

    .PARAMETER KeepNulls
        If this switch is enabled, the SqlBulkCopy option to preserve NULL values will be enabled.

        Per Microsoft "Preserve null values in the destination table regardless of the settings for default values. When not specified, null values are replaced by default values where applicable."

    .PARAMETER Truncate
        If this switch is enabled, the destination table will be truncated after prompting for confirmation.

    .PARAMETER BulkCopyTimeout
        Value in seconds for the BulkCopy operations timeout. The default is 5000 seconds.

    .PARAMETER CommandTimeout
        Gets or sets the wait time (in seconds) before terminating the attempt to execute the reader and bulk copy operation. The default is 0 seconds (no timeout).

    .PARAMETER InputObject
        Enables piping of Table objects from Get-DbaDbTable

    .PARAMETER WhatIf
        If this switch is enabled, no actions are performed but informational messages will be displayed that explain what would happen if the command were to run.

    .PARAMETER Confirm
        If this switch is enabled, you will be prompted for confirmation before executing any operations that change state.

    .PARAMETER EnableException
        By default, when something goes wrong we try to catch it, interpret it and give you a friendly warning message.
        This avoids overwhelming you with "sea of red" exceptions, but is inconvenient because it basically disables advanced scripting.
        Using this switch turns this "nice by default" feature off and enables you to catch exceptions with your own try/catch.

    .NOTES
        Tags: Table, Data
        Author: Simone Bizzotto (@niphlod)

        Website: https://dbatools.io
        Copyright: (c) 2018 by dbatools, licensed under MIT
        License: MIT https://opensource.org/licenses/MIT

    .LINK
        https://dbatools.io/Copy-DbaDbTableData

    .EXAMPLE
        PS C:\> Copy-DbaDbTableData -SqlInstance sql1 -Destination sql2 -Database dbatools_from -Table dbo.test_table

        Copies all the data from table dbo.test_table (2-part name) in database dbatools_from on sql1 to table test_table in database dbatools_from on sql2.

    .EXAMPLE
        PS C:\> Copy-DbaDbTableData -SqlInstance sql1 -Destination sql2 -Database dbatools_from -DestinationDatabase dbatools_dest -Table [Schema].[test table]

        Copies all the data from table [Schema].[test table] (2-part name) in database dbatools_from on sql1 to table [Schema].[test table] in database dbatools_dest on sql2

    .EXAMPLE
        PS C:\> Get-DbaDbTable -SqlInstance sql1 -Database tempdb -Table tb1, tb2 | Copy-DbaDbTableData -DestinationTable tb3

        Copies all data from tables tb1 and tb2 in tempdb on sql1 to tb3 in tempdb on sql1

    .EXAMPLE
        PS C:\> Get-DbaDbTable -SqlInstance sql1 -Database tempdb -Table tb1, tb2 | Copy-DbaDbTableData -Destination sql2

        Copies data from tb1 and tb2 in tempdb on sql1 to the same table in tempdb on sql2

    .EXAMPLE
        PS C:\> Copy-DbaDbTableData -SqlInstance sql1 -Destination sql2 -Database dbatools_from -Table test_table -KeepIdentity -Truncate

        Copies all the data in table test_table from sql1 to sql2, using the database dbatools_from, keeping identity columns and truncating the destination

    .EXAMPLE
        PS C:\> $params = @{
        >> SqlInstance = 'sql1'
        >> Destination = 'sql2'
        >> Database = 'dbatools_from'
        >> DestinationDatabase = 'dbatools_dest'
        >> Table = '[Schema].[Table]'
        >> DestinationTable = '[dbo].[Table.Copy]'
        >> KeepIdentity = $true
        >> KeepNulls = $true
        >> Truncate = $true
        >> BatchSize = 10000
        >> }
        >>
        PS C:\> Copy-DbaDbTableData @params

        Copies all the data from table [Schema].[Table] (2-part name) in database dbatools_from on sql1 to table [dbo].[Table.Copy] in database dbatools_dest on sql2
        Keeps identity columns and Nulls, truncates the destination and processes in BatchSize of 10000.

    .EXAMPLE
        PS C:\> $params = @{
        >> SqlInstance = 'server1'
        >> Destination = 'server1'
        >> Database = 'AdventureWorks2017'
        >> DestinationDatabase = 'AdventureWorks2017'
        >> DestinationTable = '[AdventureWorks2017].[Person].[EmailPromotion]'
        >> BatchSize = 10000
        >> Query = "SELECT * FROM [OtherDb].[Person].[Person] where EmailPromotion = 1"
        >> }
        >>
        PS C:\> Copy-DbaDbTableData @params

        Copies data returned from the query on server1 into the AdventureWorks2017 on server1, using a 4-part name for the DestinationTableTable parameter. Copy is processed in BatchSize of 10000 rows.

        See the Query param documentation for more details.

    .EXAMPLE
       Copy-DbaDbTableData -SqlInstance sql1 -Database tempdb -View [tempdb].[dbo].[vw1] -DestinationTable [SampleDb].[SampleSchema].[SampleTable] -AutoCreateTable

       Copies all data from [tempdb].[dbo].[vw1] (3-part name) view on instance sql1 to an auto-created table [SampleDb].[SampleSchema].[SampleTable] on instance sql1
    #>
    [CmdletBinding(DefaultParameterSetName = "Default", SupportsShouldProcess)]
    param (
        [DbaInstanceParameter]$SqlInstance,
        [PSCredential]$SqlCredential,
        [DbaInstanceParameter[]]$Destination,
        [PSCredential]$DestinationSqlCredential,
        [string]$Database,
        [string]$DestinationDatabase,
        [string[]]$Table,
        [string[]]$View, # Copy-DbaDbTableData and Copy-DbaDbViewData are consolidated to reduce maintenance cost, so this param is specific to calls of Copy-DbaDbViewData
        [string]$Query,
        [switch]$AutoCreateTable,
        [int]$BatchSize = 50000,
        [int]$NotifyAfter = 5000,
        [string]$DestinationTable,
        [switch]$NoTableLock,
        [switch]$CheckConstraints,
        [switch]$FireTriggers,
        [switch]$KeepIdentity,
        [switch]$KeepNulls,
        [switch]$Truncate,
        [int]$BulkCopyTimeout = 5000,
        [int]$CommandTimeout = 0,
        [Parameter(ValueFromPipeline)]
        [Microsoft.SqlServer.Management.Smo.TableViewBase[]]$InputObject,
        [switch]$EnableException
    )

    begin {

        $bulkCopyOptions = 0
        $options = "TableLock", "CheckConstraints", "FireTriggers", "KeepIdentity", "KeepNulls", "Default"

        foreach ($option in $options) {
            $optionValue = Get-Variable $option -ValueOnly -ErrorAction SilentlyContinue
            if ($option -eq "TableLock" -and (!$NoTableLock)) {
                $optionValue = $true
            }
            if ($optionValue -eq $true) {
                $bulkCopyOptions += $([Microsoft.Data.SqlClient.SqlBulkCopyOptions]::$option).value__
            }
        }
    }

    process {
        if ((Test-Bound -Not -ParameterName Table, View, SqlInstance) -and (Test-Bound -Not -ParameterName InputObject)) {
            Stop-Function -Message "You must pipe in a table or specify SqlInstance, Database and [View|Table]."
            return
        }

        # determine if -Table or -View was used
        $SourceObject = $Table
        if ((Test-Bound -ParameterName View) -and (Test-Bound -ParameterName Table)) {
            Stop-Function -Message "Only one of [View|Table] may be specified."
            return
        } elseif ( Test-Bound -ParameterName View ) {
            $SourceObject = $View
        }

        if ($SqlInstance) {
            if ((Test-Bound -Not -ParameterName Database)) {
                Stop-Function -Message "Database is required when passing a SqlInstance" -Target $SourceObject
                return
            }

            if ((Test-Bound -Not -ParameterName Destination, DestinationDatabase, DestinationTable)) {
                Stop-Function -Message "Cannot copy $SourceObject into itself. One of the parameters Destination (Server), DestinationDatabase, or DestinationTable must be specified " -Target $SourceObject
                return
            }

            try {
                # Ensuring that the default db connection is to the passed in $Database instead of the master db. This way callers don't have to remember to do 3 part queries.
                $server = Connect-DbaInstance -SqlInstance $SqlInstance -SqlCredential $SqlCredential -Database $Database
            } catch {
                Stop-Function -Message "Failure" -Category ConnectionError -ErrorRecord $_ -Target $SqlInstance
                return
            }

            try {
                foreach ($sourceDataObject in $SourceObject) {
                    $dbObject = $null

                    if ( Test-Bound -ParameterName View ) {
                        $dbObject = Get-DbaDbView -SqlInstance $server -View $sourceDataObject -Database $Database -EnableException -Verbose:$false
                    } else {
                        $dbObject = Get-DbaDbTable -SqlInstance $server -Table $sourceDataObject -Database $Database -EnableException -Verbose:$false
                    }

                    if ($dbObject.Count -eq 1) {
                        $InputObject += $dbObject
                    } else {
                        Stop-Function -Message "The object $sourceDataObject matches $($dbObject.Count) objects. Unable to determine which object to copy" -Continue
                    }
                }
            } catch {
                Stop-Function -Message "Unable to determine source : $SourceObject"
                return
            }
        }

        foreach ($sqlObject in $InputObject) {
            $Database = $sqlObject.Parent.Name
            $server = $sqlObject.Parent.Parent

            if ((Test-Bound -Not -ParameterName DestinationTable)) {
                $DestinationTable = '[' + $sqlObject.Schema + '].[' + $sqlObject.Name + ']'
            }

            $newTableParts = Get-ObjectNameParts -ObjectName $DestinationTable
            #using FQTN to determine database name
            if ($newTableParts.Database) {
                $DestinationDatabase = $newTableParts.Database
            } elseif ((Test-Bound -Not -ParameterName DestinationDatabase)) {
                $DestinationDatabase = $Database
            }

            if (-not $Destination) {
                $Destination = $server
            }

            foreach ($destinstance in $Destination) {
                try {
                    $destServer = Connect-DbaInstance -SqlInstance $destinstance -SqlCredential $DestinationSqlCredential
                } catch {
                    Stop-Function -Message "Failure" -Category ConnectionError -ErrorRecord $_ -Target $destinstance -Continue
                }

                if ($DestinationDatabase -notin $destServer.Databases.Name) {
                    Stop-Function -Message "Database $DestinationDatabase doesn't exist on $destServer"
                    return
                }

                $desttable = Get-DbaDbTable -SqlInstance $destServer -Table $DestinationTable -Database $DestinationDatabase -Verbose:$false | Select-Object -First 1
                if (-not $desttable -and $AutoCreateTable) {
                    try {
                        $tablescript = $null
                        $schemaNameToReplace = $null
                        $tableNameToReplace = $null
                        if ( Test-Bound -ParameterName View ) {
                            #select view into tempdb to generate script
                            $tempTableName = "$($sqlObject.Name)_table"
                            $createquery = "SELECT * INTO tempdb..$tempTableName FROM [$($sqlObject.Schema)].[$($sqlObject.Name)] WHERE 1=2"
                            Invoke-DbaQuery -SqlInstance $server -Database $Database -Query $createquery -EnableException
                            #refreshing table list to make sure get-dbadbtable will find the new table
                            $server.Databases['tempdb'].Tables.Refresh($true)
                            $tempTable = Get-DbaDbTable -SqlInstance $server -Database tempdb -Table $tempTableName
                            # need these for generating the script of the table and then replacing the schema and name
                            $schemaNameToReplace = $tempTable.Schema
                            $tableNameToReplace = $tempTable.Name
                            $tablescript = $tempTable | Export-DbaScript -Passthru | Out-String
                            # cleanup
                            Invoke-DbaQuery -SqlInstance $server -Database $Database -Query "DROP TABLE tempdb..$tempTableName" -EnableException
                        } else {
                            $tablescript = $sqlObject | Export-DbaScript -Passthru | Out-String
                            $schemaNameToReplace = $sqlObject.Schema
                            $tableNameToReplace = $sqlObject.Name
                        }

                        #replacing table name
                        if ($newTableParts.Name) {
                            $rX = "(CREATE|ALTER)( TABLE \[$([regex]::Escape($schemaNameToReplace))\]\.\[)$([regex]::Escape($tableNameToReplace))(\])"
                            $tablescript = $tablescript -replace $rX, "`${1}`${2}$($newTableParts.Name)`${3}"
                        }
                        #replacing table schema
                        if ($newTableParts.Schema) {
                            $rX = "(CREATE|ALTER)( TABLE \[)$([regex]::Escape($schemaNameToReplace))(\]\.\[$([regex]::Escape($newTableParts.Name))\])"
                            $tablescript = $tablescript -replace $rX, "`${1}`${2}$($newTableParts.Schema)`${3}"
                        }

                        if ($PSCmdlet.ShouldProcess($destServer, "Creating new table: $DestinationTable")) {
                            Write-Message -Message "New table script: $tablescript" -Level VeryVerbose
                            Invoke-DbaQuery -SqlInstance $destServer -Database $DestinationDatabase -Query "$tablescript" -EnableException # add some string assurance there
                            #table list was updated, let's grab a fresh one
                            $destServer.Databases[$DestinationDatabase].Tables.Refresh()
                            $desttable = Get-DbaDbTable -SqlInstance $destServer -Table $DestinationTable -Database $DestinationDatabase -Verbose:$false
                            Write-Message -Message "New table created: $desttable" -Level Verbose
                        }
                    } catch {
                        Stop-Function -Message "Unable to determine destination table: $DestinationTable" -ErrorRecord $_
                        return
                    }
                }
                if (-not $desttable) {
                    Stop-Function -Message "Table $DestinationTable cannot be found in $DestinationDatabase. Use -AutoCreateTable to automatically create the table on the destination." -Continue
                }

                $connstring = $destServer.ConnectionContext.ConnectionString

                if ($server.DatabaseEngineType -eq "SqlAzureDatabase") {
                    $fqtnfrom = "$sqlObject"
                } else {
                    $fqtnfrom = "$($server.Databases[$Database]).$sqlObject"
                }

                if ($destServer.DatabaseEngineType -eq "SqlAzureDatabase") {
                    $fqtndest = "$desttable"
                } else {
                    $fqtndest = "$($destServer.Databases[$DestinationDatabase]).$desttable"
                }

                if ($fqtndest -eq $fqtnfrom -and $server.Name -eq $destServer.Name -and (Test-Bound -ParameterName Query -Not)) {
                    Stop-Function -Message "Cannot copy $fqtnfrom on $($server.Name) into $fqtndest on ($destServer.Name). Source and Destination must be different " -Target $Table
                    return
                }


                if (Test-Bound -ParameterName Query -Not) {
                    $Query = "SELECT * FROM $fqtnfrom"
                    $sourceLabel = $fqtnfrom
                } else {
                    $sourceLabel = "Query"
                }
                try {
                    if ($Truncate -eq $true) {
                        if ($Pscmdlet.ShouldProcess($destServer, "Truncating table $fqtndest")) {
                            Invoke-DbaQuery -SqlInstance $destServer -Database $DestinationDatabase -Query "TRUNCATE TABLE $fqtndest" -EnableException
                        }
                    }
                    if ($Pscmdlet.ShouldProcess($server, "Copy data from $sourceLabel")) {
                        $cmd = $server.ConnectionContext.SqlConnectionObject.CreateCommand()
                        $cmd.CommandTimeout = $CommandTimeout
                        $cmd.CommandText = $Query
                        if ($server.ConnectionContext.IsOpen -eq $false) {
                            $server.ConnectionContext.SqlConnectionObject.Open()
                        }
                        $bulkCopy = New-Object Microsoft.Data.SqlClient.SqlBulkCopy("$connstring;Database=$DestinationDatabase", $bulkCopyOptions)
                        $bulkCopy.DestinationTableName = $fqtndest
                        $bulkCopy.EnableStreaming = $true
                        $bulkCopy.BatchSize = $BatchSize
                        $bulkCopy.NotifyAfter = $NotifyAfter
                        $bulkCopy.BulkCopyTimeout = $BulkCopyTimeout

                        # The legacy bulk copy library uses a 4 byte integer to track the RowsCopied, so the only option is to use
                        # integer wrap so that copy operations of row counts greater than [int32]::MaxValue will report accurate numbers.
                        # See https://github.com/dataplat/dbatools/issues/6927 for more details
                        $script:prevRowsCopied = [int64]0
                        $script:totalRowsCopied = [int64]0

                        $elapsed = [System.Diagnostics.Stopwatch]::StartNew()
                        # Add RowCount output
                        $bulkCopy.Add_SqlRowsCopied( {

                                $script:totalRowsCopied += (Get-AdjustedTotalRowsCopied -ReportedRowsCopied $args[1].RowsCopied -PreviousRowsCopied $script:prevRowsCopied).NewRowCountAdded

                                $tstamp = $(Get-Date -format 'yyyyMMddHHmmss')
                                Write-Message -Level Verbose -Message "[$tstamp] The bulk copy library reported RowsCopied = $($args[1].RowsCopied). The previous RowsCopied = $($script:prevRowsCopied). The adjusted total rows copied = $($script:totalRowsCopied)"

                                $RowsPerSec = [math]::Round($script:totalRowsCopied / $elapsed.ElapsedMilliseconds * 1000.0, 1)
                                Write-Progress -Id 1 -Activity "Inserting rows" -Status ([System.String]::Format("{0} rows ({1} rows/sec)", $script:totalRowsCopied, $RowsPerSec))

                                # save the previous count of rows copied to be used on the next event notification
                                $script:prevRowsCopied = $args[1].RowsCopied
                            })
                    }

                    if ($Pscmdlet.ShouldProcess($destServer, "Writing rows to $fqtndest")) {
                        $reader = $cmd.ExecuteReader()
                        $bulkCopy.WriteToServer($reader)
                        $finalRowCountReported = Get-BulkRowsCopiedCount $bulkCopy

                        $script:totalRowsCopied += (Get-AdjustedTotalRowsCopied -ReportedRowsCopied $finalRowCountReported -PreviousRowsCopied $script:prevRowsCopied).NewRowCountAdded

                        $RowsTotal = $script:totalRowsCopied
                        $TotalTime = [math]::Round($elapsed.Elapsed.TotalSeconds, 1)
                        Write-Message -Level Verbose -Message "$RowsTotal rows inserted in $TotalTime sec"
                        if ($RowsTotal -gt 0) {
                            Write-Progress -Id 1 -Activity "Inserting rows" -Status "Complete" -Completed
                        }

                        $server.ConnectionContext.SqlConnectionObject.Close()
                        $bulkCopy.Close()
                        $bulkCopy.Dispose()
                        $reader.Close()

                        [pscustomobject]@{
                            SourceInstance        = $server.Name
                            SourceDatabase        = $Database
                            SourceDatabaseID      = $sqlObject.Parent.ID
                            SourceSchema          = $sqlObject.Schema
                            SourceTable           = $sqlObject.Name
                            DestinationInstance   = $destServer.Name
                            DestinationDatabase   = $DestinationDatabase
                            DestinationDatabaseID = $desttable.Parent.ID
                            DestinationSchema     = $desttable.Schema
                            DestinationTable      = $desttable.Name
                            RowsCopied            = $RowsTotal
                            Elapsed               = [prettytimespan]$elapsed.Elapsed
                        }
                    }
                } catch {
                    Stop-Function -Message "Something went wrong" -ErrorRecord $_ -Target $server -continue
                }
            }
        }
    }
}
# SIG # Begin signature block
# MIIjYAYJKoZIhvcNAQcCoIIjUTCCI00CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCCJYJp6Ug51r6gz
# F67RPVIuPqCIFXIAra/7DxEWGNkO9KCCHVkwggUaMIIEAqADAgECAhADBbuGIbCh
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
# BgorBgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCBRpQBP9MY3L60w0yWMaSx/Bf6N
# cYcDsXTvzUD7BRX8jTANBgkqhkiG9w0BAQEFAASCAQB5F9AncGmrh1MtpH7m7C3r
# v49xpseEbABik8qFnaexbYMzYnlvsDgCF3IyQT2kr78ga+OT7wbnEJU35gJ1ZKYv
# 46gUzWeYFHoFXdarm0PZpAU+JG68wMRiexdFm4wXFptRCIW388kmbyhkX54nKWiw
# WBvd4slBk0HwJziZJV29J1KxMRKgwGdw+2nctG6IRFTpG+APhDvjRFfJgPc3KWvo
# u7WXg1/kOxqfxuNp+bVceLLqZ9d294QJiH2tOYcrGMKkInCJf6BmeKDHeFsy+wAm
# KiNZXITeXzB1oNDaxImg6jOjzobw3+iF7Vu/iNT1yyxzHMTwoEdfsxYtcrKBaHLu
# oYIDIDCCAxwGCSqGSIb3DQEJBjGCAw0wggMJAgEBMHcwYzELMAkGA1UEBhMCVVMx
# FzAVBgNVBAoTDkRpZ2lDZXJ0LCBJbmMuMTswOQYDVQQDEzJEaWdpQ2VydCBUcnVz
# dGVkIEc0IFJTQTQwOTYgU0hBMjU2IFRpbWVTdGFtcGluZyBDQQIQDE1pckuU+jwq
# Sj0pB4A9WjANBglghkgBZQMEAgEFAKBpMBgGCSqGSIb3DQEJAzELBgkqhkiG9w0B
# BwEwHAYJKoZIhvcNAQkFMQ8XDTIyMTExNzA4NTUxOVowLwYJKoZIhvcNAQkEMSIE
# IKh/UBU/J1RyI70nOT8iS7myopF7vbT4gz7aNoMKnfoLMA0GCSqGSIb3DQEBAQUA
# BIICAJwnKc3E0Tglp7ZDukOOM3FD4GXbdXKiWArh0TbKfcaVVPH39IWM+mMZ8LJ4
# WkvxeTbkpPvwaYgkKv1ufWZz4BrViqzkIluED8w2jnF5/m2q0B9NOY6yIVjR4pCy
# KPZp/V6WTgUMSuFm1j8pBbmtltfbeFLVrZv/b1NMIPttyHkKhscXGnXuCpf00gVn
# 0iZ1l/+iVL6PfYMS4MAaWw4y+okGrdLJrmSzstCPXq+XlpLRQyyXfSho5XnsRkla
# wFUUgYvMH0gqSzwYIgVYkfC3jbTrU2a0S2+5Jj3W4YUPd5Wk8EmR7NWKNBrrFh29
# YfawEc7ty+KuD/6mUvQ8OG9b6PtFXSUeKVizgDd2/UBXUfC9ODp5HRsZZ8YwFjI8
# j4+cnkRYo3PxVjxMjVkB95szb6K5Bgk7TL4h80HZ8Ii9H0pfQJNxO2K32Lo4MWP7
# Fv5Cu7QWSy88KS46qf2/jy8VVOwD4AkU/UTqL2HBhx370ln8ECSbbFbX37Q5ceof
# akKfUe08fa5xrs+CbDOqrOVPot8CubP+b6rh2IeFTtZXliV4hPb2p/cQWm0GG9xm
# ScDxxH/3dEOf88zcU8lb0iQ/r8pvoXpM95QhDDTjyuP03H11Gir57znWbOrP09Ff
# NGv+BByGAi5Y2fWvA5BW1OfI2WGPOjLaXDcAF3VXureQmW6G
# SIG # End signature block
