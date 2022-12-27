function Import-DbaCsv {
    <#
    .SYNOPSIS
        Efficiently imports very large (and small) CSV files into SQL Server.

    .DESCRIPTION
        Import-DbaCsv takes advantage of .NET's super fast SqlBulkCopy class to import CSV files into SQL Server.

        The entire import is performed within a transaction, so if a failure occurs or the script is aborted, no changes will persist.

        If the table or view specified does not exist and -AutoCreateTable, it will be automatically created using slow and inefficient but accommodating data types.

        This importer supports fields spanning multiple lines. The only restriction is that they must be quoted, otherwise it would not be possible to distinguish between malformed data and multi-line values.

    .PARAMETER Path
        Specifies path to the CSV file(s) to be imported. Multiple files may be imported at once.

    .PARAMETER NoHeaderRow
        By default, the first row is used to determine column names for the data being imported.

        Use this switch if the first row contains data and not column names.

    .PARAMETER Delimiter
        Specifies the delimiter used in the imported file(s). If no delimiter is specified, comma is assumed.

        Valid delimiters are '`t`, '|', ';',' ' and ',' (tab, pipe, semicolon, space, and comma).

    .PARAMETER SingleColumn
        Specifies that the file contains a single column of data. Otherwise, the delimiter check bombs.

    .PARAMETER SqlInstance
        The SQL Server Instance to import data into.

    .PARAMETER SqlCredential
        Login to the target instance using alternative credentials. Accepts PowerShell credentials (Get-Credential).

        Windows Authentication, SQL Server Authentication, Active Directory - Password, and Active Directory - Integrated are all supported.

        For MFA support, please use Connect-DbaInstance.

    .PARAMETER Database
        Specifies the name of the database the CSV will be imported into. Options for this this parameter are  auto-populated from the server.

    .PARAMETER Schema
        Specifies the schema in which the SQL table or view where CSV will be imported into resides. Default is dbo.

        If a schema does not currently exist, it will be created, after a prompt to confirm this. Authorization will be set to dbo by default.

        This parameter overrides -UseFileNameForSchema.

    .PARAMETER Table
        Specifies the SQL table or view where CSV will be imported into.

        If a table name is not specified, the table name will be automatically determined from the filename.

        If the table specified does not exist and -AutoCreateTable, it will be automatically created using slow and inefficient but accommodating data types.

        If the automatically generated table datatypes do not work for you, please create the table prior to import.

        If you want to import specific columns from a CSV, create a view with corresponding columns.

    .PARAMETER Column
        Import only specific columns. To remap column names, use the ColumnMap.

    .PARAMETER ColumnMap
        By default, the bulk copy tries to automap columns. When it doesn't work as desired, this parameter will help. Check out the examples for more information.

    .PARAMETER KeepOrdinalOrder
        By default, the importer will attempt to map exact-match columns names from the source document to the target table. Using this parameter will keep the ordinal order instead.

    .PARAMETER AutoCreateTable
        Creates a table if it does not already exist. The table will be created with sub-optimal data types such as nvarchar(max)

    .PARAMETER Truncate
        If this switch is enabled, the destination table will be truncated prior to import.

    .PARAMETER NotifyAfter
        Specifies the import row count interval for reporting progress. A notification will be shown after each group of this many rows has been imported.

    .PARAMETER BatchSize
        Specifies the batch size for the import. Defaults to 50000.

    .PARAMETER UseFileNameForSchema
        If this switch is enabled, the script will try to find the schema name in the input file by looking for a period (.) in the file name.

        If used with the -Table parameter you may still specify the target table name. If -Table is not used the file name after the first period will
        be used for the table name.

        For example test.data.csv will import the csv contents to a table in the test schema.

        If it finds one it will use the file name up to the first period as the schema. If there is no period in the filename it will default to dbo.

        If a schema does not currently exist, it will be created, after a prompt to confirm this. Authorization will be set to dbo by default.

        This behaviour will be overridden if the -Schema parameter is specified.

    .PARAMETER TableLock
        If this switch is enabled, the SqlBulkCopy option to acquire a table lock will be used.

        Per Microsoft "Obtain a bulk update lock for the duration of the bulk copy operation. When not
        specified, row locks are used."

    .PARAMETER CheckConstraints
        If this switch is enabled, the SqlBulkCopy option to check constraints will be used.

        Per Microsoft "Check constraints while data is being inserted. By default, constraints are not checked."

    .PARAMETER FireTriggers
        If this switch is enabled, the SqlBulkCopy option to allow insert triggers to be executed will be used.

        Per Microsoft "When specified, cause the server to fire the insert triggers for the rows being inserted into the database."

    .PARAMETER KeepIdentity
        If this switch is enabled, the SqlBulkCopy option to keep identity values from the source will be used.

        Per Microsoft "Preserve source identity values. When not specified, identity values are assigned by the destination."

    .PARAMETER KeepNulls
        If this switch is enabled, the SqlBulkCopy option to keep NULL values in the table will be used.

        Per Microsoft "Preserve null values in the destination table regardless of the settings for default values. When not specified, null values are replaced by default values where applicable."

    .PARAMETER NoProgress
        The progress bar is pretty but can slow down imports. Use this parameter to quietly import.

    .PARAMETER Quote
        Defines the default quote character wrapping every field.
        Default: double-quotes

    .PARAMETER Escape
        Defines the default escape character letting insert quotation characters inside a quoted field.

        The escape character can be the same as the quote character.
        Default: double-quotes

    .PARAMETER Comment
        Defines the default comment character indicating that a line is commented out.
        Default: hashtag

    .PARAMETER TrimmingOption
        Determines which values should be trimmed. Default is "None". Options are All, None, UnquotedOnly and QuotedOnly.

    .PARAMETER BufferSize
        Defines the default buffer size. The default BufferSize is 4096.

    .PARAMETER ParseErrorAction
        By default, the parse error action throws an exception and ends the import.

        You can also choose AdvanceToNextLine which basically ignores parse errors.

    .PARAMETER Encoding
        By default, set to UTF-8.

        The encoding of the file.

    .PARAMETER NullValue
        The value which denotes a DbNull-value.

    .PARAMETER MaxQuotedFieldLength
        The maximum length (in bytes) for any quoted field.

    .PARAMETER SkipEmptyLine
        Skip empty lines.

    .PARAMETER SupportsMultiline
        Indicates if the importer should support multiline fields.

    .PARAMETER UseColumnDefault
        Use the column default values if the field is not in the record.

    .PARAMETER NoTransaction
        Do not use a transaction when performing the import.

    .PARAMETER WhatIf
        Shows what would happen if the command were to run. No actions are actually performed.

    .PARAMETER Confirm
        Prompts you for confirmation before executing any changing operations within the command.

    .PARAMETER EnableException
        By default, when something goes wrong we try to catch it, interpret it and give you a friendly warning message.
        This avoids overwhelming you with "sea of red" exceptions, but is inconvenient because it basically disables advanced scripting.
        Using this switch turns this "nice by default" feature off and enables you to catch exceptions with your own try/catch.

    .NOTES
        Tags: Import, Data, Utility
        Author: Chrissy LeMaire (@cl), netnerds.net

        Website: https://dbatools.io
        Copyright: (c) 2018 by dbatools, licensed under MIT
        License: MIT https://opensource.org/licenses/MIT

    .LINK
        https://dbatools.io/Import-DbaCsv

    .EXAMPLE
        PS C:\> Import-DbaCsv -Path C:\temp\housing.csv -SqlInstance sql001 -Database markets

        Imports the entire comma-delimited housing.csv to the SQL "markets" database on a SQL Server named sql001, using the first row as column names.

        Since a table name was not specified, the table name is automatically determined from filename as "housing".

    .EXAMPLE
        PS C:\> Import-DbaCsv -Path .\housing.csv -SqlInstance sql001 -Database markets -Table housing -Delimiter "`t" -NoHeaderRow

        Imports the entire tab-delimited housing.csv, including the first row which is not used for colum names, to the SQL markets database, into the housing table, on a SQL Server named sql001.

    .EXAMPLE
        PS C:\> Import-DbaCsv -Path C:\temp\huge.txt -SqlInstance sqlcluster -Database locations -Table latitudes -Delimiter "|"

        Imports the entire pipe-delimited huge.txt to the locations database, into the latitudes table on a SQL Server named sqlcluster.

    .EXAMPLE
        PS C:\> Import-DbaCsv -Path c:\temp\SingleColumn.csv -SqlInstance sql001 -Database markets -Table TempTable -SingleColumn

        Imports the single column CSV into TempTable

    .EXAMPLE
        PS C:\> Get-ChildItem -Path \\FileServer\csvs | Import-DbaCsv -SqlInstance sql001, sql002 -Database tempdb -AutoCreateTable

        Imports every CSV in the \\FileServer\csvs path into both sql001 and sql002's tempdb database. Each CSV will be imported into an automatically determined table name.

    .EXAMPLE
        PS C:\> Get-ChildItem -Path \\FileServer\csvs | Import-DbaCsv -SqlInstance sql001, sql002 -Database tempdb -AutoCreateTable -WhatIf

        Shows what would happen if the command were to be executed

    .EXAMPLE
        PS C:\> Import-DbaCsv -Path c:\temp\dataset.csv -SqlInstance sql2016 -Database tempdb -Column Name, Address, Mobile

        Import only Name, Address and Mobile even if other columns exist. All other columns are ignored and therefore null or default values.

    .EXAMPLE
        PS C:\> Import-DbaCsv -Path C:\temp\schema.data.csv -SqlInstance sql2016 -database tempdb -UseFileNameForSchema

        Will import the contents of C:\temp\schema.data.csv to table 'data' in schema 'schema'.

    .EXAMPLE
        PS C:\> Import-DbaCsv -Path C:\temp\schema.data.csv -SqlInstance sql2016 -database tempdb -UseFileNameForSchema -Table testtable

        Will import the contents of C:\temp\schema.data.csv to table 'testtable' in schema 'schema'.

    .EXAMPLE
        PS C:\> $columns = @{
        >> Text = 'FirstName'
        >> Number = 'PhoneNumber'
        >> }
        PS C:\> Import-DbaCsv -Path c:\temp\supersmall.csv -SqlInstance sql2016 -Database tempdb -ColumnMap $columns

        The CSV column 'Text' is inserted into SQL column 'FirstName' and CSV column Number is inserted into the SQL Column 'PhoneNumber'. All other columns are ignored and therefore null or default values.
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Low')]
    param (
        [parameter(ValueFromPipeline)]
        [ValidateNotNullOrEmpty()]
        [Alias("Csv", "FullPath")]
        [object[]]$Path,
        [Parameter(Mandatory)]
        [DbaInstanceParameter[]]$SqlInstance,
        [pscredential]$SqlCredential,
        [Parameter(Mandatory)]
        [string]$Database,
        [string]$Table,
        [string]$Schema,
        [switch]$Truncate,
        [char]$Delimiter = ",",
        [switch]$SingleColumn,
        [int]$BatchSize = 50000,
        [int]$NotifyAfter = 50000,
        [switch]$TableLock,
        [switch]$CheckConstraints,
        [switch]$FireTriggers,
        [switch]$KeepIdentity,
        [switch]$KeepNulls,
        [string[]]$Column,
        [hashtable]$ColumnMap,
        [switch]$KeepOrdinalOrder,
        [switch]$AutoCreateTable,
        [switch]$NoProgress,
        [switch]$NoHeaderRow,
        [switch]$UseFileNameForSchema,
        [char]$Quote = '"',
        [char]$Escape = '"',
        [char]$Comment = '#',
        [ValidateSet('All', 'None', 'UnquotedOnly', 'QuotedOnly')]
        [string]$TrimmingOption = "None",
        [int]$BufferSize = 4096,
        [ValidateSet('AdvanceToNextLine', 'ThrowException')]
        [string]$ParseErrorAction = 'ThrowException',
        [ValidateSet('ASCII', 'BigEndianUnicode', 'Byte', 'String', 'Unicode', 'UTF7', 'UTF8', 'Unknown')]
        [string]$Encoding = 'UTF8',
        [string]$NullValue,
        [int]$MaxQuotedFieldLength,
        [switch]$SkipEmptyLine,
        [switch]$SupportsMultiline,
        [switch]$UseColumnDefault,
        [switch]$NoTransaction,
        [switch]$EnableException
    )
    begin {
        $FirstRowHeader = $NoHeaderRow -eq $false
        $scriptelapsed = [System.Diagnostics.Stopwatch]::StartNew()

        if ($PSBoundParameters.UseFileNameForSchema -and $PSBoundParameters.Schema) {
            Write-Message -Level Warning -Message "Schema and UseFileNameForSchema parameters both specified. UseSchemaInFileName will be ignored."
        }

        try {
            # SilentContinue isn't enough
            Add-Type -Path "$script:PSModuleRoot\bin\csv\LumenWorks.Framework.IO.dll" -ErrorAction Stop
        } catch {
            $null = 1
        }

        function New-SqlTable {
            <#
                .SYNOPSIS
                    Creates new Table using existing SqlCommand.

                    SQL datatypes based on best guess of column data within the -ColumnText parameter.
                    Columns parameter determine column names.

                .EXAMPLE
                    New-SqlTable -Path $Path -Delimiter $Delimiter -Columns $columns -ColumnText $columntext -SqlConn $sqlconn -Transaction $transaction

                .OUTPUTS
                    Creates new table
            #>
            [Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSUseShouldProcessForStateChangingFunctions", "")]
            param (
                [Parameter(Mandatory)]
                [string]$Path,
                [Parameter(Mandatory)]
                [string]$Delimiter,
                [Parameter(Mandatory)]
                [bool]$FirstRowHeader,
                [Microsoft.Data.SqlClient.SqlConnection]$sqlconn,
                [Microsoft.Data.SqlClient.SqlTransaction]$transaction
            )
            $reader = New-Object LumenWorks.Framework.IO.Csv.CsvReader(
                (New-Object System.IO.StreamReader($Path, [System.Text.Encoding]::$Encoding)),
                $FirstRowHeader,
                $Delimiter,
                $Quote,
                $Escape,
                $Comment,
                [LumenWorks.Framework.IO.Csv.ValueTrimmingOptions]::$TrimmingOption,
                $BufferSize,
                $NullValue
            )
            $columns = $reader.GetFieldHeaders()
            $reader.Close()
            $reader.Dispose()

            # Get SQL datatypes by best guess on first data row
            $sqldatatypes = @();

            foreach ($column in $Columns) {
                $sqldatatypes += "[$column] nvarchar(MAX)"
            }

            $sql = "BEGIN CREATE TABLE [$schema].[$table] ($($sqldatatypes -join ' NULL,')) END"
            $sqlcmd = New-Object Microsoft.Data.SqlClient.SqlCommand($sql, $sqlconn, $transaction)

            try {
                $null = $sqlcmd.ExecuteNonQuery()
            } catch {
                $errormessage = $_.Exception.Message.ToString()
                Stop-Function -Continue -Message "Failed to execute $sql. `nDid you specify the proper delimiter? `n$errormessage"
            }

            Write-Message -Level Verbose -Message "Successfully created table $schema.$table with the following column definitions:`n $($sqldatatypes -join "`n ")"
            # Write-Message -Level Warning -Message "All columns are created using a best guess, and use their maximum datatype."
            Write-Message -Level Verbose -Message "This is inefficient but allows the script to import without issues."
            Write-Message -Level Verbose -Message "Consider creating the table first using best practices if the data will be used in production."
        }

        Write-Message -Level Verbose -Message "Started at $(Get-Date)"
    }
    process {
        foreach ($filename in $Path) {
            if (-not $PSBoundParameters.ColumnMap) {
                $ColumnMap = $null
            }

            if ($filename.FullName) {
                $filename = $filename.FullName
            }

            if (-not (Test-Path -Path $filename)) {
                Stop-Function -Continue -Message "$filename cannot be found"
            }

            $file = (Resolve-Path -Path $filename).ProviderPath

            # Does the second line contain the specified delimiter?
            try {
                $firstlines = Get-Content -Path $file -TotalCount 2 -ErrorAction Stop
            } catch {
                Stop-Function -Continue -Message "Failure reading $file" -ErrorRecord $_
            }
            if (-not $SingleColumn) {
                if ($firstlines -notmatch $Delimiter) {
                    Stop-Function -Message "Delimiter ($Delimiter) not found in first few rows of $file. If this is a single column import, please specify -SingleColumn"
                    return
                }
            }

            # Automatically generate Table name if not specified
            if (-not $PSBoundParameters.Table) {
                $filename = [IO.Path]::GetFileNameWithoutExtension($file)

                if ($filename.IndexOf('.') -ne -1) { $periodFound = $true }

                if ($UseFileNameForSchema -and $periodFound -and -not $PSBoundParameters.Schema) {
                    $table = $filename.Remove(0, $filename.IndexOf('.') + 1)
                    Write-Message -Level Verbose -Message "Table name not specified, using $table from file name"
                } else {
                    $table = [IO.Path]::GetFileNameWithoutExtension($file)
                    Write-Message -Level Verbose -Message "Table name not specified, using $table"
                }
            }

            # Use dbo as schema name if not specified in parms, or as first string before a period in filename
            if (-not ($PSBoundParameters.Schema)) {
                if ($UseFileNameForSchema) {
                    $filename = [IO.Path]::GetFileNameWithoutExtension($file)
                    if ($filename.IndexOf('.') -eq -1) {
                        $schema = "dbo"
                        Write-Message -Level Verbose -Message "Schema not specified, and not found in file name, using dbo"
                    } else {
                        $schema = $filename.SubString(0, $filename.IndexOf('.'))
                        Write-Message -Level Verbose -Message "Schema detected in filename, using $schema"
                    }
                } else {
                    $schema = 'dbo'
                    Write-Message -Level Verbose -Message "Schema not specified, using dbo"
                }
            }

            foreach ($instance in $SqlInstance) {
                $elapsed = [System.Diagnostics.Stopwatch]::StartNew()
                # Open Connection to SQL Server
                try {
                    $server = Connect-DbaInstance -SqlInstance $instance -SqlCredential $SqlCredential -Database $Database -StatementTimeout 0 -MinimumVersion 9
                    $sqlconn = $server.ConnectionContext.SqlConnectionObject
                    if ($sqlconn.State -ne 'Open') {
                        $sqlconn.Open()
                    }
                } catch {
                    Stop-Function -Message "Failure" -Category ConnectionError -ErrorRecord $_ -Target $instance -Continue
                }

                if (-not $NoTransaction) {
                    if ($PSCmdlet.ShouldProcess($instance, "Starting transaction in $Database")) {
                        # Everything will be contained within 1 transaction, even creating a new table if required
                        # and truncating the table, if specified.
                        $transaction = $sqlconn.BeginTransaction()
                    }
                }

                # Ensure Schema exists
                $sql = "select count(*) from [$Database].sys.schemas where name='$schema'"
                $sqlcmd = New-Object Microsoft.Data.SqlClient.SqlCommand($sql, $sqlconn, $transaction)

                # If Schema doesn't exist create it
                # Defaulting to dbo.
                if (($sqlcmd.ExecuteScalar()) -eq 0) {
                    if (-not $AutoCreateTable) {
                        Stop-Function -Continue -Message "Schema $Schema does not exist and AutoCreateTable was not specified"
                    }
                    $sql = "CREATE SCHEMA [$schema] AUTHORIZATION dbo"
                    if ($PSCmdlet.ShouldProcess($instance, "Creating schema $schema")) {
                        $sqlcmd = New-Object Microsoft.Data.SqlClient.SqlCommand($sql, $sqlconn, $transaction)
                        try {
                            $null = $sqlcmd.ExecuteNonQuery()
                        } catch {
                            Stop-Function -Continue -Message "Could not create $schema" -ErrorRecord $_
                        }
                    }
                }

                # Ensure table or view exists
                $sql = "select count(*) from [$Database].sys.tables where name = '$table' and schema_id=schema_id('$schema')"
                $sqlcmd = New-Object Microsoft.Data.SqlClient.SqlCommand($sql, $sqlconn, $transaction)

                $sql2 = "select count(*) from [$Database].sys.views where name = '$table' and schema_id=schema_id('$schema')"
                $sqlcmd2 = New-Object Microsoft.Data.SqlClient.SqlCommand($sql2, $sqlconn, $transaction)

                # Create the table if required. Remember, this will occur within a transaction, so if the script fails, the
                # new table will no longer exist.
                if (($sqlcmd.ExecuteScalar()) -eq 0 -and ($sqlcmd2.ExecuteScalar()) -eq 0) {
                    if (-not $AutoCreateTable) {
                        Stop-Function -Continue -Message "Table or view $table does not exist and AutoCreateTable was not specified"
                    }
                    Write-Message -Level Verbose -Message "Table does not exist"
                    if ($PSCmdlet.ShouldProcess($instance, "Creating table $table")) {
                        try {
                            New-SqlTable -Path $file -Delimiter $Delimiter -FirstRowHeader $FirstRowHeader -SqlConn $sqlconn -Transaction $transaction
                        } catch {
                            Stop-Function -Continue -Message "Failure" -ErrorRecord $_
                        }
                    }
                } else {
                    Write-Message -Level Verbose -Message "Table exists"
                }

                # Truncate if specified. Remember, this will occur within a transaction, so if the script fails, the
                # truncate will not be committed.
                if ($Truncate) {
                    $sql = "TRUNCATE TABLE [$schema].[$table]"
                    if ($PSCmdlet.ShouldProcess($instance, "Performing TRUNCATE TABLE [$schema].[$table] on $Database")) {
                        $sqlcmd = New-Object Microsoft.Data.SqlClient.SqlCommand($sql, $sqlconn, $transaction)
                        try {
                            $null = $sqlcmd.ExecuteNonQuery()
                        } catch {
                            Stop-Function -Continue -Message "Could not truncate $schema.$table" -ErrorRecord $_
                        }
                    }
                }

                # Setup bulk copy
                Write-Message -Level Verbose -Message "Starting bulk copy for $(Split-Path $file -Leaf)"

                # Setup bulk copy options
                [int]$bulkCopyOptions = ([Microsoft.Data.SqlClient.SqlBulkCopyOptions]::Default)
                $options = "TableLock", "CheckConstraints", "FireTriggers", "KeepIdentity", "KeepNulls"
                foreach ($option in $options) {
                    $optionValue = Get-Variable $option -ValueOnly -ErrorAction SilentlyContinue
                    if ($optionValue -eq $true) {
                        $bulkCopyOptions += $([Microsoft.Data.SqlClient.SqlBulkCopyOptions]::$option).value__
                    }
                }

                if ($PSCmdlet.ShouldProcess($instance, "Performing import from $file")) {
                    try {
                        # Create SqlBulkCopy using default options, or options specified in command line.
                        if ($bulkCopyOptions) {
                            $bulkcopy = New-Object Microsoft.Data.SqlClient.SqlBulkCopy($sqlconn, $bulkCopyOptions, $transaction)
                        } else {
                            $bulkcopy = New-Object Microsoft.Data.SqlClient.SqlBulkCopy($sqlconn, ([Microsoft.Data.SqlClient.SqlBulkCopyOptions]::Default), $transaction)
                        }

                        $bulkcopy.DestinationTableName = "[$schema].[$table]"
                        $bulkcopy.BulkCopyTimeout = 0
                        $bulkCopy.BatchSize = $BatchSize
                        $bulkCopy.NotifyAfter = $NotifyAfter
                        $bulkCopy.EnableStreaming = $true

                        # If the first column has quotes, then we have to setup a column map
                        $quotematch = (Get-Content -Path $file -TotalCount 1 -ErrorAction Stop).ToString()

                        if ((-not $KeepOrdinalOrder -and -not $AutoCreateTable) -or ($quotematch -match "'" -or $quotematch -match '"')) {
                            if ($ColumnMap) {
                                Write-Message -Level Verbose -Message "ColumnMap was supplied. Additional auto-mapping will not be attempted."
                            } elseif ($NoHeaderRow) {
                                Write-Message -Level Verbose -Message "NoHeaderRow was supplied. Additional auto-mapping will not be attempted."
                            } else {
                                try {
                                    $ColumnMap = @{ }
                                    $firstline = Get-Content -Path $file -TotalCount 1 -ErrorAction Stop
                                    $firstline -split "$Delimiter", 0, "SimpleMatch" | ForEach-Object {
                                        $trimmed = $PSItem.Trim('"')
                                        Write-Message -Level Verbose -Message "Adding $trimmed to ColumnMap"
                                        $ColumnMap.Add($trimmed, $trimmed)
                                    }
                                } catch {
                                    # oh well, we tried
                                    Write-Message -Level Verbose -Message "Couldn't auto create ColumnMap :("
                                    $ColumnMap = $null
                                }
                            }
                        }

                        if ($ColumnMap) {
                            foreach ($columnname in $ColumnMap) {
                                foreach ($key in $columnname.Keys) {
                                    $null = $bulkcopy.ColumnMappings.Add($key, $columnname[$key])
                                }
                            }
                        }

                        if ($Column) {
                            foreach ($columnname in $Column) {
                                $null = $bulkcopy.ColumnMappings.Add($columnname, $columnname)
                            }
                        }
                    } catch {
                        Stop-Function -Continue -Message "Failure" -ErrorRecord $_
                    }

                    # Write to server :D
                    try {

                        [Action[double]] $progressCallback = {
                            param($progress)

                            if (-not $NoProgress) {
                                $timetaken = [math]::Round($elapsed.Elapsed.TotalSeconds, 2)
                                $percent = [int]($progress * 100)
                                Write-ProgressHelper -StepNumber $percent -TotalSteps 100 -Activity "Importing from $file" -Message ([System.String]::Format("Progress: {0} rows {1}% in {2} seconds", $script:totalRowsCopied, $percent, $timetaken))
                            }
                        }

                        $stream = [System.IO.File]::OpenRead($File);
                        $progressStream = New-Object Sqlcollaborative.Dbatools.IO.ProgressStream($stream, $progressCallback, 0.05)
                        $textReader = New-Object System.IO.StreamReader($progressStream, [System.Text.Encoding]::$Encoding)

                        $reader = New-Object LumenWorks.Framework.IO.Csv.CsvReader(
                            $textReader,
                            $FirstRowHeader,
                            $Delimiter,
                            $Quote,
                            $Escape,
                            $Comment,
                            [LumenWorks.Framework.IO.Csv.ValueTrimmingOptions]::$TrimmingOption,
                            $BufferSize,
                            $NullValue
                        )

                        if ($PSBoundParameters.MaxQuotedFieldLength) {
                            $reader.MaxQuotedFieldLength = $MaxQuotedFieldLength
                        }
                        if ($PSBoundParameters.SkipEmptyLine) {
                            $reader.SkipEmptyLines = $SkipEmptyLine
                        }
                        if ($PSBoundParameters.SupportsMultiline) {
                            $reader.SupportsMultiline = $SupportsMultiline
                        }
                        if ($PSBoundParameters.UseColumnDefault) {
                            $reader.UseColumnDefaults = $UseColumnDefault
                        }
                        if ($PSBoundParameters.ParseErrorAction) {
                            $reader.DefaultParseErrorAction = $ParseErrorAction
                        }

                        # The legacy bulk copy library uses a 4 byte integer to track the RowsCopied, so the only option is to use
                        # integer wrap so that copy operations of row counts greater than [int32]::MaxValue will report accurate numbers.
                        # See https://github.com/dataplat/dbatools/issues/6927 for more details
                        $script:prevRowsCopied = [int64]0
                        $script:totalRowsCopied = [int64]0

                        # Add rowcount output
                        $bulkCopy.Add_SqlRowsCopied( {
                                $script:totalRowsCopied += (Get-AdjustedTotalRowsCopied -ReportedRowsCopied $args[1].RowsCopied -PreviousRowsCopied $script:prevRowsCopied).NewRowCountAdded

                                $tstamp = $(Get-Date -format 'yyyyMMddHHmmss')
                                Write-Message -Level Verbose -Message "[$tstamp] The bulk copy library reported RowsCopied = $($args[1].RowsCopied). The previous RowsCopied = $($script:prevRowsCopied). The adjusted total rows copied = $($script:totalRowsCopied)"
                                # progress is written by the ProgressStream callback
                                # save the previous count of rows copied to be used on the next event notification
                                $script:prevRowsCopied = $args[1].RowsCopied
                            })

                        $bulkCopy.WriteToServer($reader)

                        $completed = $true
                    } catch {
                        $completed = $false

                        Stop-Function -Continue -Message "Failure" -ErrorRecord $_
                    } finally {
                        try {
                            $reader.Close()
                            $reader.Dispose()
                        } catch {
                        }

                        if (-not $NoTransaction) {
                            if ($completed) {
                                try {
                                    $null = $transaction.Commit()
                                } catch {
                                }
                            } else {
                                try {
                                    $null = $transaction.Rollback()
                                } catch {
                                }
                            }
                        }

                        try {
                            $sqlconn.Close()
                            $sqlconn.Dispose()
                        } catch {
                        }

                        try {
                            $bulkCopy.Close()
                            $bulkcopy.Dispose()
                        } catch {
                        }

                        $finalRowCountReported = Get-BulkRowsCopiedCount $bulkCopy

                        $script:totalRowsCopied += (Get-AdjustedTotalRowsCopied -ReportedRowsCopied $finalRowCountReported -PreviousRowsCopied $script:prevRowsCopied).NewRowCountAdded

                        if ($completed) {
                            Write-Progress -id 1 -activity "Inserting $($script:totalRowsCopied) rows" -status "Complete" -Completed
                        } else {
                            Write-Progress -id 1 -activity "Inserting $($script:totalRowsCopied) rows" -status "Failed" -Completed
                        }
                    }
                }
                if ($PSCmdlet.ShouldProcess($instance, "Finalizing import")) {
                    if ($completed) {
                        # "Note: This count does not take into consideration the number of rows actually inserted when Ignore Duplicates is set to ON."
                        $rowsPerSec = [math]::Round($script:totalRowsCopied / $elapsed.ElapsedMilliseconds * 1000.0, 1)

                        Write-Message -Level Verbose -Message "$($script:totalRowsCopied) total rows copied"

                        [pscustomobject]@{
                            ComputerName  = $server.ComputerName
                            InstanceName  = $server.ServiceName
                            SqlInstance   = $server.DomainInstanceName
                            Database      = $Database
                            Table         = $table
                            Schema        = $schema
                            RowsCopied    = $script:totalRowsCopied
                            Elapsed       = [prettytimespan]$elapsed.Elapsed
                            RowsPerSecond = $rowsPerSec
                            Path          = $file
                        }
                    } else {
                        Stop-Function -Message "Transaction rolled back. Was the proper delimiter specified? Is the first row the column name?" -ErrorRecord $_
                        return
                    }
                }
            }
        }
    }
    end {
        # Close everything just in case & ignore errors
        try {
            $null = $sqlconn.close(); $null = $sqlconn.Dispose();
            $null = $bulkCopy.close(); $bulkcopy.dispose();
            $null = $reader.close(); $null = $reader.dispose()
        } catch {
            #here to avoid an empty catch
            $null = 1
        }

        # Script is finished. Show elapsed time.
        $totaltime = [math]::Round($scriptelapsed.Elapsed.TotalSeconds, 2)
        Write-Message -Level Verbose -Message "Total Elapsed Time for everything: $totaltime seconds"
    }
}

# SIG # Begin signature block
# MIIjYAYJKoZIhvcNAQcCoIIjUTCCI00CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCDNp4j6q2mD5UQb
# Fomh7iYn7tJa8ScD/cLNzTyDDQSWcqCCHVkwggUaMIIEAqADAgECAhADBbuGIbCh
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
# BgorBgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCBAIyIoDsi8ZsifMxUkqdKFgj7Q
# AxSaZigjTk9HLu6qIjANBgkqhkiG9w0BAQEFAASCAQBMLIRYW1pXu8JyPWfa8M2M
# BH6aN0YxmcW6bR5n6pl9aVNRDKQ4Y+CHJSdvscp0oznj40yYoLjVQxVJNPo97G5+
# txoDpSEDnj/eeoNnW4z4zCYLBklKiaPRnA+Vp2bT+T+ZeOc7J3zrmznBuOVhC1H7
# Io9VO3WrGl8oslny/wEIwc5QitFOlUHfGRm19HLFFvBsETBb6/mSo3Qe31T925Kq
# GEBQMAz9IZBP1hzIRCvLseKowDJejjDabS5aLfVDyfEApkQ7+P3igQrAQOEQJ9V4
# zLHfYzmAMI7ZrNL/J09oC+keANN6EYb5eWx2ee4KgtvLoNa+b4r9kqGVTB7ixzK6
# oYIDIDCCAxwGCSqGSIb3DQEJBjGCAw0wggMJAgEBMHcwYzELMAkGA1UEBhMCVVMx
# FzAVBgNVBAoTDkRpZ2lDZXJ0LCBJbmMuMTswOQYDVQQDEzJEaWdpQ2VydCBUcnVz
# dGVkIEc0IFJTQTQwOTYgU0hBMjU2IFRpbWVTdGFtcGluZyBDQQIQDE1pckuU+jwq
# Sj0pB4A9WjANBglghkgBZQMEAgEFAKBpMBgGCSqGSIb3DQEJAzELBgkqhkiG9w0B
# BwEwHAYJKoZIhvcNAQkFMQ8XDTIyMTExNzA4NTYzNlowLwYJKoZIhvcNAQkEMSIE
# IEEuB8OEPqG/1gIq7xpUoeTj8bG6aTa6uidP0Yl0XHHsMA0GCSqGSIb3DQEBAQUA
# BIICAAEdA5VIJX1WI6+beP14EZnQZiPMKRjsY1wOliVWMgMxmi7A5LzXVWQ6s4Kp
# 2mLIKVcJG6K3EdzLMlngj35xg5/HfG+EiaaO9IczKWdd2wylET9PkeFipDqDYlaK
# BFy+r5xB0r+JCyCkdAarcOiBIQ0mNLRjGh5iZeWq1OnQR8QDgZRQ2ZHH5jqtLRTQ
# HAVVxIIRfaaJeXUulzcCzMZh202yEndpAq34ZJQp8FhifxlbprMIkv90M7Nianuf
# qMCIGkSYPqSQyuPRHdlJcfo5mWFZKscO3WnISFSQo+mW6ZM9MPiY+i1ZLb6Wypa5
# mSH2N6HBGs1LeZFMq64CgDKrcvbGhnvutX72Dtlr/ZD0hi3ekO1jibza8CNvKJOd
# DCOoRz1q51P4PoZF2W20VQOrouL1etmiAAWz1B6p8LKd3ueFb5JBGI8Mq/mJr97G
# 8nFjiQ6eijj7icX7kINTxyZfDzAOkLGvDpSgjOuaKMRib3h87KHzL0ENXZiKnsm1
# KGfCpfCkbeTAKHA/sE161nB3UUeFkM3MW1kq1tzjzEJd66GDjuJWkaOungJyUrDe
# waXdmoBpsTA64pO2LJ0oRNqbBteJAlHtvrZHn+BqkWUW/aDhzshHm7Uqr+eVzOvG
# zBDQYr8j3BbYgBjRMI8gWpZfwooLnJRgZDjii578rmnGittA
# SIG # End signature block
