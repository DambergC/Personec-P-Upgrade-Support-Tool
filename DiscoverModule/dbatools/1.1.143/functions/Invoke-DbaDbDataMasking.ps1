function Invoke-DbaDbDataMasking {
    <#
    .SYNOPSIS
        Masks data by using randomized values determined by a configuration file and a randomizer framework

    .DESCRIPTION
        TMasks data by using randomized values determined by a configuration file and a randomizer framework

        It will use a configuration file that can be made manually or generated using New-DbaDbMaskingConfig

        Note that the following column and data types are not currently supported:
        Identity
        ForeignKey
        Computed
        Hierarchyid
        Geography
        Geometry
        Xml

    .PARAMETER SqlInstance
        The target SQL Server instance or instances.

    .PARAMETER SqlCredential
        Login to the target instance using alternative credentials. Accepts PowerShell credentials (Get-Credential).

        Windows Authentication, SQL Server Authentication, Active Directory - Password, and Active Directory - Integrated are all supported.

        For MFA support, please use Connect-DbaInstance.

    .PARAMETER Database
        Databases to process through

    .PARAMETER Table
        Tables to process. By default all the tables will be processed

    .PARAMETER Column
        Columns to process. By default all the columns will be processed

    .PARAMETER FilePath
        Configuration file that contains the which tables and columns need to be masked

    .PARAMETER Locale
        Set the local to enable certain settings in the masking

    .PARAMETER CharacterString
        The characters to use in string data. 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789' by default

    .PARAMETER ExcludeTable
        Exclude specific tables even if it's listed in the config file.

    .PARAMETER ExcludeColumn
        Exclude specific columns even if it's listed in the config file.

    .PARAMETER MaxValue
        Force a max length of strings instead of relying on datatype maxes. Note if a string datatype has a lower MaxValue, that will be used instead.

        Useful for adhoc updates and testing, otherwise, the config file should be used.

    .PARAMETER ModulusFactor
        Calculating the next nullable by using the remainder from the modulus. Default is every 10.

    .PARAMETER ExactLength
        Mask string values to the same length. So 'Tate' will be replaced with 4 random characters.

    .PARAMETER CommandTimeout
        Timeout for the database connection in seconds. Default is 300.

    .PARAMETER BatchSize
        Size of the batch to use to write the masked data back to the database

    .PARAMETER Retry
        The amount of retries to generate a unique row for a table. Default is 1000.

    .PARAMETER DictionaryFilePath
        Import the dictionary to be used in in the database masking

    .PARAMETER DictionaryExportPath
        Export the dictionary to the given path. Naming convention will be [computername]_[instancename]_[database]_Dictionary.csv

        Be careful with this feature, this export is the key to get the original values which is a security risk!

    .PARAMETER Force
        Forcefully execute commands when needed

    .PARAMETER WhatIf
        If this switch is enabled, no actions are performed but informational messages will be displayed that explain what would happen if the command were to run.

    .PARAMETER Confirm
        If this switch is enabled, you will be prompted for confirmation before executing any operations that change state.

    .PARAMETER EnableException
        By default, when something goes wrong we try to catch it, interpret it and give you a friendly warning message.
        This avoids overwhelming you with "sea of red" exceptions, but is inconvenient because it basically disables advanced scripting.
        Using this switch turns this "nice by default" feature off and enables you to catch exceptions with your own try/catch.

    .NOTES
        Tags: Masking, DataMasking
        Author: Sander Stad (@sqlstad, sqlstad.nl) | Chrissy LeMaire (@cl, netnerds.net)

        Website: https://dbatools.io
        Copyright: (c) 2018 by dbatools, licensed under MIT
        License: MIT https://opensource.org/licenses/MIT

    .LINK
        https://dbatools.io/Invoke-DbaDbDataMasking

    .EXAMPLE
        Invoke-DbaDbDataMasking -SqlInstance SQLDB2 -Database DB1 -FilePath C:\Temp\sqldb1.db1.tables.json

        Apply the data masking configuration from the file "sqldb1.db1.tables.json" to the db1 database on sqldb2. Prompt for confirmation for each table.

    .EXAMPLE
        Get-ChildItem -Path C:\Temp\sqldb1.db1.tables.json | Invoke-DbaDbDataMasking -SqlInstance SQLDB2 -Database DB1 -Confirm:$false

        Apply the data masking configuration from the file "sqldb1.db1.tables.json" to the db1 database on sqldb2. Do not prompt for confirmation.

    .EXAMPLE
        New-DbaDbMaskingConfig -SqlInstance SQLDB1 -Database DB1 -Path C:\Temp\clone -OutVariable file
        $file | Invoke-DbaDbDataMasking -SqlInstance SQLDB2 -Database DB1 -Confirm:$false

        Create the data masking configuration file "sqldb1.db1.tables.json", then use it to mask the db1 database on sqldb2. Do not prompt for confirmation.

    .EXAMPLE
        Get-ChildItem -Path C:\Temp\sqldb1.db1.tables.json | Invoke-DbaDbDataMasking -SqlInstance SQLDB2, sqldb3 -Database DB1 -Confirm:$false

        See what would happen if you the data masking configuration from the file "sqldb1.db1.tables.json" to the db1 database on sqldb2 and sqldb3. Do not prompt for confirmation.
    #>
    [CmdLetBinding(SupportsShouldProcess, ConfirmImpact = "High")]
    param (
        [DbaInstanceParameter[]]$SqlInstance,
        [PSCredential]$SqlCredential,
        [string[]]$Database,
        [parameter(Mandatory, ValueFromPipeline)]
        [Alias('Path', 'FullName')]
        [object]$FilePath,
        [string]$Locale = 'en',
        [string]$CharacterString = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789',
        [string[]]$Table,
        [string[]]$Column,
        [string[]]$ExcludeTable,
        [string[]]$ExcludeColumn,
        [int]$MaxValue,
        [int]$ModulusFactor,
        [switch]$ExactLength,
        [int]$CommandTimeout,
        [int]$BatchSize,
        [int]$Retry,
        [string[]]$DictionaryFilePath,
        [string]$DictionaryExportPath,
        [switch]$EnableException
    )
    begin {
        if ($Force) { $ConfirmPreference = 'none' }

        $supportedDataTypes = @(
            'bit', 'bigint', 'bool',
            'char', 'date',
            'datetime', 'datetime2', 'decimal',
            'float',
            'int',
            'money',
            'nchar', 'ntext', 'nvarchar',
            'smalldatetime', 'smallint',
            'text', 'time', 'tinyint',
            'uniqueidentifier', 'userdefineddatatype',
            'varchar'
        )

        $supportedFakerMaskingTypes = Get-DbaRandomizedType | Select-Object Type -ExpandProperty Type -Unique

        $supportedFakerSubTypes = Get-DbaRandomizedType | Select-Object Subtype -ExpandProperty Subtype -Unique

        $supportedFakerSubTypes += "Date"

        # Set defaults
        if (-not $ModulusFactor) {
            $ModulusFactor = 10
            Write-Message -Level Verbose -Message "Modulus factor set to $ModulusFactor"
        }

        if (-not $CommandTimeout) {
            $CommandTimeout = 300
            Write-Message -Level Verbose -Message "Command time-out set to $CommandTimeout"
        }

        if (-not $BatchSize) {
            $BatchSize = 1000
            Write-Message -Level Verbose -Message "Batch size set to $BatchSize"
        }

        if (-not $Retry) {
            $Retry = 1000
            Write-Message -Level Verbose -Message "Retry count set to $Retry"
        }
    }

    process {
        if (Test-FunctionInterrupt) {
            return
        }

        if ($FilePath.ToString().StartsWith('http')) {
            $tables = Invoke-RestMethod -Uri $FilePath
        } else {
            # Test the configuration file
            try {
                $configErrors = @()

                $configErrors += Test-DbaDbDataMaskingConfig -FilePath $FilePath -EnableException

                if ($configErrors.Count -ge 1) {
                    Stop-Function -Message "Errors found testing the configuration file." -Target $FilePath
                    return $configErrors
                }
            } catch {
                Stop-Function -Message "Something went wrong testing the configuration file" -ErrorRecord $_ -Target $FilePath
                return
            }

            # Get all the items that should be processed
            try {
                $tables = Get-Content -Path $FilePath -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
            } catch {
                Stop-Function -Message "Could not parse masking config file" -ErrorRecord $_ -Target $FilePath
                return
            }
        }

        # Test the columns for data types
        foreach ($tabletest in $tables.Tables) {
            if ($Table -and $tabletest.Name -notin $Table) {
                continue
            }

            foreach ($columntest in $tabletest.Columns) {
                if ($columntest.ColumnType -in 'hierarchyid', 'geography', 'xml', 'geometry' -and $columntest.Name -notin $Column) {
                    Stop-Function -Message "$($columntest.ColumnType) is not supported, please remove the column $($columntest.Name) from the $($tabletest.Name) table" -Target $tables -Continue
                }
            }
        }

        foreach ($instance in $SqlInstance) {
            try {
                $server = Connect-DbaInstance -SqlInstance $instance -SqlCredential $SqlCredential -MinimumVersion 9
            } catch {
                Stop-Function -Message "Failure" -Category ConnectionError -ErrorRecord $_ -Target $instance -Continue
            }

            # Check if the deterministic values table is already present
            if ($server.Databases['tempdb'].Tables.Name -contains 'DeterministicValues') {
                Write-Message -Level Verbose -Message "Deterministic values table already exists. Dropping it...."
                $query = "DROP TABLE [dbo].[DeterministicValues];"
                $server.Databases['tempdb'].Query($query)
            }

            # Create the deterministic value table
            $query = "
                CREATE TABLE dbo.DeterministicValues
                (
                    [ValueKey] VARCHAR(900),
                    [NewValue] VARCHAR(900)
                )

                CREATE UNIQUE NONCLUSTERED INDEX UNX__DeterministicValues_ValueKey
                ON dbo.DeterministicValues ( ValueKey )
            "

            $null = $server.Databases['tempdb'].Query($query)

            # Import the dictionary files
            if ($DictionaryFilePath.Count -ge 1) {
                foreach ($file in $DictionaryFilePath) {
                    Write-Message -Level Verbose -Message "Importing dictionary file '$file'"
                    if (Test-Path -Path $file) {
                        try {
                            # Import the keys and values
                            Import-DbaCsv -Path $file -SqlInstance $server -Database tempdb -Schema dbo -Table DeterministicValues
                        } catch {
                            Stop-Function -Message "Could not import csv data from file '$file'" -ErrorRecord $_ -Target $file
                        }
                    } else {
                        Stop-Function -Message "Could not import dictionary file '$file'" -ErrorRecord $_ -Target $file
                    }
                }
            }

            # Get the database name
            if (-not $Database) {
                $Database = $tables.Name
            }

            # Loop through the databases
            foreach ($dbName in $Database) {
                if ($server.VersionMajor -lt 9) {
                    Stop-Function -Message "SQL Server version must be 2005 or greater" -Continue
                }

                $db = $server.Databases[$($dbName)]

                #$stepcounter = $nullmod = 0
                $nullmod = 0

                #region for each table
                foreach ($tableobject in $tables.Tables) {
                    $elapsed = [System.Diagnostics.Stopwatch]::StartNew()

                    $uniqueDataTableName = $null
                    $uniqueValueColumns = @()
                    $stringBuilder = [System.Text.StringBuilder]''

                    if ($tableobject.Name -in $ExcludeTable) {
                        Write-Message -Level Verbose -Message "Skipping $($tableobject.Name) because it is explicitly excluded"
                        continue
                    }

                    if ($tableobject.Name -notin $db.Tables.Name) {
                        Stop-Function -Message "Table $($tableobject.Name) is not present in $db" -Target $db -Continue
                    }

                    $dbTable = $db.Tables | Where-Object { $_.Schema -eq $tableobject.Schema -and $_.Name -eq $tableobject.Name }

                    [bool]$cleanupIdentityColumn = $false

                    # Make sure there is an identity column present to speed things up
                    if (-not ($dbTable.Columns | Where-Object { $_.Identity -eq $true })) {
                        Write-Message -Level Verbose -Message "Adding identity column to table [$($dbTable.Schema)].[$($dbTable.Name)]"
                        $query = "ALTER TABLE [$($dbTable.Schema)].[$($dbTable.Name)] ADD MaskingID BIGINT IDENTITY(1, 1) NOT NULL;"

                        try {
                            Invoke-DbaQuery -SqlInstance $server -SqlCredential $SqlCredential -Database $db.Name -Query $query
                        } catch {
                            Stop-Function -Message "Could not alter the table to add the masking id" -Target $db -Continue
                        }

                        $cleanupIdentityColumn = $true

                        $identityColumn = "MaskingID"

                        $dbTable.Columns.Refresh()
                    } else {
                        $identityColumn = $dbTable.Columns | Where-Object { $_.Identity } | Select-Object -ExpandProperty Name
                    }

                    # Check if the index for the identity column is already present
                    $maskingIndexName = "NIX__$($dbTable.Schema)_$($dbTable.Name)_Masking"
                    try {
                        if ($dbTable.Indexes.Name -contains $maskingIndexName) {
                            Write-Message -Level Verbose -Message "Masking index already exists in table [$($dbTable.Schema)].[$($dbTable.Name)]. Dropping it..."
                            $dbTable.Indexes[$($maskingIndexName)].Drop()
                        }
                    } catch {
                        Stop-Function -Message "Could not remove identity index to table [$($dbTable.Schema)].[$($dbTable.Name)]" -Continue
                    }

                    # Create the index for the identity column
                    try {
                        Write-Message -Level Verbose -Message "Adding index on identity column [$($identityColumn)] in table [$($dbTable.Schema)].[$($dbTable.Name)]"

                        $query = "CREATE NONCLUSTERED INDEX [$($maskingIndexName)] ON [$($dbTable.Schema)].[$($dbTable.Name)]([$($identityColumn)])"

                        $queryParams = @{
                            SqlInstance   = $server
                            SqlCredential = $SqlCredential
                            Database      = $db.Name
                            Query         = $query
                            QueryTimeout  = $CommandTimeout
                        }

                        Invoke-DbaQuery @queryParams
                    } catch {
                        Stop-Function -Message "Could not add identity index to table [$($dbTable.Schema)].[$($dbTable.Name)]" -Continue
                    }

                    try {
                        if (-not $tableobject.FilterQuery) {
                            # Get all the columns from the table
                            $columnString = "[" + (($dbTable.Columns | Where-Object { $_.DataType -in $supportedDataTypes } | Select-Object Name -ExpandProperty Name) -join "],[") + "]"

                            # Add the identifier column
                            $columnString += ",[$($identityColumn)]"

                            # Put it all together
                            $query = "SELECT $($columnString) FROM [$($tableobject.Schema)].[$($tableobject.Name)]"
                        } else {
                            # Get the query from the table objects
                            $query = ($tableobject.FilterQuery).ToLower()

                            # Check if the query already contains the identifier column
                            if (-not ($query | Select-String -Pattern $identityColumn)) {
                                # Split up the query from the first "from"
                                $queryParts = $query -split "from", 2

                                # Put it all together again with the identifier
                                $query = "$($queryParts[0].Trim()), $($identityColumn) FROM $($queryParts[1].Trim())"
                            }
                        }

                        # Get the data
                        [array]$data = $db.Query($query)
                    } catch {
                        Stop-Function -Message "Failure retrieving the data from table [$($tableobject.Schema)].[$($tableobject.Name)]" -Target $Database -ErrorRecord $_ -Continue
                    }

                    #region unique indexes
                    # Check if the table contains unique indexes
                    if ($tableobject.HasUniqueIndex) {

                        # Loop through the rows and generate a unique value for each row
                        Write-Message -Level Verbose -Message "Generating unique values for [$($tableobject.Schema)].[$($tableobject.Name)]"

                        $params = @{
                            SqlInstance   = $server
                            SqlCredential = $SqlCredential
                            Database      = $db.name
                            Schema        = $tableobject.Schema
                            Table         = $tableobject.Name
                        }

                        $indexToTable = Convert-DbaIndexToTable @params

                        if ($indexToTable) {
                            # compare the index columns to the column in the json table object
                            $compareParams = @{
                                ReferenceObject  = $indexToTable.Columns
                                DifferenceObject = $tableobject.Columns.Name
                                IncludeEqual     = $true
                            }
                            $maskingColumnIndexCount = (Compare-Object @compareParams | Where-Object { $_.SideIndicator -eq "==" }).Count

                            # Check if there is any need to generate unique values
                            if ($maskingColumnIndexCount -ge 1) {

                                # Check if the temporary table already exists
                                $server.Databases['tempdb'].Tables.Refresh()
                                $uniqueDataTableName = $indexToTable.TempTableName

                                if ($server.Databases['tempdb'].Tables.Name -contains $indexToTable.TempTableName) {
                                    Write-Message -Level Verbose -Message "Table '$($indexToTable.TempTableName)' already exists. Dropping it.."
                                    try {
                                        $query = "DROP TABLE $($indexToTable.TempTableName)"
                                        Invoke-DbaQuery -SqlInstance $server -SqlCredential $SqlCredential -Database 'tempdb' -Query $query
                                    } catch {
                                        Stop-Function -Message "Could not drop temporary table"
                                    }
                                }

                                # Create the temporary table
                                try {
                                    Write-Message -Level Verbose -Message "Creating temporary table '$($indexToTable.TempTableName)'"
                                    Invoke-DbaQuery -SqlInstance $server -SqlCredential $SqlCredential -Database 'tempdb' -Query $indexToTable.CreateStatement
                                } catch {
                                    Stop-Function -Message "Could not create temporary table #[$($tableobject.Schema)].[$($tableobject.Name)]"
                                }

                                # Create the unique index table
                                try {
                                    Write-Message -Level Verbose -Message "Creating the unique index for temporary table '$($indexToTable.TempTableName)'"
                                    Invoke-DbaQuery -SqlInstance $server -SqlCredential $SqlCredential -Database 'tempdb' -Query $indexToTable.UniqueIndexStatement
                                } catch {
                                    Stop-Function -Message "Could not create temporary table #[$($tableobject.Schema)].[$($tableobject.Name)]"
                                }

                                # Create a unique row
                                $retryCount = 0
                                for ($i = 0; $i -lt $data.Count; $i++) {
                                    $insertQuery = "INSERT INTO [$($indexToTable.TempTableName)]([$($indexToTable.Columns -join '],[')]) VALUES("
                                    $insertFailed = $false
                                    $insertValues = @()

                                    foreach ($indexColumn in $indexToTable.Columns) {
                                        $columnMaskInfo = $tableobject.Columns | Where-Object { $_.Name -eq $indexColumn }

                                        if ($indexColumn -eq "RowNr") {
                                            $newValue = $i + 1
                                        } elseif ($columnMaskInfo) {
                                            # make sure min is good
                                            if ($columnMaskInfo.MinValue) {
                                                $min = $columnMaskInfo.MinValue
                                            } else {
                                                if ($columnMaskInfo.CharacterString) {
                                                    $min = 1
                                                } else {
                                                    $min = 0
                                                }
                                            }

                                            # make sure max is good
                                            if ($MaxValue) {
                                                if ($columnMaskInfo.MaxValue -le $MaxValue) {
                                                    $max = $columnMaskInfo.MaxValue
                                                } else {
                                                    $max = $MaxValue
                                                }
                                            } else {
                                                $max = $columnMaskInfo.MaxValue
                                            }

                                            if (-not $columnMaskInfo.MaxValue -and -not (Test-Bound -ParameterName MaxValue)) {
                                                $max = 10
                                            }

                                            if ((-not $columnMaskInfo.MinValue -or -not $columnMaskInfo.MaxValue) -and ($columnMaskInfo.ColumnType -match 'date')) {
                                                if (-not $columnMaskInfo.MinValue) {
                                                    $min = (Get-Date).AddDays(-365)
                                                }
                                                if (-not $columnMaskInfo.MaxValue) {
                                                    $max = (Get-Date).AddDays(365)
                                                }
                                            }

                                            if ($columnMaskInfo.CharacterString) {
                                                $charstring = $columnMaskInfo.CharacterString
                                            } else {
                                                $charstring = $CharacterString
                                            }

                                            # Generate a new value
                                            $newValue = $null

                                            $newValueParams = $null

                                            try {
                                                $newValueParams = $null
                                                if (-not $columnobject.SubType -and $columnobject.ColumnType -in $supportedDataTypes) {
                                                    $newValueParams = @{
                                                        DataType = $columnMaskInfo.SubType
                                                        Min      = $columnMaskInfo.MinValue
                                                        Max      = $columnMaskInfo.MaxValue
                                                        Locale   = $Locale
                                                    }
                                                } else {
                                                    $newValueParams = @{
                                                        RandomizerType    = $columnMaskInfo.MaskingType
                                                        RandomizerSubtype = $columnMaskInfo.SubType
                                                        Min               = $min
                                                        Max               = $max
                                                        CharacterString   = $charstring
                                                        Format            = $columnMaskInfo.Format
                                                        Separator         = $columnMaskInfo.Separator
                                                        Locale            = $Locale
                                                    }
                                                }

                                                $newValue = Get-DbaRandomizedValue @newValueParams
                                            } catch {
                                                Stop-Function -Message "Failure" -Target $columnMaskInfo -Continue -ErrorRecord $_
                                            }
                                        } else {
                                            $newValue = $null
                                        }

                                        if ($columnMaskInfo) {
                                            try {
                                                $insertValue = Convert-DbaMaskingValue -Value $newValue -DataType $columnMaskInfo.ColumnType -Nullable:$columnMaskInfo.Nullable -EnableException

                                                if ($convertedValue.ErrorMessage) {
                                                    $maskingErrorFlag = $true
                                                    Stop-Function "Could not convert the value. $($convertedValue.ErrorMessage)" -Target $convertedValue
                                                }
                                            } catch {
                                                Stop-Function -Message "Could not convert value" -ErrorRecord $_ -Target $newValue
                                            }

                                            $insertValues += $insertValue.NewValue
                                        } elseif ($indexColumn -eq "RowNr") {
                                            $insertValues += $newValue
                                        } else {
                                            $insertValues += "NULL"
                                        }

                                        $uniqueValueColumns += $columnMaskInfo.Name
                                    }

                                    # Join all the values to the insert query
                                    $insertQuery += "$($insertValues -join ','));"

                                    # Try inserting the value
                                    try {
                                        $null = $server.Databases['tempdb'].Query($insertQuery)
                                        $insertFailed = $false
                                    } catch {
                                        Write-PSFMessage -Level Verbose -Message "Could not insert value"
                                        $insertFailed = $true
                                    }

                                    # Try to insert the value as long it's failed
                                    while ($insertFailed) {
                                        if ($retryCount -eq $Retry) {
                                            Stop-Function -Message "Could not create a unique row after $retryCount tries. Stopping..."
                                            return
                                        }

                                        $insertQuery = "INSERT INTO [$($indexToTable.TempTableName)]([$($indexToTable.Columns -join '],[')]) VALUES("

                                        foreach ($indexColumn in $indexToTable.Columns) {
                                            $columnMaskInfo = $tableobject.Columns | Where-Object { $_.Name -eq $indexColumn }

                                            if ($indexColumn -eq "RowNr") {
                                                $newValue = $i + 1
                                            } elseif ($columnMaskInfo) {
                                                # make sure min is good
                                                if ($columnMaskInfo.MinValue) {
                                                    $min = $columnMaskInfo.MinValue
                                                } else {
                                                    if ($columnMaskInfo.CharacterString) {
                                                        $min = 1
                                                    } else {
                                                        $min = 0
                                                    }
                                                }

                                                # make sure max is good
                                                if ($MaxValue) {
                                                    if ($columnMaskInfo.MaxValue -le $MaxValue) {
                                                        $max = $columnMaskInfo.MaxValue
                                                    } else {
                                                        $max = $MaxValue
                                                    }
                                                } else {
                                                    $max = $columnMaskInfo.MaxValue
                                                }

                                                if (-not $columnMaskInfo.MaxValue -and -not (Test-Bound -ParameterName MaxValue)) {
                                                    $max = 10
                                                }

                                                if ((-not $columnMaskInfo.MinValue -or -not $columnMaskInfo.MaxValue) -and ($columnMaskInfo.ColumnType -match 'date')) {
                                                    if (-not $columnMaskInfo.MinValue) {
                                                        $min = (Get-Date).AddDays(-365)
                                                    }
                                                    if (-not $columnMaskInfo.MaxValue) {
                                                        $max = (Get-Date).AddDays(365)
                                                    }
                                                }

                                                if ($columnMaskInfo.CharacterString) {
                                                    $charstring = $columnMaskInfo.CharacterString
                                                } else {
                                                    $charstring = $CharacterString
                                                }

                                                # Generate a new value
                                                $newValue = $null

                                                $newValueParams = $null

                                                try {
                                                    $newValueParams = $null
                                                    if (-not $columnobject.SubType -and $columnobject.ColumnType -in $supportedDataTypes) {
                                                        $newValueParams = @{
                                                            DataType = $columnMaskInfo.SubType
                                                            Min      = $columnMaskInfo.MinValue
                                                            Max      = $columnMaskInfo.MaxValue
                                                            Locale   = $Locale
                                                        }
                                                    } else {
                                                        $newValueParams = @{
                                                            RandomizerType    = $columnMaskInfo.MaskingType
                                                            RandomizerSubtype = $columnMaskInfo.SubType
                                                            Min               = $min
                                                            Max               = $max
                                                            CharacterString   = $charstring
                                                            Format            = $columnMaskInfo.Format
                                                            Separator         = $columnMaskInfo.Separator
                                                            Locale            = $Locale
                                                        }
                                                    }

                                                    $newValue = Get-DbaRandomizedValue @newValueParams
                                                } catch {
                                                    Stop-Function -Message "Failure" -Target $columnMaskInfo -Continue -ErrorRecord $_
                                                }
                                            } else {
                                                $newValue = $null
                                            }

                                            if ($columnMaskInfo) {
                                                try {
                                                    $insertValue = Convert-DbaMaskingValue -Value $newValue -DataType $columnMaskInfo.ColumnType -Nullable:$columnMaskInfo.Nullable -EnableException

                                                    if ($convertedValue.ErrorMessage) {
                                                        $maskingErrorFlag = $true
                                                        Stop-Function "Could not convert the value. $($convertedValue.ErrorMessage)" -Target $convertedValue
                                                    }
                                                } catch {
                                                    Stop-Function -Message "Could not convert value" -ErrorRecord $_ -Target $newValue
                                                }

                                                $insertValues += $insertValue.NewValue
                                            } elseif ($indexColumn -eq "RowNr") {
                                                $insertValues += $newValue
                                            } else {
                                                $insertValues += "NULL"
                                            }
                                        }

                                        # Join all the values to the insert query
                                        $insertQuery += "$($insertValues -join ','));"

                                        # Try inserting the value
                                        try {
                                            $null = $server.Databases['tempdb'].Query($insertQuery)
                                            $insertFailed = $false
                                        } catch {
                                            Write-PSFMessage -Level Verbose -Message "Could not insert value"
                                            $insertFailed = $true
                                            $retryCount++
                                        }
                                    }
                                }

                                try {
                                    Write-Message -Level Verbose -Message "Creating masking index for [$($indexToTable.TempTableName)]"
                                    $query = "CREATE NONCLUSTERED INDEX [NIX_$($indexToTable.TempTableName)_MaskID] ON [$($indexToTable.TempTableName)]([RowNr])"
                                    $null = $server.Databases['tempdb'].Query($query)
                                } catch {
                                    Stop-Function -Message "Could not add masking index for [$($indexToTable.TempTableName)]" -ErrorRecord $_
                                }
                            } else {
                                Write-PSFMessage -Level Verbose -Message "Table [$($tableobject.Schema)].[$($tableobject.Name)] does not contain any masking index columns to process"
                            }
                        } else {
                            Stop-Function -Message "The table does not have any indexes"
                        }
                    }

                    #endregion unique indexes

                    $tablecolumns = $tableobject.Columns

                    if ($Column) {
                        $tablecolumns = $tablecolumns | Where-Object { $_.Name -in $Column }
                    }

                    if ($ExcludeColumn) {
                        if ([string]$uniqueIndex.Columns -match ($ExcludeColumn -join "|")) {
                            Stop-Function -Message "Column present in -ExcludeColumn cannot be excluded because it's part of an unique index" -Target $ExcludeColumn -Continue
                        }

                        $tablecolumns = $tablecolumns | Where-Object { $_.Name -notin $ExcludeColumn }
                    }

                    if (-not $tablecolumns) {
                        Write-Message -Level Verbose "No columns to process in [$($dbName)].[$($tableobject.Schema)].[$($tableobject.Name)], moving on"
                        continue
                    }

                    if ($Pscmdlet.ShouldProcess($instance, "Masking $($data.Count) row(s) for column [$($tablecolumns.Name -join ', ')] in $($dbName).$($tableobject.Schema).$($tableobject.Name)")) {
                        $totalBatches = [System.Math]::Ceiling($data.Count / $BatchSize)

                        # Figure out if the columns has actions
                        $columnsWithActions = @()
                        $columnsWithActions += $tableobject.Columns | Where-Object { $null -ne $_.Action }

                        # Figure out if the columns has composites
                        $columnsWithComposites = @()
                        $columnsWithComposites += $tableobject.Columns | Where-Object { $null -ne $_.Composite }

                        # Check for both special actions
                        if (($columnsWithComposites.Count -ge 1) -and ($columnsWithActions.Count -ge 1)) {
                            Stop-Function -Message "You cannot use both composites and actions"
                        }

                        # Loop through each of the rows and change them
                        foreach ($columnobject in $tablecolumns) {
                            # Set the masking error
                            [bool]$maskingErrorFlag = $false

                            # Only start generating values if the column is not using Actions or Composites
                            if (($columnobject.Name -notin $columnsWithActions.Name) -and ($columnobject.Name -notin $columnsWithComposites.Name)) {

                                # Set the counters
                                $rowNumber = $batchRowNr = $batchNr = 0

                                if ($columnobject.StaticValue) {
                                    $newValue = $columnobject.StaticValue

                                    if ($null -eq $newValue -and -not $columnobject.Nullable) {
                                        Write-PSFMessage -Message "Column '$($columnobject.Name)' static value cannot null when column is set not to be nullable."
                                    } else {
                                        try {
                                            $convertedValue = Convert-DbaMaskingValue -Value $newValue -DataType $columnobject.ColumnType -Nullable:$columnobject.Nullable -EnableException

                                            if ($convertedValue.ErrorMessage) {
                                                $maskingErrorFlag = $true
                                                Stop-Function "Could not convert the value. $($convertedValue.ErrorMessage)" -Target $convertedValue
                                            } else {
                                                $null = $stringBuilder.AppendLine("UPDATE [$($tableobject.Schema)].[$($tableobject.Name)] SET [$($columnObject.Name)] = $($convertedValue.NewValue)")
                                            }

                                        } catch {
                                            Stop-Function -Message "Could not convert value" -ErrorRecord $_ -Target $newValue
                                        }

                                        $batchRowNr++
                                    }
                                } else {
                                    Write-Message -Level Verbose -Message "Processing column [$($columnObject.Name)]"
                                    # Column does not have an action
                                    foreach ($row in $data) {
                                        # Start counting the rows
                                        $rowNumber++

                                        if ((($batchRowNr) % 100) -eq 0) {

                                            $progressParams = @{
                                                StepNumber = $batchNr
                                                TotalSteps = $totalBatches
                                                Activity   = "Masking $($data.Count) rows in $($tableobject.Schema).$($tableobject.Name) in $($dbName) on $instance"
                                                Message    = "Generating Updates"
                                            }

                                            Write-ProgressHelper @progressParams
                                        }

                                        $updates = @()
                                        $newValue = $null

                                        # Check for value being in deterministic masking table
                                        if (($null -ne $row.($columnobject.Name)) -and ($row.($columnobject.Name) -ne '')) {
                                            try {
                                                $lookupValue = Convert-DbaMaskingValue -Value $row.($columnobject.Name) -DataType varchar -Nullable:$columnobject.Nullable -EnableException

                                                if ($convertedValue.ErrorMessage) {
                                                    $maskingErrorFlag = $true
                                                    Stop-Function "Could not convert the value. $($convertedValue.ErrorMessage)" -Target $convertedValue
                                                }
                                            } catch {
                                                Stop-Function -Message "Could not convert value" -ErrorRecord $_ -Target $row.($columnobject.Name)
                                            }

                                            $query = "SELECT [NewValue] FROM dbo.DeterministicValues WHERE [ValueKey] = $($lookupValue.NewValue)"

                                            try {
                                                $lookupResult = $null
                                                $lookupResult = $server.Databases['tempdb'].Query($query)
                                            } catch {
                                                Stop-Function -Message "Something went wrong retrieving the deterministic values" -Target $query -ErrorRecord $_
                                            }
                                        }

                                        # Check the columnobject properties and possible scenarios
                                        if ($columnobject.MaskingType -eq 'Static') {
                                            $newValue = $columnobject.StaticValue
                                        } elseif ($columnobject.KeepNull -and $columnobject.Nullable -and (($row.($columnobject.Name)).GetType().Name -eq 'DBNull') -or ($row.($columnobject.Name) -eq '')) {
                                            $newValue = $null
                                        } elseif (-not $columnobject.KeepNull -and $columnobject.Nullable -and (($nullmod++) % $ModulusFactor -eq 0)) {
                                            $newValue = $null
                                        } elseif ($tableobject.HasUniqueIndex -and $columnobject.Name -in $uniqueValueColumns) {
                                            $query = "SELECT $($columnobject.Name) FROM $($uniqueDataTableName) WHERE [RowNr] = $rowNumber"

                                            try {
                                                $uniqueData = Invoke-DbaQuery -SqlInstance $server -SqlCredential $SqlCredential -Database tempdb -Query $query
                                            } catch {
                                                Stop-Function -Message "Something went wrong getting the unique data" -Target $query -ErrorRecord $_
                                            }

                                            if ($null -eq $uniqueData) {
                                                Stop-Function -Message "Could not find any unique values" -Target $tableobject
                                                return
                                            }

                                            $newValue = $uniqueData.$($columnobject.Name)
                                        } elseif ($columnobject.Deterministic -and $lookupResult.NewValue) {
                                            $newValue = $lookupResult.NewValue
                                        } else {
                                            # make sure min is good
                                            if ($columnobject.MinValue) {
                                                $min = $columnobject.MinValue
                                            } else {
                                                if ($columnobject.CharacterString) {
                                                    $min = 1
                                                } else {
                                                    $min = 0
                                                }
                                            }

                                            # make sure max is good
                                            if ($MaxValue) {
                                                if ($columnobject.MaxValue -le $MaxValue) {
                                                    $max = $columnobject.MaxValue
                                                } else {
                                                    $max = $MaxValue
                                                }
                                            } else {
                                                $max = $columnobject.MaxValue
                                            }

                                            if (-not $columnobject.MaxValue -and -not (Test-Bound -ParameterName MaxValue)) {
                                                $max = 10
                                            }

                                            if ((-not $columnobject.MinValue -or -not $columnobject.MaxValue) -and ($columnobject.ColumnType -match 'date')) {
                                                if (-not $columnobject.MinValue) {
                                                    $min = (Get-Date).AddDays(-365)
                                                }
                                                if (-not $columnobject.MaxValue) {
                                                    $max = (Get-Date).AddDays(365)
                                                }
                                            }

                                            if ($columnobject.CharacterString) {
                                                $charstring = $columnobject.CharacterString
                                            } else {
                                                $charstring = $CharacterString
                                            }

                                            # Setup the new value parameters
                                            $newValueParams = $null

                                            if ($null -eq $columnobject.SubType) {
                                                $newValueParams = @{
                                                    DataType        = $columnobject.ColumnType
                                                    Min             = $min
                                                    Max             = $max
                                                    CharacterString = $charstring
                                                    Format          = $columnobject.Format
                                                    Locale          = $Locale
                                                }
                                            } elseif ($columnobject.SubType.ToLowerInvariant() -eq 'shuffle') {
                                                if ($columnobject.ColumnType -in 'bigint', 'char', 'int', 'nchar', 'nvarchar', 'smallint', 'tinyint', 'varchar') {
                                                    $newValueParams = @{
                                                        RandomizerType    = "Random"
                                                        RandomizerSubtype = "Shuffle"
                                                        Value             = ($row.$($columnobject.Name))
                                                        Locale            = $Locale
                                                    }
                                                } elseif ($columnobject.ColumnType -in 'decimal', 'numeric', 'float', 'money', 'smallmoney', 'real') {
                                                    $newValueParams = @{
                                                        RandomizerType    = "Random"
                                                        RandomizerSubtype = "Shuffle"
                                                        Value             = ($row.$($columnobject.Name))
                                                        Locale            = $Locale
                                                    }
                                                }
                                            } else {
                                                $newValueParams = @{
                                                    RandomizerType    = $columnobject.MaskingType
                                                    RandomizerSubtype = $columnobject.SubType
                                                    Min               = $min
                                                    Max               = $max
                                                    CharacterString   = $charstring
                                                    Format            = $columnobject.Format
                                                    Separator         = $columnobject.Separator
                                                    Locale            = $Locale
                                                }
                                            }

                                            # Generate the new value
                                            try {
                                                $newValue = Get-DbaRandomizedValue @newValueParams
                                            } catch {
                                                $maskingErrorFlag = $true
                                                Stop-Function -Message "Failure" -Target $columnobject -Continue -ErrorRecord $_
                                            }
                                        }

                                        # Convert the values so they can used in T-SQL
                                        try {
                                            if ($row.($columnobject.Name) -eq '') {
                                                $convertedValue = Convert-DbaMaskingValue -Value ' ' -DataType $columnobject.ColumnType -Nullable:$columnobject.Nullable -EnableException
                                            } else {
                                                $convertedValue = Convert-DbaMaskingValue -Value $newValue -DataType $columnobject.ColumnType -Nullable:$columnobject.Nullable -EnableException
                                            }

                                            if ($convertedValue.ErrorMessage) {
                                                $maskingErrorFlag = $true
                                                Stop-Function "Could not convert the value. $($convertedValue.ErrorMessage)" -Target $convertedValue
                                            }
                                        } catch {
                                            Stop-Function -Message "Could not convert value" -ErrorRecord $_ -Target $newValue
                                        }

                                        # Add to the updates
                                        $updates += "[$($columnobject.Name)] = $($convertedValue.NewValue)"

                                        # Check if this value is determinisic
                                        if ($columnobject.Deterministic -and ($null -eq $lookupResult.NewValue)) {
                                            if (($null -ne $row.($columnobject.Name)) -and ($row.($columnobject.Name) -ne '')) {
                                                try {
                                                    $previous = Convert-DbaMaskingValue -Value $row.($columnobject.Name) -DataType $columnobject.ColumnType -Nullable:$columnobject.Nullable -EnableException

                                                    if ($convertedValue.ErrorMessage) {
                                                        $maskingErrorFlag = $true
                                                        Stop-Function "Could not convert the value. $($convertedValue.ErrorMessage)" -Target $convertedValue
                                                    }
                                                } catch {
                                                    Stop-Function -Message "Could not convert value" -ErrorRecord $_ -Target $row.($columnobject.Name)
                                                }

                                                $query = "INSERT INTO dbo.DeterministicValues (ValueKey, NewValue) VALUES ($($previous.NewValue), $($convertedValue.NewValue));"
                                                try {
                                                    $null = $server.Databases['tempdb'].Query($query)
                                                } catch {
                                                    Stop-Function -Message "Could not save deterministic value.`n$_" -Target $query -ErrorRecord $_
                                                }
                                            }
                                        }

                                        # Setup the query
                                        $updateQuery = "UPDATE [$($tableobject.Schema)].[$($tableobject.Name)] SET $($updates -join ', ') WHERE [$($identityColumn)] = $($row.$($identityColumn)); "
                                        $null = $stringBuilder.AppendLine($updateQuery)

                                        # Increase the batch row number to keep track of the batches
                                        $batchRowNr++

                                        # if we reached the batchsize
                                        if ($batchRowNr -eq $BatchSize) {
                                            # Increase the batch nr if it's not already reached
                                            if ($batchNr -lt $totalBatches) {
                                                $batchNr++
                                            }

                                            # Execute the batch
                                            try {
                                                $progressParams = @{
                                                    StepNumber = $batchNr
                                                    TotalSteps = $totalBatches
                                                    Activity   = "Masking $($data.Count) rows in $($tableobject.Schema).$($tableobject.Name).$($columnobject.Name) in $($dbName) on $instance"
                                                    Message    = "Executing Batch $batchNr/$totalBatches"
                                                }

                                                Write-ProgressHelper @progressParams

                                                Write-Message -Level Verbose -Message "Executing batch $batchNr/$totalBatches"

                                                $queryParams = @{
                                                    SqlInstance     = $instance
                                                    SqlCredential   = $SqlCredential
                                                    Database        = $db.Name
                                                    Query           = $stringBuilder.ToString()
                                                    EnableException = $EnableException
                                                    QueryTimeout    = $CommandTimeout
                                                }

                                                Invoke-DbaQuery @queryParams
                                            } catch {
                                                $maskingErrorFlag = $true
                                                Stop-Function -Message "Error updating $($tableobject.Schema).$($tableobject.Name): $_ `n$($stringBuilder.ToString())" -Target $stringBuilder.ToString() -Continue -ErrorRecord $_
                                            }

                                            $null = $stringBuilder.Clear()
                                            $batchRowNr = 0
                                        }
                                    }

                                    if ($stringBuilder.Length -ge 1) {
                                        if ($batchNr -lt $totalBatches) {
                                            $batchNr++
                                        }

                                        try {
                                            $progressParams = @{
                                                StepNumber = $batchNr
                                                TotalSteps = $totalBatches
                                                Activity   = "Masking $($data.Count) rows in $($tableobject.Schema).$($tableobject.Name) in $($dbName) on $instance"
                                                Message    = "Executing Batch $batchNr/$totalBatches"
                                            }

                                            Write-ProgressHelper @progressParams

                                            Write-Message -Level Verbose -Message "Executing batch $batchNr/$totalBatches"

                                            $queryParams = @{
                                                SqlInstance     = $instance
                                                SqlCredential   = $SqlCredential
                                                Database        = $db.Name
                                                Query           = $stringBuilder.ToString()
                                                EnableException = $EnableException
                                                QueryTimeout    = $CommandTimeout
                                            }

                                            Invoke-DbaQuery @queryParams
                                        } catch {
                                            $maskingErrorFlag = $true
                                            Stop-Function -Message "Error updating $($tableobject.Schema).$($tableobject.Name): $_`n$($stringBuilder.ToString())" -Target $stringBuilder.ToString() -Continue -ErrorRecord $_
                                        }
                                    }
                                }
                            }
                        }

                        $null = $stringBuilder.Clear()

                        # Go through the actions
                        if ($columnsWithActions.Count -ge 1) {
                            foreach ($columnObject in $columnsWithActions) {
                                Write-Message -Level Verbose -Message "Processing action for [$($columnObject.Name)]"

                                [bool]$validAction = $true

                                $columnAction = $columnobject.Action

                                $query = "UPDATE [$($tableobject.Schema)].[$($tableobject.Name)] SET [$($columnObject.Name)] = "

                                if ($columnAction.Category -eq 'DateTime') {
                                    switch ($columnAction.Type) {
                                        "Add" {
                                            $query += "DATEADD($($columnAction.SubCategory), $($columnAction.Value), [$($columnObject.Name)]);"
                                        }
                                        "Subtract" {
                                            $query += "DATEADD($($columnAction.SubCategory), - $($columnAction.Value), [$($columnObject.Name)]);"
                                        }
                                        default {
                                            $validAction = $false
                                        }
                                    }
                                } elseif ($columnAction.Category -eq 'Number') {
                                    switch ($columnAction.Type) {
                                        "Add" {
                                            $query += "[$($columnObject.Name)] + $($columnAction.Value);"
                                        }
                                        "Divide" {
                                            $query += "[$($columnObject.Name)] / $($columnAction.Value);"
                                        }
                                        "Multiply" {
                                            $query += "[$($columnObject.Name)] * $($columnAction.Value);"
                                        }
                                        "Subtract" {
                                            $query += "[$($columnObject.Name)] - $($columnAction.Value);"
                                        }
                                        default {
                                            $validAction = $false
                                        }
                                    }
                                } elseif ($columnAction.Category -eq 'Column') {
                                    switch ($columnAction.Type) {
                                        "Set" {
                                            if ($columnobject.ColumnType -like '*int*' -or $columnobject.ColumnType -in 'bit', 'bool', 'decimal', 'numeric', 'float', 'money', 'smallmoney', 'real') {
                                                $query += "$($columnAction.Value)"
                                            } elseif ($columnobject.ColumnType -in '*date*', 'time', 'uniqueidentifier') {
                                                $query += "'$($columnAction.Value)'"
                                            } else {
                                                $query += "'$($columnAction.Value)'"
                                            }
                                        }
                                        "Nullify" {
                                            if ($columnobject.Nullable) {
                                                $query += "NULL"
                                            } else {
                                                $validAction = $false
                                            }
                                        }
                                        default {
                                            $validAction = $false
                                        }
                                    }
                                }
                                # Add the query to the rest
                                if ($validAction) {
                                    $null = $stringBuilder.AppendLine($query)
                                }
                            }

                            try {
                                if ($stringBuilder.Length -ge 1) {
                                    Invoke-DbaQuery -SqlInstance $instance -SqlCredential $SqlCredential -Database $db.Name -Query $stringBuilder.ToString() -EnableException
                                }
                            } catch {
                                $stringBuilder.ToString()
                                Stop-Function -Message "Error updating $($tableobject.Schema).$($tableobject.Name): $_" -Target $stringBuilder -Continue -ErrorRecord $_
                            }

                            $null = $stringBuilder.Clear()
                        }

                        # Go through the composites
                        if ($columnsWithComposites.Count -ge 1) {
                            foreach ($columnObject in $columnsWithComposites) {
                                Write-Message -Level Verbose -Message "Processing composite for [$($columnObject.Name)]"

                                $compositeItems = @()

                                foreach ($columnComposite in $columnObject.Composite) {
                                    if ($columnComposite.Type -eq 'Column') {
                                        $compositeItems += "[$($columnComposite.Value)]"
                                    } elseif ($columnComposite.Type -eq 'Static') {
                                        $compositeItems += "'$($columnComposite.Value)'"
                                    } elseif ($columnComposite.Type -in $supportedFakerMaskingTypes) {
                                        try {
                                            $newValue = $null

                                            if ($columnobject.SubType -in $supportedDataTypes) {
                                                $newValueParams = @{
                                                    DataType        = $columnobject.SubType
                                                    CharacterString = $charstring
                                                    Min             = $columnComposite.Min
                                                    Max             = $columnComposite.Max
                                                    Locale          = $Locale
                                                }

                                                $newValue = Get-DbaRandomizedValue @newValueParams
                                            } else {
                                                $newValueParams = @{
                                                    RandomizerType    = $columnobject.MaskingType
                                                    RandomizerSubtype = $columnobject.SubType
                                                    Min               = $min
                                                    Max               = $max
                                                    CharacterString   = $charstring
                                                    Format            = $columnobject.Format
                                                    Separator         = $columnobject.Separator
                                                    Locale            = $Locale
                                                }

                                                $newValue = Get-DbaRandomizedValue @newValueParams
                                            }
                                        } catch {
                                            Stop-Function -Message "Failure" -Target $faker -Continue -ErrorRecord $_
                                        }

                                        if ($columnobject.ColumnType -match 'int') {
                                            $compositeItems += " $newValue"
                                        } elseif ($columnobject.ColumnType -in 'bit', 'bool') {
                                            if ($columnValue) {
                                                $compositeItems += "1"
                                            } else {
                                                $compositeItems += "0"
                                            }
                                        } else {
                                            $newValue = ($newValue).Tostring().Replace("'", "''")
                                            $compositeItems += "'$newValue'"
                                        }
                                    } else {
                                        $compositeItems += ""
                                    }
                                }

                                $compositeItemsUpdated = $compositeItems | ForEach-Object { $_ = "ISNULL($($_), '')"; $_ }

                                $null = $stringBuilder.AppendLine("UPDATE [$($tableobject.Schema)].[$($tableobject.Name)] SET [$($columnObject.Name)] = $($compositeItemsUpdated -join ' + ')")
                            }

                            try {
                                $stringBuilder.ToString()
                                Invoke-DbaQuery -SqlInstance $instance -SqlCredential $SqlCredential -Database $db.Name -Query $stringBuilder.ToString() -EnableException
                            } catch {
                                Stop-Function -Message "Error updating $($tableobject.Schema).$($tableobject.Name): $_" -Target $stringBuilder -Continue -ErrorRecord $_
                            }

                            $null = $stringBuilder.Clear()
                        }

                        # Clean up the masking index
                        try {
                            # Refresh the indexes to make sure to have the latest list
                            $dbTable.Indexes.Refresh()

                            # Check if the index is there
                            if ($dbTable.Indexes.Name -contains $maskingIndexName) {
                                Write-Message -Level verbose -Message "Removing identity index from table [$($dbTable.Schema)].[$($dbTable.Name)]"
                                $dbTable.Indexes[$($maskingIndexName)].Drop()
                            }
                        } catch {
                            Stop-Function -Message "Could not remove identity index from table [$($dbTable.Schema)].[$($dbTable.Name)]" -Continue
                        }

                        # Clean up the identity column
                        if ($cleanupIdentityColumn) {
                            try {
                                Write-Message -Level Verbose -Message "Removing identity column [$($identityColumn)] from table [$($dbTable.Schema)].[$($dbTable.Name)]"

                                $query = "ALTER TABLE [$($dbTable.Schema)].[$($dbTable.Name)] DROP COLUMN [$($identityColumn)]"

                                Invoke-DbaQuery -SqlInstance $instance -SqlCredential $SqlCredential -Database $db.Name -Query $query -EnableException
                            } catch {
                                Stop-Function -Message "Could not remove identity column from table [$($dbTable.Schema)].[$($dbTable.Name)]" -Continue
                            }
                        }

                        # Return the masking results
                        if ($maskingErrorFlag) {
                            $maskingStatus = "Failed"
                        } else {
                            $maskingStatus = "Successful"
                        }

                        [pscustomobject]@{
                            ComputerName = $db.Parent.ComputerName
                            InstanceName = $db.Parent.ServiceName
                            SqlInstance  = $db.Parent.DomainInstanceName
                            Database     = $dbName
                            Schema       = $tableobject.Schema
                            Table        = $tableobject.Name
                            Columns      = $tableobject.Columns.Name
                            Rows         = $($data.Count)
                            Elapsed      = [prettytimespan]$elapsed.Elapsed
                            Status       = $maskingStatus
                        }


                        # Reset time
                        $null = $elapsed.Reset()
                    }

                    # Cleanup
                    if ($uniqueDataTableName) {
                        Write-Message -Message "Cleaning up unique temporary table '$uniqueDataTableName'" -Level verbose
                        $query = "DROP TABLE [$($uniqueDataTableName)];"
                        try {
                            $null = Invoke-DbaQuery -SqlInstance $server -SqlCredential $SqlCredential -Database 'tempdb' -Query $query -EnableException
                        } catch {
                            Stop-Function -Message "Could not clean up unique values table '$uniqueDataTableName'" -Target $uniqueDataTableName -ErrorRecord $_
                        }
                    }
                }
                #endregion for each table

                # Export the dictionary when needed
                if ($DictionaryExportPath) {
                    try {
                        # Handle dictionary
                        $query = "SELECT [ValueKey], [NewValue] FROM dbo.DeterministicValues"
                        [array]$dictResult = $server.Databases['tempdb'].Query($query)

                        if ($dictResult.Count -ge 1) {
                            Write-Message -Message "Writing dictionary for $($db.Name)" -Level Verbose

                            # Check if the output directory already exists
                            if (-not (Test-Path -Path $DictionaryExportPath)) {
                                $null = New-Item -Path $DictionaryExportPath -ItemType Directory
                            }

                            # Of course with Linux we need to change the slashes
                            if (-not $script:isWindows) {
                                $dictionaryFileName = $dictionaryFileName.Replace("\", "/")
                            }

                            # Setup the file paths
                            $filenamepart = $server.Name.Replace('\', '$').Replace('TCP:', '').Replace(',', '.')
                            $dictionaryFileName = "$DictionaryExportPath\$($filenamepart).$($db.Name).Dictionary.csv"

                            # Export dictionary
                            $null = $dictResult | Export-Csv -Path $dictionaryFileName -NoTypeInformation

                            Get-ChildItem -Path $dictionaryFileName
                        } else {
                            Write-Message -Level Verbose -Message "No values to export as a dictionary"
                        }
                    } catch {
                        Stop-Function -Message "Something went wrong writing the dictionary to the $DictionaryExportPath" -Target $DictionaryExportPath -Continue -ErrorRecord $_
                    }
                }
            } # End foreach database

            # Do some cleanup
            $null = $server.Databases['tempdb'].Tables.Refresh()

            if ($server.Databases['tempdb'].Tables.Name -contains 'DeterministicValues') {
                $query = "DROP TABLE dbo.DeterministicValues"

                try {
                    Write-Message -Level Verbose -Message "Cleaning up deterministic values table"
                    $null = $server.Databases['tempdb'].Query($query)
                } catch {
                    Stop-Function -Message "Could not remove deterministic value table" -ErrorRecord $_
                }
            }

        } # End foreach instance
    } # End process block
} # End
# SIG # Begin signature block
# MIIjYAYJKoZIhvcNAQcCoIIjUTCCI00CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCBitwGXyH0hVYAw
# U+lb/LrIBRuJU9I90oLG1sD4+qvPkKCCHVkwggUaMIIEAqADAgECAhADBbuGIbCh
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
# BgorBgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCCkaj1y/zvKYGj4per0rk1Wa+Hn
# gOKBJk4nIOLqZSsRFzANBgkqhkiG9w0BAQEFAASCAQB4ZPbH818lM1KSub7OXUzM
# s8hV0YKdj7Blrc97CtrTwrXh/VAxjQJsZsnf45A2pxwooPXwF/M5zYzXToySLeWH
# Ouv46cUXe1geISz/xEfu94CvHeH5g+hlkEpZHHP1eT0OkL6jAC4Rw+NmJekiS314
# nEBuA4UPEFNoDzfT9AQPh0oqtXugZTpBsD7e06LunjpQOD82e/BtKRU2JS8fX77k
# 7UvbhFstwU7WhDRgDdlsU3M8ikWg0v0v0UTNePgVFcbRFILIWcOATmgUnK9oQRbx
# NeIMXa9j86OY5/X3WRjPdJu9RzS29eW7hvCohgtssFsJJOcYTAvHfWSpq/G4JKyZ
# oYIDIDCCAxwGCSqGSIb3DQEJBjGCAw0wggMJAgEBMHcwYzELMAkGA1UEBhMCVVMx
# FzAVBgNVBAoTDkRpZ2lDZXJ0LCBJbmMuMTswOQYDVQQDEzJEaWdpQ2VydCBUcnVz
# dGVkIEc0IFJTQTQwOTYgU0hBMjU2IFRpbWVTdGFtcGluZyBDQQIQDE1pckuU+jwq
# Sj0pB4A9WjANBglghkgBZQMEAgEFAKBpMBgGCSqGSIb3DQEJAzELBgkqhkiG9w0B
# BwEwHAYJKoZIhvcNAQkFMQ8XDTIyMTExNzA4NTY0MlowLwYJKoZIhvcNAQkEMSIE
# IM9Dx5c5lD7JgjCSYomcqpk5m27a9jpFrhbvQoTLBmNbMA0GCSqGSIb3DQEBAQUA
# BIICAAoBBReJZzCNnwee7qPUjlmV2QytTdJZIlSvY9W38qYpm0p5h5pmazQsuvuI
# sKHabelzBxbxfhgo0CVlFCBjMMQ1rR2qZVz1hk42nvbXmNy4kZieprz7zP9WWlFr
# EFI0mNr7sP5eJDYbLQA2r95/505iUK+EpRxt4k6NfHdwY0oFmq2t2FDuZ4DSMl29
# 2cqPyc4wR9oGY+zzxMBqTucdH5bbuhDUs9VN86YKLQFvBujQAEKRBbBC/I84G2Ha
# WmNVxKY8R627TCkHe7cB+ubAF8Q0UVjggGp8V/iwI9jd/+70sJj+NHyAKr9YJlvu
# 7ofkUEedoIvRiPQc3nS5IqZAcafVnzsRZE6Ur05OZf7nNEI281Oy+vhk0jYvAAEj
# C8e9DHQn931q/Aw2yIpXRjiuVJXfxXo80y8J9OKjIPjK18NvUKv7xG70gjNuZHHZ
# RlTpAJy9O4ONprVYkBRTA5mbVPlU5bblLv8eCKqRjctRztOBSw0HqlQNJJoBxQUB
# s9z35PmBR5N16iVkEe+7vsWH7SvA4rofjcatuP1Z0eXJfeWAx0PYEGT8bqiQSigA
# ebvZxnf/rZxPQaUIhIGr+NH4Q4XRW1MUDC/WWPz8xmUsY4qkYB4t+Wc/JK8bK7Y4
# BGoRrOedZm6Amrkhw3R2ydEjO/TIcW5yUQgWXUnag6axlhEq
# SIG # End signature block
