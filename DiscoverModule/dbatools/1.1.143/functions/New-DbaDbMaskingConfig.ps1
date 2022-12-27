function New-DbaDbMaskingConfig {
    <#
    .SYNOPSIS
        Generates a new data masking configuration file to be used with Invoke-DbaDbDataMasking

    .DESCRIPTION
        Generates a new data masking configuration file. This file is important to apply any data masking to the data in a database.

        Note that the following column and data types are not currently supported:
        Identity
        ForeignKey
        Computed
        Hierarchyid
        Geography
        Geometry
        Xml

        Read more here:
        https://sachabarbs.wordpress.com/2018/06/11/bogus-simple-fake-data-tool/
        https://github.com/bchavez/Bogus

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

    .PARAMETER Path
        Path where to save the generated JSON files.
        Th naming convention will be "servername.databasename.tables.json"

    .PARAMETER Locale
        Set the local to enable certain settings in the masking

    .PARAMETER CharacterString
        The characters to use in string data. 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789' by default

    .PARAMETER SampleCount
        Amount of rows to sample to make an assessment. The default is 100

    .PARAMETER KnownNameFilePath
        Points to a file containing the custom known names

    .PARAMETER PatternFilePath
        Points to a file containing the custom patterns

    .PARAMETER ExcludeDefaultKnownName
        Excludes the default known names

    .PARAMETER ExcludeDefaultPattern
        Excludes the default patterns

    .PARAMETER Force
        Forcefully execute commands when needed

    .PARAMETER InputObject
        Used for piping the values from Invoke-DbaDbPiiScan

    .PARAMETER WhatIf
        Shows what would happen if the command were to run. No actions are actually performed.

    .PARAMETER Confirm
        Prompts you for confirmation before executing any changing operations within the command.

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
        https://dbatools.io/New-DbaDbMaskingConfig

    .EXAMPLE
        New-DbaDbMaskingConfig -SqlInstance SQLDB1 -Database DB1 -Path C:\Temp\clone

        Process all tables and columns for database DB1 on instance SQLDB1

    .EXAMPLE
        New-DbaDbMaskingConfig -SqlInstance SQLDB1 -Database DB1 -Table Customer -Path C:\Temp\clone

        Process only table Customer with all the columns

    .EXAMPLE
        New-DbaDbMaskingConfig -SqlInstance SQLDB1 -Database DB1 -Table Customer -Column City -Path C:\Temp\clone

        Process only table Customer and only the column named "City"
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = "Low")]
    param (
        [DbaInstanceParameter[]]$SqlInstance,
        [PSCredential]$SqlCredential,
        [string[]]$Database,
        [string[]]$Table,
        [string[]]$Column,
        [parameter(Mandatory)]
        [string]$Path,
        [string]$Locale = 'en',
        [string]$CharacterString = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789',
        [int]$SampleCount = 100,
        [string]$KnownNameFilePath,
        [string]$PatternFilePath ,
        [switch]$ExcludeDefaultKnownName,
        [switch]$ExcludeDefaultPattern,
        [switch]$Force,
        [parameter(ValueFromPipeline = $true)]
        [object[]]$InputObject,
        [switch]$EnableException
    )
    begin {

        # Initialize the arrays
        $knownNames = @()
        $patterns = @()

        # Get the known names
        if (-not $ExcludeDefaultKnownName) {
            try {
                $knownNameFilePath = Resolve-Path -Path "$script:PSModuleRoot\bin\datamasking\pii-knownnames.json"
                $knownNames += Get-Content -Path $knownNameFilePath -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
            } catch {
                Stop-Function -Message "Couldn't parse known names file" -ErrorRecord $_
                return
            }
        }

        # Get the patterns
        if (-not $ExcludeDefaultPattern) {
            try {
                $patternFilePath = Resolve-Path -Path "$script:PSModuleRoot\bin\datamasking\pii-patterns.json"
                $patterns = Get-Content -Path $patternFilePath -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
            } catch {
                Stop-Function -Message "Couldn't parse pattern file" -ErrorRecord $_
                return
            }
        }

        # Get custom known names and patterns
        if ($KnownNameFilePath) {
            if (Test-Path -Path $KnownNameFilePath) {
                try {
                    $knownNames += Get-Content -Path $KnownNameFilePath -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
                } catch {
                    Stop-Function -Message "Couldn't parse known types file" -ErrorRecord $_ -Target $KnownNameFilePath
                    return
                }
            } else {
                Stop-Function -Message "Couldn't not find known names file" -Target $KnownNameFilePath
            }
        }

        if ($PatternFilePath ) {
            if (Test-Path -Path $PatternFilePath ) {
                try {
                    $patterns += Get-Content -Path $PatternFilePath  -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
                } catch {
                    Stop-Function -Message "Couldn't parse patterns file" -ErrorRecord $_ -Target $PatternFilePath
                    return
                }
            } else {
                Stop-Function -Message "Couldn't not find patterns file" -Target $PatternFilePath
            }
        }

        # Check if the Path is accessible
        if (-not (Test-Path -Path $Path)) {
            try {
                $null = New-Item -Path $Path -ItemType Directory -Force:$Force
            } catch {
                Stop-Function -Message "Could not create Path directory" -ErrorRecord $_ -Target $Path
            }
        } else {
            if ((Get-Item $path) -isnot [System.IO.DirectoryInfo]) {
                Stop-Function -Message "$Path is not a directory"
            }
        }

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

        $maskingconfig = @()
    }
    process {
        if (Test-FunctionInterrupt) { return }

        if ($InputObject) {
            $searchArray = @()
            $searchArray += $InputObject | Select-Object ComputerName, InstanceName, SqlInstance, Database, Schema, Table, Column
        }

        if ($SqlInstance) {
            $databases += Get-DbaDatabase -SqlInstance $SqlInstance -SqlCredential $SqlCredential -Database $Database
        }

        foreach ($db in $databases) {
            $server = $db.Parent
            $tables = @()

            # Get the tables
            if ($Table) {
                $tablecollection = $db.Tables | Where-Object Name -in $Table
            } else {
                $tablecollection = $db.Tables
            }

            if ($tablecollection.Count -lt 1) {
                Stop-Function -Message "The database does not contain any tables" -Target $db -Continue
            }

            # Loop through the tables
            foreach ($tableobject in $tablecollection) {
                Write-Message -Message "Processing table [$($tableobject.Schema)].[$($tableobject.Name)]" -Level Verbose

                $hasUniqueIndex = $false

                if ($tableobject.Indexes.IsUnique) {
                    $hasUniqueIndex = $true
                }

                $columns = @()

                # Get the columns
                if ($Column) {
                    [array]$columncollection = $tableobject.Columns | Where-Object Name -in $Column
                } else {
                    [array]$columncollection = $tableobject.Columns
                }

                foreach ($columnobject in $columncollection) {
                    $result = $minValue = $maxValue = $null

                    # Skip incompatible columns
                    if ($columnobject.Identity) {
                        Write-Message -Level Verbose -Message "Skipping $columnobject because it is an identity column"
                        continue
                    }

                    if ($columnobject.IsForeignKey) {
                        Write-Message -Level Verbose -Message "Skipping $columnobject because it is a foreign key"
                        continue
                    }

                    if ($columnobject.Computed) {
                        Write-Message -Level Verbose -Message "Skipping $columnobject because it is a computed column"
                        continue
                    }

                    if ($server.VersionMajor -ge 13 -and $columnobject.GeneratedAlwaysType -ne 'None') {
                        Write-Message -Level Verbose -Message "Skipping $columnobject because it is a computed column for temporal tables"
                        continue
                    }

                    if ($columnobject.DataType.Name -notin $supportedDataTypes) {
                        Write-Message -Level Verbose -Message "Skipping $columnobject because it is not a supported data type"
                        continue
                    }

                    if ($columnobject.DataType.SqlDataType.ToString().ToLowerInvariant() -eq 'xml') {
                        Write-Message -Level Verbose -Message "Skipping $columnobject because it is a xml column"
                        continue
                    }

                    $searchObject = [pscustomobject]@{
                        ComputerName = $db.Parent.ComputerName
                        InstanceName = $db.Parent.ServiceName
                        SqlInstance  = $db.Parent.DomainInstanceName
                        Database     = $db.Name
                        Schema       = $tableobject.Schema
                        Table        = $tableobject.Name
                        Column       = $columnobject.Name
                    }

                    if ($columnobject.Datatype.Name -in 'date', 'datetime', 'datetime2', 'smalldatetime', 'time') {
                        $columnLength = $columnobject.Datatype.NumericScale
                    } else {
                        $columnLength = $columnobject.Datatype.MaximumLength
                    }

                    $columnType = $columnobject.DataType.Name

                    switch ($columnType) {
                        "bigint" {
                            $minValue = 1
                            $maxValue = 9223372036854775807
                        }
                        { $_ -in "char", "nchar", "nvarchar", "varchar" } {
                            if ($columnLength -eq -1) {
                                if ($_ -in "char", "varchar") {
                                    $minValue = 1
                                    $maxValue = 8000
                                } elseif ($_ -in "nchar", "nvarchar") {
                                    $minValue = 1
                                    $maxValue = 4000
                                }
                            } else {
                                $minValue = [int]($columnLength / 2)
                                $maxValue = $columnLength
                            }
                        }
                        "date" { $maxValue = $null }
                        "datetime" { $maxValue = $null }
                        "datetime2" { $maxValue = $null }
                        "decimal" {
                            $minValue = 1.1
                            $maxValue = $null
                        }
                        "float" {
                            $minValue = 1.1
                            $maxValue = $null
                        }
                        "int" {
                            $minValue = 1
                            $maxValue = 2147483647
                        }
                        "money" {
                            $minValue = 1.0
                            $maxValue = 922337203685477.5807
                        }
                        "smallint" {
                            $minValue = 1
                            $maxValue = 32767
                        }
                        "smalldatetime" {
                            $maxValue = $null
                        }
                        "text" {
                            $minValue = 10
                            $maxValue = 2147483647
                        }
                        "time" {
                            $maxValue = $null
                        }
                        "tinyint" {
                            $minValue = 1
                            $maxValue = 255
                        }
                        "varbinary" {
                            $maxValue = $columnLength
                        }
                        "userdefineddatatype" {
                            if ($columnLength -eq 1) {
                                $maxValue = $columnLength
                            } else {
                                $minValue = [int]($columnLength / 2)
                                $maxValue = $columnLength
                            }
                        }
                        default {
                            $minValue = [int]($columnLength / 2)
                            $maxValue = $columnLength
                        }
                    }

                    if ($searchArray -contains $searchObject) {
                        $result = $InputObject | Where-Object { $_.Database -eq $searchObject.Name -and $_.Schema -eq $searchObject.Schema -and $_.Table -eq $searchObject.Name -and $_.Column -eq $searchObject.Name }
                    } else {

                        if ($columnobject.InPrimaryKey -and $columnobject.DataType.SqlDataType.ToString().ToLowerInvariant() -notmatch 'date') {
                            $minValue = 2
                        }

                        if ($columnobject.DataType.Name -eq "geography") {
                            # Add the results
                            $result = [pscustomobject]@{
                                ComputerName   = $db.Parent.ComputerName
                                InstanceName   = $db.Parent.ServiceName
                                SqlInstance    = $db.Parent.DomainInstanceName
                                Database       = $db.Name
                                Schema         = $tableobject.Schema
                                Table          = $tableobject.Name
                                Column         = $columnobject.Name
                                "PII-Category" = "Location"
                                "PII-Name"     = "Geography"
                                FoundWith      = "DataType"
                                MaskingType    = "Random"
                                MaskingSubType = "Decimal"
                            }
                        } else {
                            if ($knownNames.Count -ge 1) {
                                # Go through the first check to see if any column is found with a known name
                                foreach ($knownName in $knownNames) {
                                    foreach ($pattern in $knownName.Pattern) {
                                        if ($null -eq $result -and $columnobject.Name -match $pattern ) {
                                            # Add the results
                                            $result = [pscustomobject]@{
                                                ComputerName   = $db.Parent.ComputerName
                                                InstanceName   = $db.Parent.ServiceName
                                                SqlInstance    = $db.Parent.DomainInstanceName
                                                Database       = $db.Name
                                                Schema         = $tableobject.Schema
                                                Table          = $tableobject.Name
                                                Column         = $columnobject.Name
                                                "PII-Category" = $knownName.Category
                                                "PII-Name"     = $knownName.Name
                                                FoundWith      = "KnownName"
                                                MaskingType    = $knownName.MaskingType
                                                MaskingSubType = $knownName.MaskingSubType
                                            }
                                        }
                                    }
                                }
                                $knownName = $null
                            } else {
                                Write-Message -Level Verbose -Message "No known names found to perform check on"
                            }

                            # Go through the second check to see if any column is found with a known type
                            if ($patterns.Count -ge 1) {
                                if ($null -eq $result) {
                                    # Setup the query
                                    $query = "SELECT TOP($SampleCount) [$($columnobject.Name)] FROM [$($tableobject.Schema)].[$($tableobject.Name)]"

                                    # Get the data
                                    $dataset = @()

                                    try {
                                        $dataset += Invoke-DbaQuery -SqlInstance $SqlInstance -SqlCredential $SqlCredential -Database $db.Name -Query $query -EnableException
                                    } catch {
                                        $errormessage = $_.Exception.Message.ToString()
                                        Stop-Function -Message "Error executing query [$($tableobject.Schema)].[$($tableobject.Name)]: $errormessage" -Target $updatequery -Continue -ErrorRecord $_
                                    }

                                    # Check if there is any data
                                    if ($dataset.Count -ge 1) {

                                        # Loop through the patterns
                                        foreach ($patternobject in $patterns) {

                                            # If there is a result from the match
                                            if ($null -eq $result -and $dataset.$($columnobject.Name) -match $patternobject.Pattern) {
                                                # Add the results
                                                $result = [pscustomobject]@{
                                                    ComputerName   = $db.Parent.ComputerName
                                                    InstanceName   = $db.Parent.ServiceName
                                                    SqlInstance    = $db.Parent.DomainInstanceName
                                                    Database       = $db.Name
                                                    Schema         = $tableobject.Schema
                                                    Table          = $tableobject.Name
                                                    Column         = $columnobject.Name
                                                    "PII-Category" = $patternobject.Category
                                                    "PII-Name"     = $patternobject.Name
                                                    FoundWith      = "Pattern"
                                                    MaskingType    = $patternobject.MaskingType
                                                    MaskingSubType = $patternobject.MaskingSubType
                                                }
                                            }
                                            $patternobject = $null
                                        }
                                    } else {
                                        Write-Message -Message "Table $($tableobject.Name) does not contain any rows" -Level Verbose
                                    }
                                }
                            } else {
                                Write-Message -Level Verbose -Message "No patterns found to perform check on"
                            }
                        }
                    }

                    if ($result) {
                        $columns += [PSCustomObject]@{
                            Name            = $columnobject.Name
                            ColumnType      = $columnType
                            CharacterString = $( if ($result.MaskingType -in "String", "String2") { $CharacterString } else { $null } )
                            MinValue        = $minValue
                            MaxValue        = $maxValue
                            MaskingType     = $result.MaskingType
                            SubType         = $result.MaskingSubType
                            Format          = $null
                            Separator       = $null
                            Deterministic   = $false
                            Nullable        = $columnobject.Nullable
                            KeepNull        = $true
                            Composite       = $null
                            Action          = $null
                            StaticValue     = $null
                        }
                    } else {
                        $type = "Random"

                        switch ($columnType) {
                            { $_ -in "bit", "bool" } { $subType = "Bool" }
                            "bigint" { $subType = "Number" }
                            { $_ -in "char", "nchar", "nvarchar", "varchar" } { $subType = "String2" }
                            "date" {
                                $type = "Date"
                                $subType = "Past"
                            }
                            "datetime" {
                                $type = "Date"
                                $subType = "Past"
                            }
                            "datetime2" {
                                $type = "Date"
                                $subType = "Past"
                            }
                            "decimal" { $subType = "Decimal" }
                            "float" { $subType = "Float" }
                            "int" { $subType = "Number" }
                            "money" {
                                $type = "Commerce"
                                $subType = "Price"
                            }
                            "smallint" { $subType = "Number" }
                            "smalldatetime" { $subType = "Date" }
                            "text" { $subType = "String" }
                            "time" {
                                $type = "Date"
                                $subType = "Past"
                            }
                            "tinyint" { $subType = "Number" }
                            "varbinary" { $subType = "Byte" }
                            "userdefineddatatype" {
                                if ($columnLength -eq 1) {
                                    $subType = "Bool"
                                } else {
                                    $subType = "String2"
                                }
                            }
                            "uniqueidentifier" {
                                $subType = "Guid"
                            }
                            default {
                                $subType = "String2"
                            }
                        }

                        $columns += [PSCustomObject]@{
                            Name            = $columnobject.Name
                            ColumnType      = $columnType
                            CharacterString = $( if ($subType -in "String", "String2") { $CharacterString } else { $null } )
                            MinValue        = $minValue
                            MaxValue        = $maxValue
                            MaskingType     = $type
                            SubType         = $subType
                            Format          = $null
                            Separator       = $null
                            Deterministic   = $false
                            Nullable        = $columnobject.Nullable
                            KeepNull        = $true
                            Composite       = $null
                            Action          = $null
                            StaticValue     = $null
                        }
                    }
                }

                # Check if something needs to be generated
                if ($columns) {
                    $tables += [PSCustomObject]@{
                        Name           = $tableobject.Name
                        Schema         = $tableobject.Schema
                        Columns        = $columns
                        HasUniqueIndex = $hasUniqueIndex
                        FilterQuery    = $null
                    }
                } else {
                    Write-Message -Message "No columns match for masking in table $($tableobject.Name)" -Level Verbose
                }
            }

            # Check if something needs to be generated
            if ($tables) {
                $maskingconfig += [PSCustomObject]@{
                    Name   = $db.Name
                    Type   = "DataMaskingConfiguration"
                    Tables = $tables
                }
            } else {
                Write-Message -Message "No columns match for masking in table $($tableobject.Name)" -Level Verbose
            }

            # Write the data to the Path
            if ($maskingconfig) {
                Write-Message -Message "Writing masking config" -Level Verbose
                try {
                    $filenamepart = $server.Name.Replace('\', '$').Replace('TCP:', '').Replace(',', '.')

                    if ($Table) {
                        $temppath = Join-Path -Path $Path -ChildPath "$($filenamepart).$($db.Name).$($Table -join '-').DataMaskingConfig.json"
                    } else {
                        $temppath = Join-Path -Path $Path -ChildPath "$($filenamepart).$($db.Name).DataMaskingConfig.json"
                    }

                    if (-not $script:isWindows) {
                        $temppath = $temppath.Replace("\", "/")
                    }

                    Set-Content -Path $temppath -Value ($maskingconfig | ConvertTo-Json -Depth 5)
                    Get-ChildItem -Path $temppath
                } catch {
                    Stop-Function -Message "Something went wrong writing the results to the '$Path'" -Target $Path -Continue -ErrorRecord $_
                }
            } else {
                Write-Message -Message "No tables to save for database $($db.Name) on $($server.Name)" -Level Verbose
            }
        }
    }
}
# SIG # Begin signature block
# MIIjYAYJKoZIhvcNAQcCoIIjUTCCI00CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCDe2aBBRID4+byP
# dScyTX+LrrX3NlhV2//Sg3eHlhnU4KCCHVkwggUaMIIEAqADAgECAhADBbuGIbCh
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
# BgorBgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCBOGArBMn7/uHGCTh3YG/NXG3u1
# fqVzGEorvShwr47RqDANBgkqhkiG9w0BAQEFAASCAQBwjoyKrMtFvRJasNhALnCx
# FJ7VgN1o8ouN/Ey3/W0ocT4qQfbXBlaD4vPJBHu3U+ai/Vev4g8KWlwZWv008EbD
# aFKR7PBpg/j0Rm/MzAm5m+nxwLrfhy8qp21NTzZW+sa07EXwVhrUXV+QM84XyDDI
# gz2MapyPYzJwP98iwy9btvhrnoHSrhW1pMVlysYIOqCbh9eSOF0uO07XA6V2CuUH
# sx/zMWJlxi0zMeyuAOO+AlF0gy05hs6P5w/jfqkNA9m3tYMSnqsWzEHOOUoWw5dt
# ASfcnH4zo1X4Jkv/CH2PwykPIGbqkUqsCm1/7iD4dL6vXVzg+KN66gBfrkuX3NPx
# oYIDIDCCAxwGCSqGSIb3DQEJBjGCAw0wggMJAgEBMHcwYzELMAkGA1UEBhMCVVMx
# FzAVBgNVBAoTDkRpZ2lDZXJ0LCBJbmMuMTswOQYDVQQDEzJEaWdpQ2VydCBUcnVz
# dGVkIEc0IFJTQTQwOTYgU0hBMjU2IFRpbWVTdGFtcGluZyBDQQIQDE1pckuU+jwq
# Sj0pB4A9WjANBglghkgBZQMEAgEFAKBpMBgGCSqGSIb3DQEJAzELBgkqhkiG9w0B
# BwEwHAYJKoZIhvcNAQkFMQ8XDTIyMTExNzA4NTY1NlowLwYJKoZIhvcNAQkEMSIE
# IAAfKZ9BuDiluqPruMCK4wOYzpvGs4AwY6R/JxyNSAK7MA0GCSqGSIb3DQEBAQUA
# BIICAAFJ1FQrRI6KBSMZffRAAA0dkhidkyo85XajU73nkBKN2BZNMqEcJJDTJE9K
# Mo91QOKFvl+HaAwVt+iTx+/GHXYqKKGma95HN8xifoeAN79sjZcOv/+ypm3Qs+0R
# GCVXBToNUoI0SvcEwbUsC9OZVe44UVngdSc/0BToZhqVcRSUEqxlTj3sw9QOPtCV
# 4RQlV6aK7YAtjDECRNR9ACXxw8wZKsHbtMDK1KOtb+8ieCUdjjZUcyJBSVhkoj5+
# v+8G9WsKKw9GUwVehmHwbl+DaIlEfY+tF+PFo5+avokvUTjE06mCBnEVwHf0YGjo
# KjvYYnf/P/K2sV3oISPZKpVOjQe2hNVSqMK8nwFUDxk/mAD87O5+u0AenBal3rS4
# 3WdOZ/cbh9wFyY+YvghhtKQp5GeEfdH40qGa3OnjS69k88dAZDa839/RnNsAA8/r
# yaOn3iDDWo24KyDwAJd+g4mLxZVNplHdkbdn4mCI3NqTpV9OGeawpTXZ13p37+B5
# skIExHP8k+YMduI2OXzabmnAavKjkGkrQ7B7qvIZVnLaJf9VQgmYlA3MHExOTejY
# AYE6CRa+do3wkR+rhN5AJOmWZNKpktrcE0bMxoLKB8Vi/xH6D4NDXOWhus8nETKx
# 0Mmqa7iNWwSQ6Z8OoxkOU2DZ+IXavlHI4zHMaTqzxUIoO+7v
# SIG # End signature block
