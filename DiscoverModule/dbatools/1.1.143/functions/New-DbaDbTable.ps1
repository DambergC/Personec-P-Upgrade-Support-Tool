function New-DbaDbTable {
    <#
    .SYNOPSIS
        Creates a new table in a database

    .DESCRIPTION
        Creates a new table in a database

   .PARAMETER SqlInstance
       The target SQL Server instance or instances.

    .PARAMETER SqlCredential
       Login to the target instance using alternative credentials. Accepts PowerShell credentials (Get-Credential).

        Windows Authentication, SQL Server Authentication, Active Directory - Password, and Active Directory - Integrated are all supported.

        For MFA support, please use Connect-DbaInstance.

    .PARAMETER Database
        The database or databases where the table will be created

    .PARAMETER Name
        The name of the table

    .PARAMETER Schema
        The schema for the table, defaults to dbo

    .PARAMETER ColumnMap
        Hashtable for easy column creation. See Examples for details

    .PARAMETER ColumnObject
        If you want to get fancy, you can build your own column objects and pass them in

    .PARAMETER InputObject
        Allows piped input from Get-DbaDatabase

    .PARAMETER AnsiNullsStatus
        No information provided by Microsoft

    .PARAMETER ChangeTrackingEnabled
        No information provided by Microsoft

    .PARAMETER DataSourceName
        No information provided by Microsoft

    .PARAMETER Durability
        No information provided by Microsoft

    .PARAMETER ExternalTableDistribution
        No information provided by Microsoft

    .PARAMETER FileFormatName
        No information provided by Microsoft

    .PARAMETER FileGroup
        No information provided by Microsoft

    .PARAMETER FileStreamFileGroup
        No information provided by Microsoft

    .PARAMETER FileStreamPartitionScheme
        No information provided by Microsoft

    .PARAMETER FileTableDirectoryName
        No information provided by Microsoft

    .PARAMETER FileTableNameColumnCollation
        No information provided by Microsoft

    .PARAMETER FileTableNamespaceEnabled
        No information provided by Microsoft

    .PARAMETER HistoryTableName
        No information provided by Microsoft

    .PARAMETER HistoryTableSchema
        No information provided by Microsoft

    .PARAMETER IsExternal
        No information provided by Microsoft

    .PARAMETER IsFileTable
        No information provided by Microsoft

    .PARAMETER IsMemoryOptimized
        No information provided by Microsoft

    .PARAMETER IsSystemVersioned
        No information provided by Microsoft

    .PARAMETER Location
        No information provided by Microsoft

    .PARAMETER LockEscalation
        No information provided by Microsoft

    .PARAMETER Owner
        No information provided by Microsoft

    .PARAMETER PartitionScheme
        No information provided by Microsoft

    .PARAMETER QuotedIdentifierStatus
        No information provided by Microsoft

    .PARAMETER RejectSampleValue
        No information provided by Microsoft

    .PARAMETER RejectType
        No information provided by Microsoft

    .PARAMETER RejectValue
        No information provided by Microsoft

    .PARAMETER RemoteDataArchiveDataMigrationState
        No information provided by Microsoft

    .PARAMETER RemoteDataArchiveEnabled
        No information provided by Microsoft

    .PARAMETER RemoteDataArchiveFilterPredicate
        No information provided by Microsoft

    .PARAMETER RemoteObjectName
        No information provided by Microsoft

    .PARAMETER RemoteSchemaName
        No information provided by Microsoft

    .PARAMETER RemoteTableName
        No information provided by Microsoft

    .PARAMETER RemoteTableProvisioned
        No information provided by Microsoft

    .PARAMETER ShardingColumnName
        No information provided by Microsoft

    .PARAMETER TextFileGroup
        No information provided by Microsoft

    .PARAMETER TrackColumnsUpdatedEnabled
        No information provided by Microsoft

    .PARAMETER HistoryRetentionPeriod
        No information provided by Microsoft

    .PARAMETER HistoryRetentionPeriodUnit
        No information provided by Microsoft

    .PARAMETER DwTableDistribution
        No information provided by Microsoft

    .PARAMETER RejectedRowLocation
        No information provided by Microsoft

    .PARAMETER OnlineHeapOperation
        No information provided by Microsoft

    .PARAMETER LowPriorityMaxDuration
        No information provided by Microsoft

    .PARAMETER DataConsistencyCheck
        No information provided by Microsoft

    .PARAMETER LowPriorityAbortAfterWait
        No information provided by Microsoft

    .PARAMETER MaximumDegreeOfParallelism
        No information provided by Microsoft

    .PARAMETER IsNode
        No information provided by Microsoft

    .PARAMETER IsEdge
        No information provided by Microsoft

    .PARAMETER IsVarDecimalStorageFormatEnabled
        No information provided by Microsoft

    .PARAMETER Passthru
        Don't create the table, just print the table script on the screen.

    .PARAMETER WhatIf
       Shows what would happen if the command were to run. No actions are actually performed.

    .PARAMETER Confirm
       Prompts you for confirmation before executing any changing operations within the command.

    .PARAMETER EnableException
       By default, when something goes wrong we try to catch it, interpret it and give you a friendly warning message.
       This avoids overwhelming you with "sea of red" exceptions, but is inconvenient because it basically disables advanced scripting.
       Using this switch turns this "nice by default" feature off and enables you to catch exceptions with your own try/catch.

    .NOTES
       Tags: table
       Author: Chrissy LeMaire (@cl)
       Website: https://dbatools.io
       Copyright: (c) 2019 by dbatools, licensed under MIT
       License: MIT https://opensource.org/licenses/MIT

    .LINK
       https://dbatools.io/New-DbaDbTable

    .EXAMPLE
       PS C:\> $col = @{
       >> Name      = 'test'
       >> Type      = 'varchar'
       >> MaxLength = 20
       >> Nullable  = $true
       >> }
       PS C:\> New-DbaDbTable -SqlInstance sql2017 -Database tempdb -Name testtable -ColumnMap $col

       Creates a new table on sql2017 in tempdb with the name testtable and one column

    .EXAMPLE
       PS C:\> $cols = @( )
       >> $cols += @{
       >>     Name              = 'Id'
       >>     Type              = 'varchar'
       >>     MaxLength         = 36
       >>     DefaultExpression = 'NEWID()'
       >> }
       >> $cols += @{
       >>     Name          = 'Since'
       >>     Type          = 'datetime2'
       >>     DefaultString = '2021-12-31'
       >> }
       PS C:\> New-DbaDbTable -SqlInstance sql2017 -Database tempdb -Name testtable -ColumnMap $cols

       Creates a new table on sql2017 in tempdb with the name testtable and two columns.
       Uses "DefaultExpression" to interpret the value "NEWID()" as an expression regardless of the data type of the column.
       Uses "DefaultString" to interpret the value "2021-12-31" as a string regardless of the data type of the column.

    .EXAMPLE
        PS C:\> # Create collection
        >> $cols = @()

        >> # Add columns to collection
        >> $cols += @{
        >>     Name      = 'testId'
        >>     Type      = 'int'
        >>     Identity  = $true
        >> }
        >> $cols += @{
        >>     Name      = 'test'
        >>     Type      = 'varchar'
        >>     MaxLength = 20
        >>     Nullable  = $true
        >> }
        >> $cols += @{
        >>     Name      = 'test2'
        >>     Type      = 'int'
        >>     Nullable  = $false
        >> }
        >> $cols += @{
        >>     Name      = 'test3'
        >>     Type      = 'decimal'
        >>     MaxLength = 9
        >>     Nullable  = $true
        >> }
        >> $cols += @{
        >>     Name      = 'test4'
        >>     Type      = 'decimal'
        >>     Precision = 8
        >>     Scale = 2
        >>     Nullable  = $false
        >> }
        >> $cols += @{
        >>     Name      = 'test5'
        >>     Type      = 'Nvarchar'
        >>     MaxLength = 50
        >>     Nullable  =  $false
        >>     Default  =  'Hello'
        >>     DefaultName = 'DF_Name_test5'
        >> }
        >> $cols += @{
        >>     Name      = 'test6'
        >>     Type      = 'int'
        >>     Nullable  =  $false
        >>     Default  =  '0'
        >> }
        >> $cols += @{
        >>     Name      = 'test7'
        >>     Type      = 'smallint'
        >>     Nullable  =  $false
        >>     Default  =  100
        >> }
        >> $cols += @{
        >>     Name      = 'test8'
        >>     Type      = 'Nchar'
        >>     MaxLength = 3
        >>     Nullable  =  $false
        >>     Default  =  'ABC'
        >> }
        >> $cols += @{
        >>     Name      = 'test9'
        >>     Type      = 'char'
        >>     MaxLength = 4
        >>     Nullable  =  $false
        >>     Default  =  'XPTO'
        >> }
        >> $cols += @{
        >>     Name      = 'test10'
        >>     Type      = 'datetime'
        >>     Nullable  =  $false
        >>     Default  =  'GETDATE()'
        >> }

        PS C:\> New-DbaDbTable -SqlInstance sql2017 -Database tempdb -Name testtable -ColumnMap $cols

        Creates a new table on sql2017 in tempdb with the name testtable and ten columns.
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Low')]
    param (
        [DbaInstanceParameter[]]$SqlInstance,
        [PSCredential]$SqlCredential,
        [String[]]$Database,
        [String]$Name,
        [String]$Schema = "dbo",
        [hashtable[]]$ColumnMap,
        [Microsoft.SqlServer.Management.Smo.Column[]]$ColumnObject,
        [Switch]$AnsiNullsStatus,
        [Switch]$ChangeTrackingEnabled,
        [String]$DataSourceName,
        [Microsoft.SqlServer.Management.Smo.DurabilityType]$Durability,
        [Microsoft.SqlServer.Management.Smo.ExternalTableDistributionType]$ExternalTableDistribution,
        [String]$FileFormatName,
        [String]$FileGroup,
        [String]$FileStreamFileGroup,
        [String]$FileStreamPartitionScheme,
        [String]$FileTableDirectoryName,
        [String]$FileTableNameColumnCollation,
        [Switch]$FileTableNamespaceEnabled,
        [String]$HistoryTableName,
        [String]$HistoryTableSchema,
        [Switch]$IsExternal,
        [Switch]$IsFileTable,
        [Switch]$IsMemoryOptimized,
        [Switch]$IsSystemVersioned,
        [String]$Location,
        [Microsoft.SqlServer.Management.Smo.LockEscalationType]$LockEscalation,
        [String]$Owner,
        [String]$PartitionScheme,
        [Switch]$QuotedIdentifierStatus,
        [Double]$RejectSampleValue,
        [Microsoft.SqlServer.Management.Smo.ExternalTableRejectType]$RejectType,
        [Double]$RejectValue,
        [Microsoft.SqlServer.Management.Smo.RemoteDataArchiveMigrationState]$RemoteDataArchiveDataMigrationState,
        [Switch]$RemoteDataArchiveEnabled,
        [String]$RemoteDataArchiveFilterPredicate,
        [String]$RemoteObjectName,
        [String]$RemoteSchemaName,
        [String]$RemoteTableName,
        [Switch]$RemoteTableProvisioned,
        [String]$ShardingColumnName,
        [String]$TextFileGroup,
        [Switch]$TrackColumnsUpdatedEnabled,
        [Int32]$HistoryRetentionPeriod,
        [Microsoft.SqlServer.Management.Smo.TemporalHistoryRetentionPeriodUnit]$HistoryRetentionPeriodUnit,
        [Microsoft.SqlServer.Management.Smo.DwTableDistributionType]$DwTableDistribution,
        [String]$RejectedRowLocation,
        [Switch]$OnlineHeapOperation,
        [Int32]$LowPriorityMaxDuration,
        [Switch]$DataConsistencyCheck,
        [Microsoft.SqlServer.Management.Smo.AbortAfterWait]$LowPriorityAbortAfterWait,
        [Int32]$MaximumDegreeOfParallelism,
        [Switch]$IsNode,
        [Switch]$IsEdge,
        [Switch]$IsVarDecimalStorageFormatEnabled,
        [switch]$Passthru,
        [parameter(ValueFromPipeline)]
        [Microsoft.SqlServer.Management.Smo.Database[]]$InputObject,
        [switch]$EnableException
    )
    begin {
        function Get-SqlType {
            param([string]$TypeName)
            switch ($TypeName) {
                'Boolean' { [Data.SqlDbType]::Bit }
                'Byte[]' { [Data.SqlDbType]::VarBinary }
                'Byte' { [Data.SQLDbType]::VarBinary }
                'Datetime' { [Data.SQLDbType]::DateTime }
                'Decimal' { [Data.SqlDbType]::Decimal }
                'Double' { [Data.SqlDbType]::Float }
                'Guid' { [Data.SqlDbType]::UniqueIdentifier }
                'Int16' { [Data.SQLDbType]::SmallInt }
                'Int32' { [Data.SQLDbType]::Int }
                'Int64' { [Data.SqlDbType]::BigInt }
                'UInt16' { [Data.SQLDbType]::SmallInt }
                'UInt32' { [Data.SQLDbType]::Int }
                'UInt64' { [Data.SqlDbType]::BigInt }
                'Single' { [Data.SqlDbType]::Decimal }
                default { [Data.SqlDbType]::VarChar }
            }
        }
    }
    process {
        if ((Test-Bound -ParameterName SqlInstance)) {
            if ((Test-Bound -Not -ParameterName Database) -or (Test-Bound -Not -ParameterName Name)) {
                Stop-Function -Message "You must specify one or more databases and one Name when using the SqlInstance parameter."
                return
            }
        }

        foreach ($instance in $SqlInstance) {
            $InputObject += Get-DbaDatabase -SqlInstance $instance -SqlCredential $SqlCredential -Database $Database
        }

        foreach ($db in $InputObject) {
            $server = $db.Parent
            if ($Pscmdlet.ShouldProcess("Creating new table [$Schema].[$Name] in $db on $server")) {
                # Test if table already exists. This ways we can drop the table if part of the creation fails.
                $existingTable = $db.tables | Where-Object { $_.Schema -eq $Schema -and $_.Name -eq $Name }
                if ($existingTable) {
                    Stop-Function -Message "Table [$Schema].[$Name] already exists in $db on $server" -Continue
                }
                try {
                    $object = New-Object -TypeName Microsoft.SqlServer.Management.Smo.Table $db, $Name, $Schema
                    $properties = $PSBoundParameters | Where-Object Key -notin 'SqlInstance', 'SqlCredential', 'Name', 'Schema', 'ColumnMap', 'ColumnObject', 'InputObject', 'EnableException', 'Passthru'

                    foreach ($prop in $properties.Key) {
                        $object.$prop = $prop
                    }

                    foreach ($column in $ColumnObject) {
                        $object.Columns.Add($column)
                    }

                    foreach ($column in $ColumnMap) {
                        $sqlDbType = [Microsoft.SqlServer.Management.Smo.SqlDataType]$($column.Type)
                        if ($sqlDbType -eq 'VarBinary' -or $sqlDbType -in @('VarChar', 'NVarChar', 'Char', 'NChar')) {
                            if ($column.MaxLength -gt 0) {
                                $dataType = New-Object Microsoft.SqlServer.Management.Smo.DataType $sqlDbType, $column.MaxLength
                            } else {
                                $sqlDbType = [Microsoft.SqlServer.Management.Smo.SqlDataType]"$(Get-SqlType $column.DataType.Name)Max"
                                $dataType = New-Object Microsoft.SqlServer.Management.Smo.DataType $sqlDbType
                            }
                        } elseif ($sqlDbType -eq 'Decimal') {
                            if ($column.MaxLength -gt 0) {
                                $dataType = New-Object Microsoft.SqlServer.Management.Smo.DataType $sqlDbType, $column.MaxLength
                            } elseif ($column.Precision -gt 0) {
                                $dataType = New-Object Microsoft.SqlServer.Management.Smo.DataType $sqlDbType, $column.Precision, $column.Scale
                            } else {
                                $sqlDbType = [Microsoft.SqlServer.Management.Smo.SqlDataType]"$(Get-SqlType $column.DataType.Name)Max"
                                $dataType = New-Object Microsoft.SqlServer.Management.Smo.DataType $sqlDbType
                            }
                        } else {
                            $dataType = New-Object Microsoft.SqlServer.Management.Smo.DataType $sqlDbType
                        }
                        $sqlColumn = New-Object Microsoft.SqlServer.Management.Smo.Column $object, $column.Name, $dataType
                        $sqlColumn.Nullable = $column.Nullable

                        if ($column.DefaultName) {
                            $dfName = $column.DefaultName
                        } else {
                            $dfName = "DF_$name`_$($column.Name)"
                        }
                        if ($column.DefaultExpression) {
                            # override the default that would add quotes to an expression
                            $sqlColumn.AddDefaultConstraint($dfName).Text = $column.DefaultExpression
                        } elseif ($column.DefaultString) {
                            # override the default that would not add quotes to a date string
                            $sqlColumn.AddDefaultConstraint($dfName).Text = "'$($column.DefaultString)'"
                        } elseif ($column.Default) {
                            if ($sqlDbType -in @('NVarchar', 'NChar', 'NVarcharMax', 'NCharMax')) {
                                $sqlColumn.AddDefaultConstraint($dfName).Text = "N'$($column.Default)'"
                            } elseif ($sqlDbType -in @('Varchar', 'Char', 'VarcharMax', 'CharMax')) {
                                $sqlColumn.AddDefaultConstraint($dfName).Text = "'$($column.Default)'"
                            } else {
                                $sqlColumn.AddDefaultConstraint($dfName).Text = $column.Default
                            }
                        }

                        if ($column.Identity) {
                            $sqlColumn.Identity = $true
                            if ($column.IdentitySeed) {
                                $sqlColumn.IdentitySeed = $column.IdentitySeed
                            }
                            if ($column.IdentityIncrement) {
                                $sqlColumn.IdentityIncrement = $column.IdentityIncrement
                            }
                        }
                        $object.Columns.Add($sqlColumn)
                    }

                    # user has specified a schema that does not exist yet
                    $schemaObject = $null
                    if (-not ($db | Get-DbaDbSchema -Schema $Schema -IncludeSystemSchemas)) {
                        Write-Message -Level Verbose -Message "Schema $Schema does not exist in $db and will be created."
                        $schemaObject = New-Object -TypeName Microsoft.SqlServer.Management.Smo.Schema $db, $Schema
                    }

                    if ($Passthru) {
                        $ScriptingOptionsObject = New-DbaScriptingOption
                        $ScriptingOptionsObject.ContinueScriptingOnError = $false
                        $ScriptingOptionsObject.DriAllConstraints = $true

                        if ($schemaObject) {
                            $schemaObject.Script($ScriptingOptionsObject)
                        }

                        $object.Script($ScriptingOptionsObject)
                    } else {
                        if ($schemaObject) {
                            $null = Invoke-Create -Object $schemaObject
                        }
                        $null = Invoke-Create -Object $object
                    }
                    $db | Get-DbaDbTable -Table "[$Schema].[$Name]"
                } catch {
                    $exception = $_
                    Write-Message -Level Verbose -Message "Failed to create table or failure while adding constraints. Will try to remove table (and schema)."
                    try {
                        $object.Refresh()
                        $object.DropIfExists()
                        if ($schemaObject) {
                            $schemaObject.Refresh()
                            $schemaObject.DropIfExists()
                        }
                    } catch {
                        Write-Message -Level Warning -Message "Failed to drop table: $_. Maybe table still exists."
                    }
                    Stop-Function -Message "Failure" -ErrorRecord $exception -Continue
                }
            }
        }
    }
}

# SIG # Begin signature block
# MIIjYAYJKoZIhvcNAQcCoIIjUTCCI00CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCCf1o37srU+sQzR
# cVYVsFQrHzqtBEqQDQ9NxEx8bWKX2qCCHVkwggUaMIIEAqADAgECAhADBbuGIbCh
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
# BgorBgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCD8z+N2tEC+VJsuES8M6qOHSjcF
# j+/V4gptvp45WBzCcTANBgkqhkiG9w0BAQEFAASCAQAh/Ld1xYWLzjdbEo3R1o6d
# 14Sftk7ub4pWXVLugptzxrl9Z5TQ8HkMSckylEP4RbNpMXqniDJINaw9Uw9LoCsQ
# CEyI9hliRIwcSXNOEO8B/eWgUMpmoArCKlL9XtK4KYkZbIZM1hgFCObIMHnMDdOE
# EdE5u9i3JXUODeC71HhIWLlLnyWkMXbpOtgfmN9qQKwZiwjEyIPA3tOkxA6Wx1YI
# uoRitvj2171AtgX6LZCpcEeRTTJ5hWRc/VDj9mDRlMLE4dqkiQyHCiEYqEK4eC0e
# ePfVn+AauIEHBmFSyHXFrhHP/NdrZDVTsnMCwSz0ZBVu21FXCafRmpE5DeGwuprq
# oYIDIDCCAxwGCSqGSIb3DQEJBjGCAw0wggMJAgEBMHcwYzELMAkGA1UEBhMCVVMx
# FzAVBgNVBAoTDkRpZ2lDZXJ0LCBJbmMuMTswOQYDVQQDEzJEaWdpQ2VydCBUcnVz
# dGVkIEc0IFJTQTQwOTYgU0hBMjU2IFRpbWVTdGFtcGluZyBDQQIQDE1pckuU+jwq
# Sj0pB4A9WjANBglghkgBZQMEAgEFAKBpMBgGCSqGSIb3DQEJAzELBgkqhkiG9w0B
# BwEwHAYJKoZIhvcNAQkFMQ8XDTIyMTExNzA4NTY1N1owLwYJKoZIhvcNAQkEMSIE
# IBs2h+5NPpxh4LWn9M1FWg7Z0aFJCuX8VyYuC+4lmEa6MA0GCSqGSIb3DQEBAQUA
# BIICAGWFQ5gux1DsG/pWxkT0s++IXOpWRdgWOOXtQi/1gUxARyrH34KbEg3rtc5x
# WrC/rqbvHnMg3pABSBw4ubVSzGzk5+XP2ECWQNon/gJiezcCi5dw+VXsIIYYnDE6
# pmcXFsnFadFxF6a2DRdnz47vPFL7UJwbIE5BAoWeRtTOIYtEOSpzyYWUyoZXKDK+
# HW8+aSsBPMlLBof/9znkoS+heksSJt+PV8NgKk7inj5dfZWVXHWbbtxph5oBQ9dH
# 5r7UixmMZF4F5lb04PPraW0p54FJAIsM2jwEiPYU/EgdBPV04N+rDR8tJpq77qs6
# 1YS0DPEOTqEyosZdywequ04/q7WY2kdFgBq136Lpj5G2qlc/KamMtO09A4bJc3d2
# JjXFE+6wmhDYWutm3rc/kKZTad5a9nJ/vlB1yxPfdY3RoTF3K49AcQMRmqsb7wMC
# 1tM4lUArDWGz/ktSxB9jcXJJ1dtC5oYh7FHEzpGWGygZQumirPk5+nsInQbJkdP6
# /mPbnn4UrZ2Um1tD/twc9Qt/WHt2ZC2W11UkqH9KKdHsrSKjLxi2dbzl3IfEWcFW
# p0rQAOrHULbrQXv8pfjQv5qGfdeuBjQQ7seXqc6TuqaCcFKbzhcoiPOFnMGQNVU0
# rizANUPeZkV/Haa7UiY+NW7WVZcd/qeY9K2muffcmhMF7WR9
# SIG # End signature block
