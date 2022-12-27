function ConvertTo-DbaDataTable {
    <#
    .SYNOPSIS
        Creates a DataTable for an object.

    .DESCRIPTION
        Creates a DataTable based on an object's properties. This allows you to easily write to SQL Server tables.

        Thanks to Chad Miller, this is based on his script. https://gallery.technet.microsoft.com/scriptcenter/4208a159-a52e-4b99-83d4-8048468d29dd

        If the attempt to convert to data table fails, try the -Raw parameter for less accurate datatype detection.

    .PARAMETER InputObject
        The object to transform into a DataTable.

    .PARAMETER TimeSpanType
        Specifies the type to convert TimeSpan objects into. Default is 'TotalMilliseconds'. Valid options are: 'Ticks', 'TotalDays', 'TotalHours', 'TotalMinutes', 'TotalSeconds', 'TotalMilliseconds', and 'String'.

    .PARAMETER SizeType
        Specifies the type to convert DbaSize objects to. Default is 'Int64'. Valid options are 'Int32', 'Int64', and 'String'.

    .PARAMETER IgnoreNull
        If this switch is enabled, objects with null values will be ignored (empty rows will be added by default).

    .PARAMETER Raw
        If this switch is enabled, the DataTable will be created with strings. No attempt will be made to parse/determine data types.

    .PARAMETER EnableException
        By default, when something goes wrong we try to catch it, interpret it and give you a friendly warning message.
        This avoids overwhelming you with "sea of red" exceptions, but is inconvenient because it basically disables advanced scripting.
        Using this switch turns this "nice by default" feature off and enables you to catch exceptions with your own try/catch.

    .NOTES
        Tags: Table, Data
        Author: Chrissy LeMaire (@cl), netnerds.net

        Website: https://dbatools.io/
        Copyright: (c) 2018 by dbatools, licensed under MIT
        License: MIT https://opensource.org/licenses/MIT

    .LINK
        https://dbatools.io/ConvertTo-DbaDataTable

    .OUTPUTS
        System.Object[]

    .EXAMPLE
        PS C:\> Get-Service | ConvertTo-DbaDataTable

        Creates a DataTable from the output of Get-Service.

    .EXAMPLE
        PS C:\> ConvertTo-DbaDataTable -InputObject $csv.cheesetypes

        Creates a DataTable from the CSV object $csv.cheesetypes.

    .EXAMPLE
        PS C:\> $dblist | ConvertTo-DbaDataTable

        Creates a DataTable from the $dblist object passed in via pipeline.

    .EXAMPLE
        PS C:\> Get-Process | ConvertTo-DbaDataTable -TimeSpanType TotalSeconds

        Creates a DataTable with the running processes and converts any TimeSpan property to TotalSeconds.

    #>
    [CmdletBinding()]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSUseOutputTypeCorrectly", "", Justification = "PSSA Rule Ignored by BOH")]
    [OutputType([System.Object[]])]
    param (
        [Parameter(Position = 0,
            Mandatory,
            ValueFromPipeline)]
        [AllowNull()]
        [PSObject[]]$InputObject,
        [ValidateSet("Ticks",
            "TotalDays",
            "TotalHours",
            "TotalMinutes",
            "TotalSeconds",
            "TotalMilliseconds",
            "String")]
        [ValidateNotNullOrEmpty()]
        [string]$TimeSpanType = "TotalMilliseconds",
        [ValidateSet("Int64", "Int32", "String")]
        [string]$SizeType = "Int64",
        [switch]$IgnoreNull,
        [switch]$Raw,
        [switch]$EnableException
    )

    begin {
        Write-Message -Level Debug -Message "Bound parameters: $($PSBoundParameters.Keys -join ", ")"
        Write-Message -Level Debug -Message "TimeSpanType = $TimeSpanType | SizeType = $SizeType"

        function Convert-Type {
            # This function will check so that the type is an accepted type which could be used when inserting into a table.
            # If a type is accepted (included in the $type array) then it will be passed on, otherwise it will first change type before passing it on.
            # Special types will have both their types converted as well as the value.
            # TimeSpan is a special type and will be converted into the $timespantype. (default: TotalMilliseconds) so that the timespan can be stored in a database further down the line.
            [CmdletBinding()]
            param (
                $type,
                $value,
                $timespantype = 'TotalMilliseconds',
                $sizetype = 'Int64'
            )

            $types = [System.Collections.ArrayList]@(
                'System.Int32',
                'System.UInt32',
                'System.Int16',
                'System.UInt16',
                'System.Int64',
                'System.UInt64',
                'System.Decimal',
                'System.Single',
                'System.Double',
                'System.Byte',
                'System.Byte[]',
                'System.SByte',
                'System.Boolean',
                'System.DateTime',
                'System.Guid',
                'System.Char'
            )

            # The $special variable is used to mark the return value if a conversion was made on the value itself.
            # If this is set to true the original value will later be ignored when updating the DataTable.
            # And the value returned from this function will be used instead. (cannot modify existing properties)
            $special = $false
            $specialType = ""

            # Special types need to be converted in some way.
            # This attempt is to convert timespan into something that works in a table.
            # I couldn't decide on what to convert it to so the user can decide.
            # If the parameter is not used, TotalMilliseconds will be used as default.
            # Ticks are more accurate but I think milliseconds are more useful most of the time.
            if (($type -eq 'System.TimeSpan') -or ($type -eq 'Sqlcollaborative.Dbatools.Utility.DbaTimeSpan') -or ($type -eq 'Sqlcollaborative.Dbatools.Utility.DbaTimeSpanPretty')) {
                $special = $true
                if ($timespantype -eq 'String') {
                    $value = $value.ToString()
                    $type = 'System.String'
                } else {
                    # Let's use Int64 for all other types than string.
                    # We could match the type more closely with the timespantype but that can be added in the future if needed.
                    $value = $value.$timespantype
                    $type = 'System.Int64'
                }
                $specialType = 'Timespan'
            } elseif ($type -eq 'Sqlcollaborative.Dbatools.Utility.Size') {
                $special = $true
                switch ($sizetype) {
                    'Int64' {
                        $value = $value.Byte
                        $type = 'System.Int64'
                    }
                    'Int32' {
                        $value = $value.Byte
                        $type = 'System.Int32'
                    }
                    'String' {
                        $value = $value.ToString()
                        $type = 'System.String'
                    }
                }
                $specialType = 'Size'
            } elseif (-not ($type -in $types)) {
                # All types which are not found in the array will be converted into strings.
                # In this way we don't ignore it completely and it will be clear in the end why it looks as it does.
                $type = 'System.String'
            }

            # return a hashtable instead of an object. I like hashtables :)
            return @{ type = $type; Value = $value; Special = $special; SpecialType = $specialType }
        }

        function Convert-SpecialType {
            <#
            .SYNOPSIS
                Converts a value for a known column.

            .DESCRIPTION
                Converts a value for a known column.

            .PARAMETER Value
                The value to convert

            .PARAMETER Type
                The special type for which to convert

            .PARAMETER SizeType
                The size type defined by the user

            .PARAMETER TimeSpanType
                The timespan type defined by the user
        #>
            [CmdletBinding()]
            param (
                $Value,
                [ValidateSet('Timespan', 'Size')]
                [string]$Type,
                [string]$SizeType,
                [string]$TimeSpanType
            )

            switch ($Type) {
                'Size' {
                    if ($SizeType -eq 'String') { return $Value.ToString() }
                    else { return $Value.Byte }
                }
                'Timespan' {
                    if ($TimeSpanType -eq 'String') {
                        $Value.ToString()
                    } else {
                        $Value.$TimeSpanType
                    }
                }
            }
        }

        function Add-Column {
            <#
            .SYNOPSIS
                Adds a column to the datatable in progress.

            .DESCRIPTION
                Adds a column to the datatable in progress.

            .PARAMETER Property
                The property for which to add a column.

            .PARAMETER DataTable
                Autofilled. The table for which to add a column.

            .PARAMETER TimeSpanType
                Autofilled. How should timespans be handled?

            .PARAMETER SizeType
                Autofilled. How should sizes be handled?

            .PARAMETER Raw
                Autofilled. Whether the column should be string, no matter the input.
        #>
            [CmdletBinding()]
            param (
                [System.Management.Automation.PSPropertyInfo]$Property,
                [System.Data.DataTable]$DataTable = $datatable,
                [string]$TimeSpanType = $TimeSpanType,
                [string]$SizeType = $SizeType,
                [bool]$Raw = $Raw
            )

            $type = $property.TypeNameOfValue
            try {
                if ($Property.MemberType -like 'ScriptProperty') {
                    $type = $Property.GetType().FullName
                }
            } catch { $type = 'System.String' }

            $converted = Convert-Type -type $type -value $property.Value -timespantype $TimeSpanType -sizetype $SizeType

            $column = New-Object System.Data.DataColumn
            $column.ColumnName = $property.Name.ToString()
            if (-not $Raw) {
                $column.DataType = [System.Type]::GetType($converted.type)
            }
            $null = $DataTable.Columns.Add($column)
            $converted
        }

        $datatable = New-Object System.Data.DataTable

        # Accelerate subsequent lookups of columns and special type columns
        $columns = @()
        $specialColumns = @()
        $specialColumnsType = @{ }

        $ShouldCreateColumns = $true
    }

    process {
        #region Handle null objects
        if ($null -eq $InputObject) {
            if (-not $IgnoreNull) {
                $datarow = $datatable.NewRow()
                $datatable.Rows.Add($datarow)
            }

            # Only ends the current process block
            return
        }
        #endregion Handle null objects


        foreach ($object in $InputObject) {
            #region Handle null objects
            if ($null -eq $object) {
                if (-not $IgnoreNull) {
                    $datarow = $datatable.NewRow()
                    $datatable.Rows.Add($datarow)
                }
                continue
            }
            #endregion Handle null objects

            #Handle rows already being System.Data.DataRow
            if ($object.GetType().FullName -eq 'System.Data.DataRow') {
                $datatable.Merge($object.Table)
                $datatable = $datatable.DefaultView.ToTable($true)
                continue
            }

            # The new row to insert
            $datarow = $datatable.NewRow()

            #region Process Properties
            $objectProperties = $object.PSObject.Properties
            foreach ($property in $objectProperties) {
                #region Create Columns as needed
                if ($ShouldCreateColumns) {
                    $newColumn = Add-Column -Property $property
                    $columns += $property.Name
                    if ($newColumn.Special) {
                        $specialColumns += $property.Name
                        $specialColumnsType[$property.Name] = $newColumn.SpecialType
                    }
                }
                #endregion Create Columns as needed

                # Handle null properties, as well as properties with access errors
                try {
                    $propValueLength = $property.value.length
                } catch {
                    $propValueLength = 0
                }

                #region Insert value into column of row
                if ($propValueLength -gt 0) {
                    # If the typename was a special typename we want to use the value returned from Convert-Type instead.
                    # We might get error if we try to change the value for $property.value if it is read-only. That's why we use $converted.value instead.
                    if ($property.Name -in $specialColumns) {
                        $datarow.Item($property.Name) = Convert-SpecialType -Value $property.value -Type $specialColumnsType[$property.Name] -SizeType $SizeType -TimeSpanType $TimeSpanType
                    } else {
                        if ($property.value.ToString().length -eq 15) {
                            if ($property.value.ToString() -eq 'System.Object[]') {
                                $value = $property.value -join ", "
                            } elseif ($property.value.ToString() -eq 'System.String[]') {
                                $value = $property.value -join ", "
                            } else {
                                $value = $property.value
                            }
                        } else {
                            $value = $property.value
                        }

                        try {
                            $datarow.Item($property.Name) = $value
                        } catch {
                            if ($property.Name -notin $columns) {
                                try {
                                    $newColumn = Add-Column -Property $property
                                    $columns += $property.Name
                                    if ($newColumn.Special) {
                                        $specialColumns += $property.Name
                                        $specialColumnsType[$property.Name] = $newColumn.SpecialType
                                    }

                                    $datarow.Item($property.Name) = $newColumn.Value
                                } catch {
                                    Stop-Function -Message "Failed to add property $($property.Name) from $object" -ErrorRecord $_ -Target $object
                                }
                            } else {
                                Stop-Function -Message "Failed to add property $($property.Name) from $object" -ErrorRecord $_ -Target $object
                            }
                        }
                    }
                }
                #endregion Insert value into column of row
            }

            $datatable.Rows.Add($datarow)
            # If this is the first non-null object then the columns has just been created.
            # Set variable to false to skip creating columns from now on.
            if ($ShouldCreateColumns) {
                $ShouldCreateColumns = $false
            }
            #endregion Process Properties
        }
    }
    end {
        Write-Message -Level InternalComment -Message "Finished."
        , $datatable
    }
}
# SIG # Begin signature block
# MIIjYAYJKoZIhvcNAQcCoIIjUTCCI00CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCBQm09p6xDR/yTq
# zE7wO8Eom+cu8Pm+k+awKOg7CCmt1KCCHVkwggUaMIIEAqADAgECAhADBbuGIbCh
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
# BgorBgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCBWGrZuLuGwV8Ttufm0Ae2V4lZT
# OawvAyDlAr+q3lozyTANBgkqhkiG9w0BAQEFAASCAQBZVz/X32A1Fuy021nDxbAb
# 6CMteGAstiNx71lcYbnxaBJRJs0KSlTcIGIIjAakOYyIoxQwiSly8PVgeZy6Lpcs
# 4MBJ+QjY6bQlcEh/mRhFQSuOfTUZyr6vOkT96PqVp6bGcEn68OT/AOd+CuvcSjl6
# OG2Bq5NXWSC2Ij2D4WmTt6dv+XrHfNYGi9nEsdEiYMNRakug8aDHPMLBE6AmOYEP
# 3ByJSTzEmEqFGzGc4aomLDNc1Wujjo8Fe7E4uvScQBsfka81z0aF+Vih6FlOo3ma
# orT2T/aihlUsc0WC/89r24JoUcjnVp9Otld1klcegcJkJVwOwDOPbC/sxJ75OzTy
# oYIDIDCCAxwGCSqGSIb3DQEJBjGCAw0wggMJAgEBMHcwYzELMAkGA1UEBhMCVVMx
# FzAVBgNVBAoTDkRpZ2lDZXJ0LCBJbmMuMTswOQYDVQQDEzJEaWdpQ2VydCBUcnVz
# dGVkIEc0IFJTQTQwOTYgU0hBMjU2IFRpbWVTdGFtcGluZyBDQQIQDE1pckuU+jwq
# Sj0pB4A9WjANBglghkgBZQMEAgEFAKBpMBgGCSqGSIb3DQEJAzELBgkqhkiG9w0B
# BwEwHAYJKoZIhvcNAQkFMQ8XDTIyMTExNzA4NTUxNFowLwYJKoZIhvcNAQkEMSIE
# IMeCxtNkV42sIANah7YgMA8HuEOb20NWXGZ2U9zq+RKnMA0GCSqGSIb3DQEBAQUA
# BIICAM1qO9lgrvA1/7Qa0iLjyov42oIUeVWbV0+F6K1FLNKy8zzbo1v5YAlnnx5q
# 9Effy1z9jM4JIjcJX1lKP8OK3vw+I54uPUJAkliBIji1O/JOlb65GTVsV77DkRxl
# UtlK72g+8Ud8MtbcVoIPx3hIpgnOa3tpwb01ue+N1SCKnyLSji3wak3AG/HPDpoF
# Wj/ahLI4/fXLaKTMc4H/N/ZTk+W6LJZRDQb770xoJaeVzSldd31kf8ElgAC6JpFf
# G1KhPme83rKC1LMe45t7VXrjV4e9s7Gau3ybbi+QTWIVkuNdwjmiyMdVrz0HiLvz
# 7D2DUCmgaMgf8oSY0m4fwiaZ4kherctjVsqg4x1wPjA3VyrD96OC59FIVMQePyBI
# e+8PHcncphuv4kGILXboMRslua+ES9hVH+Qh0/s1XbjnEKld2EfRe3Bc64O/3lUF
# aMcq9XbfyNz90HoYdlHa4H0L78EFaV+SRYYYWVEi593y+9JNXE5enMN0HCyRXHPd
# +g36IYteyFf+L6dzx1pzPFE97Suc/d7M/8+12Kvekc0u6VaSc5jtiL0aMAKJ0rpX
# 0W9iiQ2ws+mkdn+53e+ZUgoBvDsDiB/1iw0xHmvVXn9IbfWwX2+El8l/iH3aIxIA
# YciTmFqEoYoruoXEmQR3pE/g2apinvGGPGsr65czfU7YlTSb
# SIG # End signature block
