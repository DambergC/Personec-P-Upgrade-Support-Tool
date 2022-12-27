function Invoke-DbaDbDecryptObject {
    <#
    .SYNOPSIS
        Returns the decrypted version of an object

    .DESCRIPTION
        SQL Server provides an option to encrypt the code used in various types of objects.
        If the original code is no longer available for an encrypted object it won't be possible to view the definition.
        With this command the dedicated admin connection (DAC) can be used to search for the object and decrypt it.

        The command will output the results to the console by default.
        There is an option to export all the results to a folder creating .sql files.

        To connect to a remote SQL instance the remote dedicated administrator connection option will need to be configured.
        The binary versions of the objects can only be retrieved using a DAC connection.
        You can check the remote DAC connection with:
        'Get-DbaSpConfigure -SqlInstance [yourinstance] -ConfigName RemoteDacConnectionsEnabled'
        It should say 1 in the ConfiguredValue.

        The local DAC connection is enabled by default.

        To change the configurations you can use the Set-DbaSpConfigure command:
        'Set-DbaSpConfigure -SqlInstance [yourinstance] -ConfigName RemoteDacConnectionsEnabled -Value 1'
        In some cases you may need to reboot the instance.

    .PARAMETER SqlInstance
        The target SQL Server instance

    .PARAMETER SqlCredential
        Login to the target instance using alternative credentials. Accepts PowerShell credentials (Get-Credential).

        Windows Authentication, SQL Server Authentication, Active Directory - Password, and Active Directory - Integrated are all supported.

        For MFA support, please use Connect-DbaInstance.

    .PARAMETER Database
        Database to search for the object.

    .PARAMETER ObjectName
        The name of the object to search for in the database.

    .PARAMETER EncodingType
        The encoding type used to decrypt and encrypt values.

    .PARAMETER ExportDestination
        Location to output the decrypted object definitions.
        The destination will use the instance name, database name and object type i.e.: C:\temp\decrypt\SQLDB1\DB1\StoredProcedure

    .PARAMETER EnableException
        By default, when something goes wrong we try to catch it, interpret it and give you a friendly warning message.
        This avoids overwhelming you with "sea of red" exceptions, but is inconvenient because it basically disables advanced scripting.
        Using this switch turns this "nice by default" feature off and enables you to catch exceptions with your own try/catch.

    .NOTES
        Tags: Encryption, Decrypt, Utility
        Author: Sander Stad (@sqlstad), sqlstad.nl

        Website: https://dbatools.io
        Copyright: (c) 2018 by dbatools, licensed under MIT
        License: MIT https://opensource.org/licenses/MIT

    .LINK
        https://dbatools.io/Invoke-DbaDbDecryptObject

    .EXAMPLE
        PS C:\> Invoke-DbaDbDecryptObject -SqlInstance SQLDB1 -Database DB1 -ObjectName Function1

        Decrypt object "Function1" in DB1 of instance SQLDB1 and output the data to the user.

    .EXAMPLE
        PS C:\> Invoke-DbaDbDecryptObject -SqlInstance SQLDB1 -Database DB1 -ObjectName Function1 -ExportDestination C:\temp\decrypt

        Decrypt object "Function1" in DB1 of instance SQLDB1 and output the data to the folder "C:\temp\decrypt".

    .EXAMPLE
        PS C:\> Invoke-DbaDbDecryptObject -SqlInstance SQLDB1 -Database DB1 -ExportDestination C:\temp\decrypt

        Decrypt all objects in DB1 of instance SQLDB1 and output the data to the folder "C:\temp\decrypt"

    .EXAMPLE
        PS C:\> Invoke-DbaDbDecryptObject -SqlInstance SQLDB1 -Database DB1 -ObjectName Function1, Function2

        Decrypt objects "Function1" and "Function2" and output the data to the user.

    .EXAMPLE
        PS C:\> "SQLDB1" | Invoke-DbaDbDecryptObject -Database DB1 -ObjectName Function1, Function2

        Decrypt objects "Function1" and "Function2" and output the data to the user using a pipeline for the instance.

    #>
    [CmdletBinding()]
    param(
        [parameter(Mandatory, ValueFromPipeline)]
        [DbaInstanceParameter]$SqlInstance,
        [PSCredential]$SqlCredential,
        [parameter(Mandatory)]
        [object[]]$Database,
        [string[]]$ObjectName,
        [ValidateSet('ASCII', 'UTF8')]
        [string]$EncodingType = 'ASCII',
        [string]$ExportDestination,
        [switch]$EnableException
    )

    begin {

        function Invoke-DecryptData() {
            param(
                [parameter(Mandatory)]
                [byte[]]$Secret,
                [parameter(Mandatory)]
                [byte[]]$KnownPlain,
                [parameter(Mandatory)]
                [byte[]]$KnownSecret
            )

            # Declare pointers
            [int]$i = 0

            # Loop through each of the characters and apply an XOR to decrypt the data
            $result = $(

                # Loop through the byte string
                while ($i -lt $Secret.Length) {

                    # Compare the byte string character to the key character using XOR
                    if ($i -lt $Secret.Length) {
                        $Secret[$i] -bxor $KnownPlain[$i] -bxor $KnownSecret[$i]
                    }

                    # Increment the byte string indicator
                    $i += 2

                } # end while loop

            ) # end data value

            # Get the string value from the data
            $decryptedData = $Encoding.GetString($result)

            # Return the decrypted data
            return $decryptedData
        }

        # Create array list to hold the results
        $objectCollection = New-Object System.Collections.ArrayList

        # Set the encoding
        if ($EncodingType -eq 'ASCII') {
            $encoding = [System.Text.Encoding]::ASCII
        } elseif ($EncodingType -eq 'UTF8') {
            $encoding = [System.Text.Encoding]::UTF8
        }

        # Check the export parameter
        if ($ExportDestination -and -not (Test-Path $ExportDestination)) {
            try {
                # Create the new destination
                New-Item -Path $ExportDestination -ItemType Directory -Force | Out-Null
            } catch {
                Stop-Function -Message "Couldn't create destination folder $ExportDestination" -ErrorRecord $_ -Target $instance -Continue
            }
        }

    }

    process {

        if (Test-FunctionInterrupt) { return }

        # Loop through all the instances
        foreach ($instance in $SqlInstance) {

            # Check the configuration of the intance to see if the DAC is enabled
            $config = Get-DbaSpConfigure -SqlInstance $instance -SqlCredential $SqlCredential -ConfigName RemoteDacConnectionsEnabled
            if ($config.ConfiguredValue -ne 1) {
                Stop-Function -Message "DAC is not enabled for instance $instance.`nPlease use 'Set-DbaSpConfigure -SqlInstance $instance -SqlCredential <credential> -ConfigName RemoteDacConnectionsEnabled -Value 1' to configure the instance to allow DAC connections" -Target $instance -Continue
            }

            # Try to connect to instance
            try {
                $server = New-Object Microsoft.SqlServer.Management.Smo.Server "ADMIN:$instance"

                # credential usage
                if ($null -ne $SqlCredential) {
                    $context = $server.ConnectionContext
                    $context.LoginSecure = $false  # this allows for SQL auth to be done
                    $context.Login = $SqlCredential.UserName
                    $context.SecurePassword = $SqlCredential.Password
                }
            } catch {
                Stop-Function -Message "Error occurred while establishing connection to $instance" -Category ConnectionError -ErrorRecord $_ -Target $instance -Continue
            }

            # Get all the databases that compare to the database parameter
            $databaseCollection = $server.Databases | Where-Object { $_.Name -in $Database }

            # Use the table's schema for the trigger's schema. The schema name is not returned as a property for triggers (except in the URN).
            $triggerSchema = @{label = "Schema"; expression = { $_.Parent.Schema } }

            # Loop through each of databases
            foreach ($db in $databaseCollection) {

                $triggers = @($db.Tables | Where-Object { $_.IsSystemObject -eq $false } | ForEach-Object { $_.Triggers })

                # Get the objects
                if ($ObjectName) {
                    $storedProcedures = @($db.StoredProcedures | Where-Object { $_.Name -in $ObjectName -and $_.IsEncrypted -eq $true } | Select-Object Name, Schema, @{N = "ObjectType"; E = { 'StoredProcedure' } }, @{N = "SubType"; E = { '' } })
                    $functions = @($db.UserDefinedFunctions | Where-Object { $_.Name -in $ObjectName -and $_.IsEncrypted -eq $true } | Select-Object Name, Schema, @{N = "ObjectType"; E = { "UserDefinedFunction" } }, @{N = "SubType"; E = { $_.FunctionType.ToString().Trim() } })
                    $views = @($db.Views | Where-Object { $_.Name -in $ObjectName -and $_.IsEncrypted -eq $true } | Select-Object Name, Schema, @{N = "ObjectType"; E = { 'View' } }, @{N = "SubType"; E = { '' } })
                    $triggers = @($triggers | Where-Object { $_.Name -in $ObjectName -and $_.IsEncrypted -eq $true } | Select-Object Name, $triggerSchema, Parent, @{N = "ObjectType"; E = { 'Trigger' } }, @{N = "SubType"; E = { '' } })
                } else {
                    # Get all encrypted objects
                    $storedProcedures = @($db.StoredProcedures | Where-Object { $_.IsEncrypted -eq $true } | Select-Object Name, Schema, @{N = "ObjectType"; E = { 'StoredProcedure' } }, @{N = "SubType"; E = { '' } })
                    $functions = @($db.UserDefinedFunctions | Where-Object { $_.IsEncrypted -eq $true } | Select-Object Name, Schema, @{N = "ObjectType"; E = { "UserDefinedFunction" } }, @{N = "SubType"; E = { $_.FunctionType.ToString().Trim() } })
                    $views = @($db.Views | Where-Object { $_.IsEncrypted -eq $true } | Select-Object Name, Schema, @{N = "ObjectType"; E = { 'View' } }, @{N = "SubType"; E = { '' } })
                    $triggers = @($triggers | Where-Object { $_.IsEncrypted -eq $true } | Select-Object Name, $triggerSchema, Parent, @{N = "ObjectType"; E = { 'Trigger' } }, @{N = "SubType"; E = { '' } })
                }

                # Check if there are any objects
                if ($storedProcedures.Count -ge 1) {
                    $objectCollection += $storedProcedures
                }
                if ($functions.Count -ge 1) {
                    $objectCollection += $functions
                }
                if ($views.Count -ge 1) {
                    $objectCollection += $views
                }
                if ($triggers.Count -ge 1) {
                    $objectCollection += $triggers
                }
                # Loop through all the objects
                foreach ($object in $objectCollection) {

                    # Setup the query to get the secret. Include the schema name to find the object. Exclude null values in sys.sysobjvalues for triggers.
                    $querySecret = "SELECT imageval AS Value FROM sys.sysobjvalues WHERE objid = OBJECT_ID('$($object.Schema).$($object.Name)') AND imageval IS NOT NULL"

                    # Get the result of the secret query
                    try {
                        $secret = $server.Databases[$db.Name].Query($querySecret)
                    } catch {
                        Stop-Function -Message "Couldn't retrieve secret from $instance" -ErrorRecord $_ -Target $instance -Continue
                    }

                    # Check if at least a value came back
                    if ($secret) {

                        # Setup a known plain command and get the binary version of it
                        switch ($object.ObjectType) {

                            'StoredProcedure' {
                                $queryKnownPlain = (" " * $secret.Value.Length) + "ALTER PROCEDURE [$($object.Schema)].[$($object.Name)] WITH ENCRYPTION AS RETURN 0;"
                            }
                            'UserDefinedFunction' {

                                switch ($object.SubType) {
                                    'Inline' {
                                        $queryKnownPlain = (" " * $secret.value.length) + "ALTER FUNCTION [$($object.Schema)].[$($object.Name)]() RETURNS TABLE WITH ENCRYPTION AS RETURN SELECT 0 i;"
                                    }
                                    'Scalar' {
                                        $queryKnownPlain = (" " * $secret.value.length) + "ALTER FUNCTION [$($object.Schema)].[$($object.Name)]() RETURNS INT WITH ENCRYPTION AS BEGIN RETURN 0 END;"
                                    }
                                    'Table' {
                                        $queryKnownPlain = (" " * $secret.value.length) + "ALTER FUNCTION [$($object.Schema)].[$($object.Name)]() RETURNS @r TABLE(i INT) WITH ENCRYPTION AS BEGIN RETURN END;"
                                    }
                                }
                            }
                            'View' {
                                $queryKnownPlain = (" " * $secret.Value.Length) + "ALTER VIEW [$($object.Schema)].[$($object.Name)] WITH ENCRYPTION AS SELECT NULL AS [Value];"
                            }
                            'Trigger' {
                                $queryKnownPlain = (" " * $secret.Value.Length) + "ALTER TRIGGER [$($object.Schema)].[$($object.Name)] ON $($object.Parent) WITH ENCRYPTION AFTER INSERT AS RAISERROR (''Invoke-DbaDbDecryptObject'', 16, 10);"
                            }
                        }

                        # Convert the known plain into binary
                        if ($queryKnownPlain) {
                            try {
                                $knownPlain = $encoding.GetBytes(($queryKnownPlain))
                            } catch {
                                Stop-Function -Message "Couldn't convert the known plain to binary" -ErrorRecord $_ -Target $instance -Continue
                            }
                        } else {
                            Stop-Function -Message "Something went wrong setting up the known plain" -ErrorRecord $_ -Target $instance -Continue
                        }

                        # Setup the query to change the object in SQL Server and roll it back getting the encrypted version
                        # Exclude null values in sys.sysobjvalues for triggers and include the full schema and object name.
                        $queryKnownSecret = "
                            BEGIN TRANSACTION;
                                EXEC ('$queryKnownPlain');
                                SELECT imageval AS Value
                                FROM sys.sysobjvalues
                                WHERE objid = OBJECT_ID('$($object.Schema).$($object.Name)')
                                AND imageval IS NOT NULL;
                            ROLLBACK;
                        "

                        # Get the result for the known encrypted
                        try {
                            $knownSecret = $server.Databases[$db.Name].Query($queryKnownSecret)
                        } catch {
                            Stop-Function -Message "Couldn't retrieve known secret from $instance" -ErrorRecord $_ -Target $instance -Continue
                        }

                        # Get the result
                        $result = Invoke-DecryptData -Secret $secret.value -KnownPlain $knownPlain -KnownSecret $knownSecret.value

                        # Check if the results need to be exported
                        $filePath = $null
                        if ($ExportDestination) {
                            # make up the file name
                            $filename = "$($object.Schema).$($object.Name).sql"

                            # Check the export destination
                            if ($ExportDestination.EndsWith("\")) {
                                $destinationFolder = "$ExportDestination$instance\$($db.Name)\$($object.ObjectType)\"
                            } else {
                                $destinationFolder = "$ExportDestination\$instance\$($db.Name)\$($object.ObjectType)\"
                            }

                            # Check if the destination folder exists
                            if (-not (Test-Path $destinationFolder)) {
                                try {
                                    # Create the new destination
                                    New-Item -Path $destinationFolder -ItemType Directory -Force:$Force | Out-Null
                                } catch {
                                    Stop-Function -Message "Couldn't create destination folder $destinationFolder" -ErrorRecord $_ -Target $instance -Continue
                                }
                            }

                            # Combine the destination folder and the file name to get the path
                            $filePath = $destinationFolder + $filename

                            # Export the result
                            try {
                                $result | Out-File -FilePath $filePath -Force
                            } catch {
                                Stop-Function -Message "Couldn't export the results of $($object.Name) to $filePath" -ErrorRecord $_ -Target $instance -Continue
                            }

                        }

                        # Add the results to the custom object
                        [PSCustomObject]@{
                            ComputerName = $instance.ComputerName
                            InstanceName = $server.ServiceName
                            SqlInstance  = $server.DomainInstanceName
                            Database     = $db.Name
                            Type         = $object.ObjectType
                            Schema       = $object.Schema
                            Name         = $object.Name
                            FullName     = "$($object.Schema).$($object.Name)"
                            Script       = $result
                            OutputFile   = $filePath
                        }
                    }
                }
            }
        }
    }
    end {
        Write-Message -Message "Finished decrypting data" -Level Verbose
    }
}
# SIG # Begin signature block
# MIIjYAYJKoZIhvcNAQcCoIIjUTCCI00CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCCvXQeZSVzKbzzi
# gWeQX2aBW3WQrRO7NDe5C5BXocnZMqCCHVkwggUaMIIEAqADAgECAhADBbuGIbCh
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
# BgorBgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCBXVx8PYhG1zIDPbdw2pzunDGzO
# HhgL7+oJKMgdFOPsDTANBgkqhkiG9w0BAQEFAASCAQA4ZLOxJnWEbxwvBzBKpaem
# zYjTGlRUDDQAlZIsrHgeFAsLxjTEinvE8ZA0j/7Ur3Jl0mU75k6tVZnrVBAvYCac
# EKfetc3A/PvUEchZLynCTf44OBXia+Y20PhgtHLZpJsZ+oL9GnFllRFfut1VH7zZ
# pTlImZJUbpPHKIObMucp4WDzCNH5yJ2uLLlZgmdyHkGnmQ855rgQWp+se55P7cRd
# hbyZmmJJrpFPQaBDCctH01YKtslMjKdiLiOT94UEuz4ttyoKTSjHUlmda9v8GfGM
# YSL0mdKPX8VLerTIx50mv9xpu1+vb8eE/zwnI+W3xYT+Abkj46GuAEMirmyElmnF
# oYIDIDCCAxwGCSqGSIb3DQEJBjGCAw0wggMJAgEBMHcwYzELMAkGA1UEBhMCVVMx
# FzAVBgNVBAoTDkRpZ2lDZXJ0LCBJbmMuMTswOQYDVQQDEzJEaWdpQ2VydCBUcnVz
# dGVkIEc0IFJTQTQwOTYgU0hBMjU2IFRpbWVTdGFtcGluZyBDQQIQDE1pckuU+jwq
# Sj0pB4A9WjANBglghkgBZQMEAgEFAKBpMBgGCSqGSIb3DQEJAzELBgkqhkiG9w0B
# BwEwHAYJKoZIhvcNAQkFMQ8XDTIyMTExNzA4NTY0M1owLwYJKoZIhvcNAQkEMSIE
# IBydWxVjojIOV/ejJRRfJ+qAuDLMO0T+pND9XQLcZrZ/MA0GCSqGSIb3DQEBAQUA
# BIICAGU7svOf+Mlr1jEyaEG1n/WK9Q1xltpZBEL0dYm+xItyKobXJOqayExkdmUM
# 2plVQWoeRRaFK5++nXL/921+VRMN/cjy4rzz5Z8Lhr/0V4RzLwse4gMUihwtAVxw
# VB5GkofKiyS4cs9RD7FPi4tYLqWtwEeW0p2bxRErxJBA4gT/BbgqNvnCSuOfs8BU
# uelq+XTsBYE5NlS39bhaSc4rVz2Qka4AwJ4ibIzay9NDVzBKF1XZiHearA1gCLQG
# EvTZ4zaBnfHnJMni752G+Lr9FTVain1GwpHefUFhQiF3hGKXTAfykRKpkzLbOGs9
# cdYib8nZ9fbulbXGHajWK79Qbe000OWGfUeXFu6wm9g9DITjhz1GAKGyFnGYPn6C
# VITdLvb2OHKOn+odRWQr7//3wAAHjzTfZDAthQnijhmMOuUyfw64zBZBl13jQQEZ
# vn1gmkRXJTZMbF+xxzwk8rmm1Bo44iuzqW5aK0soj1HjmjeZfRE0g27eyo/r5lA8
# tXgjwADWSsTY1BDINukTGzE7ciMc90Chss8Z4dlfbShn2KttwSDO0G2wAQMo0IRo
# QAdgw1YX3bQorcBN2040msPto5ydbQYzsJrvNsky13Tuga/Bo19Nzz2rn4ywBRTZ
# 4gb5Taa47dg09OWIT3YnY3e0HDuPnhNRIQTIgJ3Rd4Zi9oB2
# SIG # End signature block
