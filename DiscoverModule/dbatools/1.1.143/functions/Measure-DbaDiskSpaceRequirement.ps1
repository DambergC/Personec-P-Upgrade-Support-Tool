function Measure-DbaDiskSpaceRequirement {
    <#
    .SYNOPSIS
        Calculate the space needed to copy and possibly replace a database from one SQL server to another.

    .DESCRIPTION
        Returns a file list from source and destination where source file may overwrite destination. Complex scenarios where a new file may exist is taken into account.
        This command will accept a hash object in pipeline with the following keys: Source, SourceDatabase, Destination. Using this command will provide a way to prepare before a complex migration with multiple databases from different sources and destinations.

    .PARAMETER Source
        Source SQL Server.

    .PARAMETER SourceSqlCredential
        Login to the target instance using alternative credentials. Accepts PowerShell credentials (Get-Credential).

        Windows Authentication, SQL Server Authentication, Active Directory - Password, and Active Directory - Integrated are all supported.

        For MFA support, please use Connect-DbaInstance.

    .PARAMETER Database
        The database to copy. It MUST exist.

    .PARAMETER Destination
        Destination SQL Server instance.

    .PARAMETER DestinationSqlCredential
        Login to the target instance using alternative credentials. Accepts PowerShell credentials (Get-Credential).

        Windows Authentication, SQL Server Authentication, Active Directory - Password, and Active Directory - Integrated are all supported.

        For MFA support, please use Connect-DbaInstance.

    .PARAMETER DestinationDatabase
        The database name at destination.
        May or may not be present, if unspecified it will default to the database name provided in SourceDatabase.

    .PARAMETER Credential
        The credentials to use to connect via CIM/WMI/PowerShell remoting.

    .PARAMETER EnableException
        By default, when something goes wrong we try to catch it, interpret it and give you a friendly warning message.
        This avoids overwhelming you with "sea of red" exceptions, but is inconvenient because it basically disables advanced scripting.
        Using this switch turns this "nice by default" feature off and enables you to catch exceptions with your own try/catch.

    .NOTES
        Tags: Diagnostic, Storage, Space, Database
        Author: Pollus Brodeur (@pollusb)

        Website: https://dbatools.io
        Copyright: (c) 2018 by dbatools, licensed under MIT
        License: MIT https://opensource.org/licenses/MIT

    .LINK
        https://dbatools.io/Measure-DbaDiskSpaceRequirement

    .EXAMPLE
        PS C:\> Measure-DbaDiskSpaceRequirement -Source INSTANCE1 -Database DB1 -Destination INSTANCE2

        Calculate space needed for a simple migration with one database with the same name at destination.

    .EXAMPLE
        PS C:\> @(
        >> [PSCustomObject]@{Source='SQL1';Destination='SQL2';Database='DB1'},
        >> [PSCustomObject]@{Source='SQL1';Destination='SQL2';Database='DB2'}
        >> ) | Measure-DbaDiskSpaceRequirement

        Using a PSCustomObject with 2 databases to migrate on SQL2.

    .EXAMPLE
        PS C:\> Import-Csv -Path .\migration.csv -Delimiter "`t" | Measure-DbaDiskSpaceRequirement | Format-Table -AutoSize

        Using a CSV file. You will need to use this header line "Source<tab>Destination<tab>Database<tab>DestinationDatabase".

    .EXAMPLE
        PS C:\> $qry = "SELECT Source, Destination, Database FROM dbo.Migrations"
        PS C:\> Invoke-DbaCmd -SqlInstance DBA -Database Migrations -Query $qry | Measure-DbaDiskSpaceRequirement

        Using a SQL table. We are DBA after all!
    #>
    [CmdletBinding()]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSUseOutputTypeCorrectly", "", Justification = "PSSA Rule Ignored by BOH")]
    param(
        [Parameter(Mandatory, ValueFromPipelineByPropertyName)]
        [DbaInstanceParameter]$Source,
        [Parameter(Mandatory, ValueFromPipelineByPropertyName)]
        [string]$Database,
        [Parameter(ValueFromPipelineByPropertyName)]
        [PSCredential]$SourceSqlCredential,
        [Parameter(Mandatory, ValueFromPipelineByPropertyName)]
        [DbaInstanceParameter]$Destination,
        [Parameter(ValueFromPipelineByPropertyName)]
        [string]$DestinationDatabase,
        [Parameter(ValueFromPipelineByPropertyName)]
        [PSCredential]$DestinationSqlCredential,
        [Parameter(ValueFromPipelineByPropertyName)]
        [PSCredential]$Credential,
        [switch]$EnableException
    )
    begin {
        $local:cacheMP = @{ }
        $local:cacheDP = @{ }
        function Get-MountPoint {
            [CmdletBinding()]
            param(
                [Parameter(Mandatory)]
                $computerName,
                [PSCredential]$credential
            )
            Get-DbaCmObject -Class Win32_MountPoint -ComputerName $computerName -Credential $credential | Select-Object @{n = 'Mountpoint'; e = { $_.Directory.split('=')[1].Replace('"', '').Replace('\\', '\') } }
        }
        function Get-MountPointFromPath {
            [CmdletBinding()]
            param(
                [Parameter(Mandatory)]
                $path,
                [Parameter(Mandatory)]
                $computerName,
                [PSCredential]$credential
            )
            if (!$cacheMP[$computerName]) {
                try {
                    $cacheMP.Add($computerName, (Get-MountPoint -computerName $computerName -credential $credential))
                    Write-Message -Level Verbose -Message "cacheMP[$computerName] is now cached"
                } catch {
                    # This way, I won't be asking again for this computer.
                    $cacheMP.Add($computerName, '?')
                    Stop-Function -Message "Can't connect to $computerName. cacheMP[$computerName] = ?" -ErrorRecord $_ -Target $computerName -Continue
                }
            }
            if ($cacheMP[$computerName] -eq '?') {
                return '?'
            }
            foreach ($m in ($cacheMP[$computerName] | Sort-Object -Property Mountpoint -Descending)) {
                if ($path -like "$($m.Mountpoint)*") {
                    return $m.Mountpoint
                }
            }
            Write-Message -Level Warning -Message "Path $path can't be found in any MountPoints of $computerName"
        }
        function Get-MountPointFromDefaultPath {
            [CmdletBinding()]
            param(
                [Parameter(Mandatory)]
                [ValidateSet('Log', 'Data')]
                $DefaultPathType,
                [Parameter(Mandatory)]
                $SqlInstance,
                [PSCredential]$SqlCredential,
                # Could probably use the computer defined in SqlInstance but info was already available from the caller
                $computerName,
                [PSCredential]$Credential
            )
            if (!$cacheDP[$SqlInstance]) {
                try {
                    $cacheDP.Add($SqlInstance, (Get-DbaDefaultPath -SqlInstance $SqlInstance -SqlCredential $SqlCredential -EnableException))
                    Write-Message -Level Verbose -Message "cacheDP[$SqlInstance] is now cached"
                } catch {
                    Stop-Function -Message "Can't connect to $SqlInstance" -Continue
                    $cacheDP.Add($SqlInstance, '?')
                    return '?'
                }
            }
            if ($cacheDP[$SqlInstance] -eq '?') {
                return '?'
            }
            if (!$computerName) {
                $computerName = $cacheDP[$SqlInstance].ComputerName
            }
            if (!$cacheMP[$computerName]) {
                try {
                    $cacheMP.Add($computerName, (Get-MountPoint -computerName $computerName -Credential $Credential))
                } catch {
                    Stop-Function -Message "Can't connect to $computerName." -Continue
                    $cacheMP.Add($computerName, '?')
                    return '?'
                }
            }
            if ($DefaultPathType -eq 'Log') {
                $path = $cacheDP[$SqlInstance].Log
            } else {
                $path = $cacheDP[$SqlInstance].Data
            }
            foreach ($m in ($cacheMP[$computerName] | Sort-Object -Property Mountpoint -Descending)) {
                if ($path -like "$($m.Mountpoint)*") {
                    return $m.Mountpoint
                }
            }
        }
    }
    process {
        try {
            $sourceServer = Connect-DbaInstance -SqlInstance $Source -SqlCredential $SourceSqlCredential
        } catch {
            Stop-Function -Message "Failure" -Category ConnectionError -ErrorRecord $_ -Target $Source
            return
        }

        try {
            $destServer = Connect-DbaInstance -SqlInstance $Destination -SqlCredential $DestinationSqlCredential
        } catch {
            Stop-Function -Message "Failure" -Category ConnectionError -ErrorRecord $_ -Target $Destination
            return
        }

        if (Test-Bound 'DestinationDatabase' -not) {
            $DestinationDatabase = $Database
        }
        Write-Message -Level Verbose -Message "$Source.[$Database] -> $Destination.[$DestinationDatabase]"

        $sourceDb = Get-DbaDatabase -SqlInstance $sourceServer -Database $Database -SqlCredential $SourceSqlCredential
        if (Test-Bound 'Database' -not) {
            Stop-Function -Message "Database [$Database] MUST exist on Source Instance $Source." -ErrorRecord $_
        }
        $sourceFiles = @($sourceDb.FileGroups.Files | Select-Object Name, FileName, Size, @{n = 'Type'; e = { 'Data' } })
        $sourceFiles += @($sourceDb.LogFiles | Select-Object Name, FileName, Size, @{n = 'Type'; e = { 'Log' } })

        if ($destDb = Get-DbaDatabase -SqlInstance $destServer -Database $DestinationDatabase -SqlCredential $DestinationSqlCredential) {
            $destFiles = @($destDb.FileGroups.Files | Select-Object Name, FileName, Size, @{n = 'Type'; e = { 'Data' } })
            $destFiles += @($destDb.LogFiles | Select-Object Name, FileName, Size, @{n = 'Type'; e = { 'Log' } })
            $computerName = $destDb.ComputerName
        } else {
            Write-Message -Level Verbose -Message "Database [$DestinationDatabase] does not exist on Destination Instance $Destination."
            $computerName = $destServer.ComputerName
        }

        foreach ($sourceFile in $sourceFiles) {
            foreach ($destFile in $destFiles) {
                if (($found = ($sourceFile.Name -eq $destFile.Name))) {
                    # Files found on both sides
                    [PSCustomObject]@{
                        SourceComputerName      = $sourceServer.ComputerName
                        SourceInstance          = $sourceServer.ServiceName
                        SourceSqlInstance       = $sourceServer.DomainInstanceName
                        DestinationComputerName = $destServer.ComputerName
                        DestinationInstance     = $destServer.ServiceName
                        DestinationSqlInstance  = $destServer.DomainInstanceName
                        SourceDatabase          = $sourceDb.Name
                        SourceLogicalName       = $sourceFile.Name
                        SourceFileName          = $sourceFile.FileName
                        SourceFileSize          = [DbaSize]($sourceFile.Size * 1000)
                        DestinationDatabase     = $destDb.Name
                        DestinationLogicalName  = $destFile.Name
                        DestinationFileName     = $destFile.FileName
                        DestinationFileSize     = [DbaSize]($destFile.Size * 1000) * -1
                        DifferenceSize          = [DbaSize]( ($sourceFile.Size * 1000) - ($destFile.Size * 1000) )
                        MountPoint              = Get-MountPointFromPath -Path $destFile.Filename -ComputerName $computerName -Credential $Credential
                        FileLocation            = 'Source and Destination'
                    } | Select-DefaultView -ExcludeProperty SourceComputerName, SourceInstance, DestinationInstance, DestinationLogicalName
                    break
                }
            }
            if (!$found) {
                # Files on source but not on destination
                [PSCustomObject]@{
                    SourceComputerName      = $sourceServer.ComputerName
                    SourceInstance          = $sourceServer.ServiceName
                    SourceSqlInstance       = $sourceServer.DomainInstanceName
                    DestinationComputerName = $destServer.ComputerName
                    DestinationInstance     = $destServer.ServiceName
                    DestinationSqlInstance  = $destServer.DomainInstanceName
                    SourceDatabase          = $sourceDb.Name
                    SourceLogicalName       = $sourceFile.Name
                    SourceFileName          = $sourceFile.FileName
                    SourceFileSize          = [DbaSize]($sourceFile.Size * 1000)
                    DestinationDatabase     = $DestinationDatabase
                    DestinationLogicalName  = $null
                    DestinationFileName     = $null
                    DestinationFileSize     = [DbaSize]0
                    DifferenceSize          = [DbaSize]($sourceFile.Size * 1000)
                    MountPoint              = Get-MountPointFromDefaultPath -DefaultPathType $sourceFile.Type -SqlInstance $Destination `
                        -SqlCredential $DestinationSqlCredential -computerName $computerName -credential $Credential
                    FileLocation            = 'Only on Source'
                } | Select-DefaultView -ExcludeProperty SourceComputerName, SourceInstance, DestinationInstance, DestinationLogicalName
            }
        }
        if ($destDb) {
            # Files on destination but not on source (strange scenario but possible)
            $destFilesNotSource = Compare-Object -ReferenceObject $destFiles -DifferenceObject $sourceFiles -Property Name -PassThru
            foreach ($destFileNotSource in $destFilesNotSource) {
                [PSCustomObject]@{
                    SourceComputerName      = $sourceServer.ComputerName
                    SourceInstance          = $sourceServer.ServiceName
                    SourceSqlInstance       = $sourceServer.DomainInstanceName
                    DestinationComputerName = $destServer.ComputerName
                    DestinationInstance     = $destServer.ServiceName
                    DestinationSqlInstance  = $destServer.DomainInstanceName
                    SourceDatabaseName      = $Database
                    SourceLogicalName       = $null
                    SourceFileName          = $null
                    SourceFileSize          = [DbaSize]0
                    DestinationDatabaseName = $destDb.Name
                    DestinationLogicalName  = $destFileNotSource.Name
                    DestinationFileName     = $destFile.FileName
                    DestinationFileSize     = [DbaSize]($destFileNotSource.Size * 1000) * -1
                    DifferenceSize          = [DbaSize]($destFileNotSource.Size * 1000) * -1
                    MountPoint              = Get-MountPointFromPath -Path $destFileNotSource.Filename -ComputerName $computerName -Credential $Credential
                    FileLocation            = 'Only on Destination'
                } | Select-DefaultView -ExcludeProperty SourceComputerName, SourceInstance, DestinationInstance, DestinationLogicalName
            }
        }
        $DestinationDatabase = $null
    }
}
# SIG # Begin signature block
# MIIjYAYJKoZIhvcNAQcCoIIjUTCCI00CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCBWVN3kJ1AxKM2N
# rkWtAXuSDJbv9DP0zY7cdtKABrG7CaCCHVkwggUaMIIEAqADAgECAhADBbuGIbCh
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
# BgorBgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCCdUTN57hA/bx4FXb0QCENOgElk
# yPCX4QHet/7odM+ORjANBgkqhkiG9w0BAQEFAASCAQBAo82y0U5dKF0n49kJiZ+H
# uSNo6CK4Bhn564iIdM4Cgi8RyiW2em9F3ZFbd+9qFyiYEqj1Qzs10wzO4VF9cbH1
# odj2k/hRxHEpKd0eR4Gnvv+KgMrTt0ch5+6Y7UyT24CgWuosmJoVWHNqYdpe4OoJ
# yM43cwXWs6OzNMPqNfKeFRmMEl/AzU97jR35vd3bxz8dwFd+GFYNHygZIIKMfJZY
# larYrnklzpHKYLTdv9FLypWQHnLw0mUPHW8uvs7YvwhKn+eXu2iaAwuU4Qzsmgue
# o3FkRFIrvvoM7cWMh6AjecbeMwd8LM24gC7Dnbcikxj5uniZ7WLXD0TUgzyoa9jN
# oYIDIDCCAxwGCSqGSIb3DQEJBjGCAw0wggMJAgEBMHcwYzELMAkGA1UEBhMCVVMx
# FzAVBgNVBAoTDkRpZ2lDZXJ0LCBJbmMuMTswOQYDVQQDEzJEaWdpQ2VydCBUcnVz
# dGVkIEc0IFJTQTQwOTYgU0hBMjU2IFRpbWVTdGFtcGluZyBDQQIQDE1pckuU+jwq
# Sj0pB4A9WjANBglghkgBZQMEAgEFAKBpMBgGCSqGSIb3DQEJAzELBgkqhkiG9w0B
# BwEwHAYJKoZIhvcNAQkFMQ8XDTIyMTExNzA4NTY0OFowLwYJKoZIhvcNAQkEMSIE
# IFgAjb3DJePfLjTP/e2nmCjFOunlrVZUbva5aYCUjRz2MA0GCSqGSIb3DQEBAQUA
# BIICAM8WEzsF7p5bedvECWNjj4e/6QZAtw2lsI/0k1dFeLrS+RNrAMHdGV4+OpZu
# /qIUDkTyiDMYJ07r10OR924bPGKaB9o1qH8mjHnERXGKzNqHJo9evgX9yIBwXvqx
# MXdRLSxkaEvXCOv5YwJVrzyTe2V2jUZputR7WChKxWXtfOchW+XMqd2EV6PAdOg6
# dSec/qoE4luC42FWZ79f81fEnoW6YqV01xAeoWPR8Y/UFZ7xVDUv+LJWGPVfvGnd
# 0KRmIIieZAhgkj4s3EbZUMzHbkmsuHBU3VYq4VvmQf3lGBmmIT9W0SNdTqBI1bB6
# Cy70h/pGLtyEuWmZsV0wlXSuHna1UD3SoIz6yMa1YNvP77vL309R46ju7EI0BVVO
# ioQecvdezulnL8fxQvoyzC3UZdvBW1d3tEi9RuV/cXllwqJNSamy0gXlUBQSAGyu
# mvTJuiE5Mk0vKm7biYbNGVxwu1Pdf0j0ZXwXAOF5FdccL0jTk6mrsSkI+u956hmp
# hCPMCpRuSQvmfUFMuAXzCmrQ/bjLv4GQ7PrWHXgTzqSJgt2qzL1QIRvtBM7iV4zr
# tekgeALoszMyJxf7geK/X1nMsX3qYd5bNnQKS+w5d6NE2rpBiNPN65gNo+rDSs9e
# mqGEeXz6OkoyIBmQWU0DKOkegD2PS0vS62pMfCS+8l/WpgpZ
# SIG # End signature block
