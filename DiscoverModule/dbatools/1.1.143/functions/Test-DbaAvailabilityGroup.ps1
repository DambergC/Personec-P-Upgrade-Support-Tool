function Test-DbaAvailabilityGroup {
    <#
    .SYNOPSIS
        Tests the health of an Availability Group and prerequisites for changing it.

    .DESCRIPTION
        Tests the health of an Availability Group.

        Can also test whether all prerequisites for Add-DbaAgDatabase are met.

    .PARAMETER SqlInstance
        The primary replica of the Availability Group.

    .PARAMETER SqlCredential
        Login to the target instance using alternative credentials. Accepts PowerShell credentials (Get-Credential).

        Windows Authentication, SQL Server Authentication, Active Directory - Password, and Active Directory - Integrated are all supported.

        For MFA support, please use Connect-DbaInstance.

    .PARAMETER AvailabilityGroup
        The name of the Availability Group to test.

    .PARAMETER Secondary
        Not required - the command will figure this out. But use this parameter if secondary replicas listen on a non default port.

    .PARAMETER SecondarySqlCredential
        Login to the target instance using alternative credentials. Accepts PowerShell credentials (Get-Credential).

        Windows Authentication, SQL Server Authentication, Active Directory - Password, and Active Directory - Integrated are all supported.

        For MFA support, please use Connect-DbaInstance.

    .PARAMETER AddDatabase
        Test whether all prerequisites for Add-DbaAgDatabase to add these databases to the Availability Group are met.

        Use Secondary, SecondarySqlCredential, SeedingMode, SharedPath and UseLastBackup with the same values that will be used with Add-DbaAgDatabase later.

    .PARAMETER SeedingMode
        Only used when AddDatabase is used. See documentation at Add-DbaAgDatabase for more details.

    .PARAMETER SharedPath
        Only used when AddDatabase is used. See documentation at Add-DbaAgDatabase for more details.

    .PARAMETER UseLastBackup
        Only used when AddDatabase is used. See documentation at Add-DbaAgDatabase for more details.

    .PARAMETER EnableException
        By default, when something goes wrong we try to catch it, interpret it and give you a friendly warning message.
        This avoids overwhelming you with "sea of red" exceptions, but is inconvenient because it basically disables advanced scripting.
        Using this switch turns this "nice by default" feature off and enables you to catch exceptions with your own try/catch.

    .NOTES
        Tags: AvailabilityGroup, HA, AG, Test
        Author: Andreas Jordan (@JordanOrdix), ordix.de

        Website: https://dbatools.io
        Copyright: (c) 2021 by dbatools, licensed under MIT
        License: MIT https://opensource.org/licenses/MIT

    .LINK
        https://dbatools.io/Test-DbaAvailabilityGroup

    .EXAMPLE
        PS C:\> Test-DbaAvailabilityGroup -SqlInstance SQL2016 -AvailabilityGroup TestAG1

        Test Availability Group TestAG1 with SQL2016 as the primary replica.

    .EXAMPLE
        PS C:\> Test-DbaAvailabilityGroup -SqlInstance SQL2016 -AvailabilityGroup TestAG1 -AddDatabase AdventureWorks -SeedingMode Automatic

        Test if database AdventureWorks can be added to the Availability Group TestAG1 with automatic seeding.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, Position = 0)]
        [DbaInstanceParameter]$SqlInstance,
        [PSCredential]$SqlCredential,
        [Parameter(Mandatory = $true)]
        [string]$AvailabilityGroup,
        [DbaInstanceParameter[]]$Secondary,
        [PSCredential]$SecondarySqlCredential,
        [string[]]$AddDatabase,
        [ValidateSet('Automatic', 'Manual')]
        [string]$SeedingMode,
        [string]$SharedPath,
        [switch]$UseLastBackup,
        [switch]$EnableException
    )
    process {
        try {
            $server = Connect-DbaInstance -SqlInstance $SqlInstance -SqlCredential $SqlCredential
        } catch {
            Stop-Function -Message "Failure" -Category ConnectionError -ErrorRecord $_ -Target $SqlInstance
            return
        }

        try {
            $ag = Get-DbaAvailabilityGroup -SqlInstance $server -AvailabilityGroup $AvailabilityGroup -EnableException
        } catch {
            Stop-Function -Message "Availability Group $AvailabilityGroup not found on $server." -ErrorRecord $_
            return
        }

        if (-not $ag) {
            Stop-Function -Message "Availability Group $AvailabilityGroup not found on $server."
            return
        }

        if ($ag.LocalReplicaRole -ne 'Primary') {
            Stop-Function -Message "LocalReplicaRole of replica $server is not Primary, but $($ag.LocalReplicaRole). Please connect to the current primary replica $($ag.PrimaryReplica)."
            return
        }

        # Test for health of Availability Group

        # Later: Get replica and database states like in SSMS dashboard
        # Now: Just test for ConnectionState -eq 'Connected'

        # Note on further development:
        # As long as there are no databases in the Availability Group, test for RollupSynchronizationState is not useful

        # The primary replica always has the best information about all the replicas.
        # We can maybe also connect to the secondary replicas and test their view of the situation, but then only test the local replica.

        $failure = $false
        foreach ($replica in $ag.AvailabilityReplicas) {
            if ($replica.ConnectionState -ne 'Connected') {
                $failure = $true
                Stop-Function -Message "ConnectionState of replica $replica is not Connected, but $($replica.ConnectionState)." -Continue
            }
        }
        if ($failure) {
            Stop-Function -Message "ConnectionState of one or more replicas is not Connected."
            return
        }


        # For now, just output the base information.

        if (-not $AddDatabase) {
            [PSCustomObject]@{
                ComputerName      = $ag.ComputerName
                InstanceName      = $ag.InstanceName
                SqlInstance       = $ag.SqlInstance
                AvailabilityGroup = $ag.AvailabilityGroup
            }
        }


        # Test for Add-DbaAgDatabase

        foreach ($dbName in $AddDatabase) {
            $db = $server.Databases[$dbName]

            if ($SeedingMode -eq 'Automatic' -and $server.VersionMajor -lt 13) {
                Stop-Function -Message "Automatic seeding mode only supported in SQL Server 2016 and above" -Target $server
                return
            }

            if (-not $db) {
                Stop-Function -Message "Database $db is not found on $server." -Continue
            }

            if ($db.RecoveryModel -ne 'Full') {
                Stop-Function -Message "RecoveryModel of database $db is not Full, but $($db.RecoveryModel)." -Continue
            }

            if ($db.Status -ne 'Normal') {
                Stop-Function -Message "Status of database $db is not Normal, but $($db.Status)." -Continue
            }

            $backups = @( )
            if ($UseLastBackup) {
                try {
                    $backups = Get-DbaDbBackupHistory -SqlInstance $server -Database $db.Name -IncludeCopyOnly -Last -EnableException
                } catch {
                    Stop-Function -Message "Failed to get backup history for database $db." -ErrorRecord $_ -Continue
                }
                if ($backups.Type -notcontains 'Log') {
                    Stop-Function -Message "Cannot use last backup for database $db. A log backup must be the last backup taken." -Continue
                }
            }

            if ($SeedingMode -eq 'Automatic' -and $server.VersionMajor -lt 13) {
                Stop-Function -Message "Automatic seeding mode only supported in SQL Server 2016 and above." -Continue
            }

            # Try to connect to secondary replicas as soon as possible to fail the command before making any changes to the Availability Group.
            # Also test if these are really secondary replicas for that availability group. Only needed if -Secondary is used, but will do it anyway to simplify code.
            # Also test if database is already at the secondary and if so if Status is Restoring.
            # We store the server SMO in a hashtable based on the DomainInstanceName of the server as this is equal to the name of the replica in $ag.AvailabilityReplicas.
            if ($Secondary) {
                $secondaryReplicas = $Secondary
            } else {
                $secondaryReplicas = ($ag.AvailabilityReplicas | Where-Object { $_.Role -eq 'Secondary' }).Name
            }

            $replicaServerSMO = @{ }
            $restoreNeeded = @{ }
            $backupNeeded = $false
            $failure = $false
            foreach ($replica in $secondaryReplicas) {
                try {
                    $replicaServer = Connect-DbaInstance -SqlInstance $replica -SqlCredential $SecondarySqlCredential
                } catch {
                    $failure = $true
                    Stop-Function -Message "Failure" -Category ConnectionError -ErrorRecord $_ -Target $replica -Continue
                }

                try {
                    $replicaAg = Get-DbaAvailabilityGroup -SqlInstance $replicaServer -AvailabilityGroup $AvailabilityGroup -EnableException
                    $replicaName = $replicaAg.Parent.DomainInstanceName
                } catch {
                    $failure = $true
                    Stop-Function -Message "Availability Group $AvailabilityGroup not found on replica $replicaServer." -ErrorRecord $_ -Continue
                }

                if (-not $replicaAg) {
                    $failure = $true
                    Stop-Function -Message "Availability Group $AvailabilityGroup not found on replica $replicaServer." -Continue
                }

                if ($replicaAg.LocalReplicaRole -ne 'Secondary') {
                    $failure = $true
                    Stop-Function -Message "LocalReplicaRole of replica $replicaServer is not Secondary, but $($replicaAg.LocalReplicaRole)." -Continue
                }

                $replicaDb = $replicaAg.Parent.Databases[$db.Name]

                if ($replicaDb) {
                    # Database already present on replica, so test if already joined or if we can use it.
                    if ($replicaDb.AvailabilityGroupName -eq $AvailabilityGroup) {
                        Write-Message -Level Verbose -Message "Database $db is already part of the Availability Group on replica $replicaName."
                    } else {
                        if ($replicaDb.Status -ne 'Restoring') {
                            $failure = $true
                            Stop-Function -Message "Status of database $db on replica $replicaName is not Restoring, but $($replicaDb.Status)" -Continue
                        }
                        if ($UseLastBackup) {
                            $failure = $true
                            Stop-Function -Message "Database $db is already present on $replicaName, so -UseLastBackup must not be used. Please remove database from replica to use -UseLastBackup." -Continue
                        }
                        Write-Message -Level Verbose -Message "Database $db is already present in restoring status on replica $replicaName."
                    }
                } else {
                    # No database on replica, so test if we need a backup.
                    # We need to restore a backup if the desired or the current seeding mode is manual.
                    # To have a detailed verbose message, we test in small steps.
                    if ($SeedingMode -eq 'Automatic') {
                        if ($ag.AvailabilityReplicas[$replicaName].SeedingMode -eq 'Automatic') {
                            Write-Message -Level Verbose -Message "Database $db will use automatic seeding on replica $replicaName. The replica is already configured accordingly."
                        } else {
                            Write-Message -Level Verbose -Message "Database $db will use automatic seeding on replica $replicaName. The replica will be configured accordingly."
                        }
                        if ($db.LastBackupDate.Year -eq 1) {
                            # Automatic seeding only works with databases that are really in RecoveryModel Full, so a full backup has been taken.
                            Write-Message -Level Verbose -Message "Database $db will need a backup first. This is ok if one of the other replicas uses manual seeding."
                            $backupNeeded = $true
                        }
                    } elseif ($SeedingMode -eq 'Manual') {
                        if ($ag.AvailabilityReplicas[$replicaName].SeedingMode -eq 'Manual') {
                            Write-Message -Level Verbose -Message "Database $db will need a restore on replica $replicaName. The replica is already configured accordingly."
                        } else {
                            Write-Message -Level Verbose -Message "Database $db will need a restore on replica $replicaName. The replica will be configured accordingly."
                        }
                        $restoreNeeded[$replicaName] = $true
                    } else {
                        if ($ag.AvailabilityReplicas[$replicaName].SeedingMode -eq 'Automatic') {
                            Write-Message -Level Verbose -Message "Database $db will use automatic seeding on replica $replicaName."
                            if ($db.LastBackupDate.Year -eq 1) {
                                # Automatic seeding only works with databases that are really in RecoveryModel Full, so a full backup has been taken.
                                Write-Message -Level Verbose -Message "Database $db will need a backup first. This is ok if one of the other replicas uses manual seeding."
                                $backupNeeded = $true
                            }
                        } else {
                            Write-Message -Level Verbose -Message "Database $db will need a restore on replica $replicaName."
                            $restoreNeeded[$replicaName] = $true
                        }
                    }
                }
                $replicaServerSMO[$replicaName] = $replicaAg.Parent
            }
            if ($failure) {
                Stop-Function -Message "Availability Group $AvailabilityGroup or database $db not found in suitable state on all secondary replicas." -Continue
            }
            if ($restoreNeeded.Count -gt 0 -and -not $SharedPath -and -not $UseLastBackup) {
                Stop-Function -Message "A restore of database $db is needed on one or more replicas, but -SharedPath or -UseLastBackup are missing." -Continue
            }
            if ($backupNeeded -and $restoreNeeded.Count -eq 0) {
                Stop-Function -Message "All replicas are configured to use automatic seeding, but the database $db was never backed up. Please backup the database or use manual seeding." -Continue
            }

            [PSCustomObject]@{
                ComputerName          = $ag.ComputerName
                InstanceName          = $ag.InstanceName
                SqlInstance           = $ag.SqlInstance
                AvailabilityGroupName = $ag.Name
                DatabaseName          = $db.Name
                AvailabilityGroupSMO  = $ag
                DatabaseSMO           = $db
                PrimaryServerSMO      = $server
                ReplicaServerSMO      = $replicaServerSMO
                RestoreNeeded         = $restoreNeeded
                Backups               = $backups
            }
        }
    }
}
# SIG # Begin signature block
# MIIjYAYJKoZIhvcNAQcCoIIjUTCCI00CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCBAzdvwskTJ0IzO
# o01bo/I6PczzU1xhEwYr3MJYfa+4gKCCHVkwggUaMIIEAqADAgECAhADBbuGIbCh
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
# BgorBgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCC6cx9ke4xGgyAkXQDGosLldzVE
# ZUZa8U6xj3FP9KLXOTANBgkqhkiG9w0BAQEFAASCAQBOjWvdw4jnuReDjFeLFFGc
# dEgfsq/vkJSHdgxZepAlJ5Crf73fvbPaUAhqhQV5yf29DD5ct38op28ZKpmUDnY2
# KrzaM7pLxbj9dnYWZZKU/GEtAMbJ2bkn9duZnFXUits28/Mk+dv2DYJ6qplYt5kD
# b2FAOuWpfks4OrqlF8SJytZFaBrezMMenJCJiJm2/mn2dvgZ6SyX/YQeIAGfxx7o
# P+8tj9ZcdBenGATjCpUVLt06Y5H7y2VAXJQ7rWUYB5+3FWSJwY7AL6peU2L59IY/
# jeW6onk1wnR3Io2/l0mDy0ekMOVjvS5Y+3LiKcwRObq0kL2rWuw2sumdJDOgX2Ot
# oYIDIDCCAxwGCSqGSIb3DQEJBjGCAw0wggMJAgEBMHcwYzELMAkGA1UEBhMCVVMx
# FzAVBgNVBAoTDkRpZ2lDZXJ0LCBJbmMuMTswOQYDVQQDEzJEaWdpQ2VydCBUcnVz
# dGVkIEc0IFJTQTQwOTYgU0hBMjU2IFRpbWVTdGFtcGluZyBDQQIQDE1pckuU+jwq
# Sj0pB4A9WjANBglghkgBZQMEAgEFAKBpMBgGCSqGSIb3DQEJAzELBgkqhkiG9w0B
# BwEwHAYJKoZIhvcNAQkFMQ8XDTIyMTExNzA4NTc0NFowLwYJKoZIhvcNAQkEMSIE
# IIIcNA8QFXOnU/mjdwfGrjyex8oFWzsjTWz1iVh7n/BsMA0GCSqGSIb3DQEBAQUA
# BIICAH7Rr5syiqC5ZRtbG1eUFz9IYpSpqOZIRKuzZi+e3yPo/V78Q2zDkajkoZTE
# hxCOo/qMw9MIK9As5rW1kop5VTjgG2kIl2SpX8DNpT26EDENh5LdkizoRHOZadjW
# 2HirCcFDVRY5lykmXqauAqHnmWbMekWUd8EV4gPxyBEtS9NrdZ8NEyTeZ9GpTHvx
# kGYTjooR1o2JFOlAbblIx6erwe5ei1xIfRugGIU3AwwzFVh0OAp8HZ5vnYbL0/Je
# BDeGPoPcdspVKnqoN0B3up9VE62ggWPD7I0ksOaTON22WPHChXUb1tEPM/J7Lx5E
# lJNDpO15J+uM+pkFAJLGZLQCms0TGEdcmoMuVgndJx2xgHRzy9jtK04nTjNq0VRD
# IuSLgbwB5yAm5MaPrBldoT94Ixi7jzWmIF2pAr88BEHb2G1AEAabp7gzjB45HtmP
# 2NnIexc7nzl/VFNBHlgV73/Me0vMqdNH3iCr+Nu1bbc9c/ldvae+3hYq6ZWRyt6I
# sc39oXDXVNFAQSQJW0itFKX7dAzTeI7JzeQhvZvViqKRPZx9/Eo8AVLNIx03Cwfr
# +2yHIR8ILQSxbwRBYUZz9L9kIDlsGtMS4bfhXcoK3G86LFSfldeIlg70HlZ6gRyK
# N23YT9MEcRfua/1aJ7DH/B//5YeRHB4XcCvU+W+KWN8UdjlX
# SIG # End signature block
