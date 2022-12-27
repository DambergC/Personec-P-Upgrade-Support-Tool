function Set-DbaDbState {
    <#
    .SYNOPSIS
        Sets various options for databases, hereby called "states"

    .DESCRIPTION
        Sets some common "states" on databases:
        - "RW" options (ReadOnly, ReadWrite)
        - "Status" options (Online, Offline, Emergency, plus a special "Detached")
        - "Access" options (SingleUser, RestrictedUser, MultiUser)

        Returns an object with SqlInstance, Database, RW, Status, Access, Notes

        Notes gets filled when something went wrong setting the state

    .PARAMETER SqlInstance
        The target SQL Server instance or instances

    .PARAMETER SqlCredential
        Login to the target instance using alternative credentials. Accepts PowerShell credentials (Get-Credential).

        Windows Authentication, SQL Server Authentication, Active Directory - Password, and Active Directory - Integrated are all supported.

        For MFA support, please use Connect-DbaInstance.

    .PARAMETER Database
        The database(s) to process - this list is auto-populated from the server. if unspecified, all databases will be processed.

    .PARAMETER ExcludeDatabase
        The database(s) to exclude - this list is auto-populated from the server

    .PARAMETER AllDatabases
        This is a parameter that was included for safety, so you don't accidentally set options on all databases without specifying

    .PARAMETER ReadOnly
        RW Option : Sets the database as READ_ONLY

    .PARAMETER ReadWrite
        RW Option : Sets the database as READ_WRITE

    .PARAMETER Online
        Status Option : Sets the database as ONLINE

    .PARAMETER Offline
        Status Option : Sets the database as OFFLINE

    .PARAMETER Emergency
        Status Option : Sets the database as EMERGENCY

    .PARAMETER Detached
        Status Option : Detaches the database

    .PARAMETER SingleUser
        Access Option : Sets the database as SINGLE_USER

    .PARAMETER RestrictedUser
        Access Option : Sets the database as RESTRICTED_USER

    .PARAMETER MultiUser
        Access Option : Sets the database as MULTI_USER

    .PARAMETER WhatIf
        Shows what would happen if the command were to run. No actions are actually performed.

    .PARAMETER Confirm
        Prompts you for confirmation before executing any changing operations within the command.

    .PARAMETER Force
        For most options, this translates to instantly rolling back any open transactions
        that may be stopping the process.
        For -Detached it is required to break mirroring and Availability Groups

    .PARAMETER EnableException
        By default, when something goes wrong we try to catch it, interpret it and give you a friendly warning message.
        This avoids overwhelming you with "sea of red" exceptions, but is inconvenient because it basically disables advanced scripting.
        Using this switch turns this "nice by default" feature off and enables you to catch exceptions with your own try/catch.

    .PARAMETER InputObject
        Accepts piped database objects

    .NOTES
        Tags: Database, State
        Author: Simone Bizzotto (@niphold)

        Website: https://dbatools.io
        Copyright: (c) 2018 by dbatools, licensed under MIT
        License: MIT https://opensource.org/licenses/MIT

    .LINK
        https://dbatools.io/Set-DbaDbState

    .EXAMPLE
        PS C:\> Set-DbaDbState -SqlInstance sqlserver2014a -Database HR -Offline

        Sets the HR database as OFFLINE

    .EXAMPLE
        PS C:\> Set-DbaDbState -SqlInstance sqlserver2014a -AllDatabases -Exclude HR -ReadOnly -Force

        Sets all databases of the sqlserver2014a instance, except for HR, as READ_ONLY

    .EXAMPLE
        PS C:\> Get-DbaDbState -SqlInstance sql2016 | Where-Object Status -eq 'Offline' | Set-DbaDbState -Online

        Finds all offline databases and sets them to online

    .EXAMPLE
        PS C:\> Set-DbaDbState -SqlInstance sqlserver2014a -Database HR -SingleUser

        Sets the HR database as SINGLE_USER

    .EXAMPLE
        PS C:\> Set-DbaDbState -SqlInstance sqlserver2014a -Database HR -SingleUser -Force

        Sets the HR database as SINGLE_USER, dropping all other connections (and rolling back open transactions)

    .EXAMPLE
        PS C:\> Get-DbaDatabase -SqlInstance sqlserver2014a -Database HR | Set-DbaDbState -SingleUser -Force

        Gets the databases from Get-DbaDatabase, and sets them as SINGLE_USER, dropping all other connections (and rolling back open transactions)

    #>
    [CmdletBinding(DefaultParameterSetName = "Default", SupportsShouldProcess, ConfirmImpact = "Medium")]
    param (
        [parameter(Mandatory, ValueFromPipelineByPropertyName, ParameterSetName = "Server")]
        [DbaInstanceParameter[]]$SqlInstance,
        [PSCredential]
        $SqlCredential,
        [object[]]$Database,
        [object[]]$ExcludeDatabase,
        [switch]$AllDatabases,
        [switch]$ReadOnly,
        [switch]$ReadWrite,
        [switch]$Online,
        [switch]$Offline,
        [switch]$Emergency,
        [switch]$Detached,
        [switch]$SingleUser,
        [switch]$RestrictedUser,
        [switch]$MultiUser,
        [switch]$Force,
        [switch]$EnableException,
        [parameter(Mandatory, ValueFromPipeline, ParameterSetName = "Database")]
        [PsCustomObject[]]$InputObject
    )

    begin {
        if ($Force) { $ConfirmPreference = 'none' }

        function Get-WrongCombo($optset, $allParams) {
            $x = 0
            foreach ($opt in $optset) {
                if ($allParams.ContainsKey($opt)) { $x += 1 }
            }
            if ($x -gt 1) {
                $msg = $optset -Join ',-'
                $msg = "You can only specify one of: -" + $msg
                throw $msg
            }
        }

        function Edit-DatabaseState($SqlInstance, $dbName, $opt, $immediate = $false) {
            $warn = $null
            $sql = "ALTER DATABASE [$dbName] SET $opt"
            if ($immediate) {
                $sql += " WITH ROLLBACK IMMEDIATE"
            } else {
                $sql += " WITH NO_WAIT"
            }
            try {
                Write-Message -Level System -Message $sql
                if ($immediate) {
                    # this can be helpful only for SINGLE_USER databases
                    # but since $immediate is called, it does no more harm
                    # than the immediate rollback
                    try {
                        $SqlInstance.KillAllProcesses($dbName)
                    } catch {
                        Write-Message -Level Verbose -Message "KillAllProcesses failed, moving on to WITH ROLLBACK IMMEDIATE"
                    }
                }
                $null = $SqlInstance.Query($sql)
            } catch {
                $warn = "Failed to set '$dbName' to $opt"
                Write-Message -Level Warning -Message $warn
            }
            return $warn
        }

        $statusHash = @{
            'Offline'       = 'OFFLINE'
            'Normal'        = 'ONLINE'
            'EmergencyMode' = 'EMERGENCY'
        }

        function Get-DbState($databaseName, $dbStatuses) {
            $base = $dbStatuses | Where-Object DatabaseName -ceq $databaseName
            foreach ($status in $statusHash.Keys) {
                if ($base.Status -match $status) {
                    $base.Status = $statusHash[$status]
                    break
                }
            }
            return $base
        }

        $RWExclusive = @('ReadOnly', 'ReadWrite')
        $statusExclusive = @('Online', 'Offline', 'Emergency', 'Detached')
        $accessExclusive = @('SingleUser', 'RestrictedUser', 'MultiUser')
        $allParams = $PSBoundParameters
        try {
            Get-WrongCombo -optset $RWExclusive -allparams $allParams
        } catch {
            Stop-Function -Message $_
            return
        }
        try {
            Get-WrongCombo -optset $statusExclusive -allparams $allParams
        } catch {
            Stop-Function -Message $_
            return
        }
        try {
            Get-WrongCombo -optset $accessExclusive -allparams $allParams
        } catch {
            Stop-Function -Message $_
            return
        }
    }
    process {
        if (Test-FunctionInterrupt) { return }
        $dbs = @()
        if (!$Database -and !$AllDatabases -and !$InputObject -and !$ExcludeDatabase) {
            Stop-Function -Message "You must specify a -AllDatabases or -Database to continue"
            return
        }

        if ($InputObject) {
            if ($InputObject.Database) {
                # comes from Get-DbaDbState
                $dbs += $InputObject.Database
            } elseif ($InputObject.Name) {
                # comes from Get-DbaDatabase
                $dbs += $InputObject
            }
        } else {
            foreach ($instance in $SqlInstance) {
                try {
                    $server = Connect-DbaInstance -SqlInstance $instance -SqlCredential $SqlCredential
                } catch {
                    Stop-Function -Message "Failure" -Category ConnectionError -ErrorRecord $_ -Target $instance -Continue
                }
                $all_dbs = $server.Databases
                $dbs += $all_dbs | Where-Object { @('master', 'model', 'msdb', 'tempdb', 'distribution') -notcontains $_.Name }

                if ($database) {
                    $dbs = $dbs | Where-Object { $database -contains $_.Name }
                }
                if ($ExcludeDatabase) {
                    $dbs = $dbs | Where-Object { $ExcludeDatabase -notcontains $_.Name }
                }
            }
        }

        # need to pick up here
        foreach ($db in $dbs) {
            if ($db.Name -in @('master', 'model', 'msdb', 'tempdb', 'distribution')) {
                Write-Message -Level Warning -Message "Database $db is a system one, skipping"
                Continue
            }
            $dbStatuses = @{ }
            $server = $db.Parent
            if ($server -notin $dbStatuses.Keys) {
                $dbStatuses[$server] = Get-DbaDbState -SqlInstance $server
            }

            # normalizing properties returned by SMO to something more "fixed"
            $db_status = Get-DbState -DatabaseName $db.Name -dbStatuses $dbStatuses[$server]


            $warn = @()

            if ($db.DatabaseSnapshotBaseName.Length -gt 0) {
                Write-Message -Level Warning -Message "Database $db is a snapshot, skipping"
                Continue
            }

            if ($ReadOnly -eq $true) {
                if ($db_status.RW -eq 'READ_ONLY') {
                    Write-Message -Level VeryVerbose -Message "Database $db is already READ_ONLY"
                } else {
                    if ($Pscmdlet.ShouldProcess($server, "Set $db to READ_ONLY")) {
                        Write-Message -Level VeryVerbose -Message "Setting database $db to READ_ONLY"
                        $partial = Edit-DatabaseState -sqlinstance $server -dbname $db.Name -opt "READ_ONLY" -immediate $Force
                        $warn += $partial
                        if (!$partial) {
                            $db_status.RW = 'READ_ONLY'
                        }
                    }
                }
            }

            if ($ReadWrite -eq $true) {
                if ($db_status.RW -eq 'READ_WRITE') {
                    Write-Message -Level VeryVerbose -Message "Database $db is already READ_WRITE"
                } else {
                    if ($Pscmdlet.ShouldProcess($server, "Set $db to READ_WRITE")) {
                        Write-Message -Level VeryVerbose -Message "Setting database $db to READ_WRITE"
                        $partial = Edit-DatabaseState -sqlinstance $server -dbname $db.Name -opt "READ_WRITE" -immediate $Force
                        $warn += $partial
                        if (!$partial) {
                            $db_status.RW = 'READ_WRITE'
                        }
                    }
                }
            }

            if ($Online -eq $true) {
                if ($db_status.Status -eq 'ONLINE') {
                    Write-Message -Level VeryVerbose -Message "Database $db is already ONLINE"
                } else {
                    if ($Pscmdlet.ShouldProcess($server, "Set $db to ONLINE")) {
                        Write-Message -Level VeryVerbose -Message "Setting database $db to ONLINE"
                        $partial = Edit-DatabaseState -sqlinstance $server -dbname $db.Name -opt "ONLINE" -immediate $Force
                        $warn += $partial
                        if (!$partial) {
                            $db_status.Status = 'ONLINE'
                        }
                    }
                }
            }

            if ($Offline -eq $true) {
                if ($db_status.Status -eq 'OFFLINE') {
                    Write-Message -Level VeryVerbose -Message "Database $db is already OFFLINE"
                } else {
                    if ($Pscmdlet.ShouldProcess($server, "Set $db to OFFLINE")) {
                        Write-Message -Level VeryVerbose -Message "Setting database $db to OFFLINE"
                        $partial = Edit-DatabaseState -sqlinstance $server -dbname $db.Name -opt "OFFLINE" -immediate $Force
                        $warn += $partial
                        if (!$partial) {
                            $db_status.Status = 'OFFLINE'
                        }
                    }
                }
            }

            if ($Emergency -eq $true) {
                if ($db_status.Status -eq 'EMERGENCY') {
                    Write-Message -Level VeryVerbose -Message "Database $db is already EMERGENCY"
                } else {
                    if ($Pscmdlet.ShouldProcess($server, "Set $db to EMERGENCY")) {
                        Write-Message -Level VeryVerbose -Message "Setting database $db to EMERGENCY"
                        $partial = Edit-DatabaseState -sqlinstance $server -dbname $db.Name -opt "EMERGENCY" -immediate $Force
                        if (!$partial) {
                            $db_status.Status = 'EMERGENCY'
                        }
                    }
                }
            }

            if ($SingleUser -eq $true) {
                if ($db_status.Access -eq 'SINGLE_USER') {
                    Write-Message -Level VeryVerbose -Message "Database $db is already SINGLE_USER"
                } else {
                    if ($Pscmdlet.ShouldProcess($server, "Set $db to SINGLE_USER")) {
                        Write-Message -Level VeryVerbose -Message "Setting $db to SINGLE_USER"
                        $partial = Edit-DatabaseState -sqlinstance $server -dbname $db.Name -opt "SINGLE_USER" -immediate $Force
                        if (!$partial) {
                            $db_status.Access = 'SINGLE_USER'
                        }
                    }
                }
            }

            if ($RestrictedUser -eq $true) {
                if ($db_status.Access -eq 'RESTRICTED_USER') {
                    Write-Message -Level VeryVerbose -Message "Database $db is already RESTRICTED_USER"
                } else {
                    if ($Pscmdlet.ShouldProcess($server, "Set $db to RESTRICTED_USER")) {
                        Write-Message -Level VeryVerbose -Message "Setting $db to RESTRICTED_USER"
                        $partial = Edit-DatabaseState -sqlinstance $server -dbname $db.Name -opt "RESTRICTED_USER" -immediate $Force
                        if (!$partial) {
                            $db_status.Access = 'RESTRICTED_USER'
                        }
                    }
                }
            }

            if ($MultiUser -eq $true) {
                if ($db_status.Access -eq 'MULTI_USER') {
                    Write-Message -Level VeryVerbose -Message "Database $db is already MULTI_USER"
                } else {
                    if ($Pscmdlet.ShouldProcess($server, "Set $db to MULTI_USER")) {
                        Write-Message -Level VeryVerbose -Message "Setting $db to MULTI_USER"
                        $partial = Edit-DatabaseState -sqlinstance $server -dbname $db.Name -opt "MULTI_USER" -immediate $Force
                        if (!$partial) {
                            $db_status.Access = 'MULTI_USER'
                        }
                    }
                }
            }

            if ($Detached -eq $true) {
                # Refresh info about database state here (before detaching)
                $db.Refresh()
                # we need to see what snaps are on the server, as base databases cannot be dropped
                $snaps = $server.Databases | Where-Object { $_.DatabaseSnapshotBaseName.Length -gt 0 }
                $snaps = $snaps.DatabaseSnapshotBaseName | Get-Unique
                if ($db.Name -in $snaps) {
                    Write-Message -Level Warning -Message "Database $db has snapshots, you need to drop them before detaching, skipping..."
                    Continue
                }
                if ($db.IsMirroringEnabled -eq $true -or $db.AvailabilityGroupName.Length -gt 0) {
                    if ($Force -eq $false) {
                        Write-Message -Level Warning -Message "Needs -Force to detach $db, skipping"
                        Continue
                    }
                }

                if ($db.IsMirroringEnabled) {
                    if ($Pscmdlet.ShouldProcess($server, "Break mirroring for $db")) {
                        try {
                            $db.ChangeMirroringState([Microsoft.SqlServer.Management.Smo.MirroringOption]::Off)
                            $db.Alter()
                            $db.Refresh()
                            Write-Message -Level VeryVerbose -Message "Broke mirroring for $db"
                        } catch {
                            Stop-Function -Message "Could not break mirror for $db. Skipping." -ErrorRecord $_ -Target $server -Continue
                        }
                    }
                }

                if ($db.AvailabilityGroupName) {
                    $agname = $db.AvailabilityGroupName
                    if ($Pscmdlet.ShouldProcess($server, "Removing $db from AG [$agname]")) {
                        try {
                            $server.AvailabilityGroups[$db.AvailabilityGroupName].AvailabilityDatabases[$db.Name].Drop()
                            Write-Message -Level VeryVerbose -Message "Successfully removed $db from AG [$agname] on $server"
                        } catch {
                            Stop-Function -Message "Could not remove $db from AG [$agname] on $server" -ErrorRecord $_ -Target $server -Continue
                        }
                    }
                }

                # DBA 101 should encourage detaching just OFFLINE databases
                # we can do that here
                if ($Pscmdlet.ShouldProcess($server, "Detaching $db")) {
                    if ($db_status.Status -ne 'OFFLINE') {
                        $null = Edit-DatabaseState -sqlinstance $server -dbname $db.Name -opt "OFFLINE" -immediate $true
                    }
                    try {
                        $sql = "EXEC master.dbo.sp_detach_db N'$($db.Name)'"
                        Write-Message -Level System -Message $sql
                        $null = $server.Query($sql)
                        $db_status.Status = 'DETACHED'
                    } catch {
                        Stop-Function -Message "Failed to detach $db" -ErrorRecord $_ -Target $server -Continue
                        $warn += "Failed to detach"
                    }

                }

            }
            if ($warn) {
                $warn = $warn | Where-Object { $_ } | Get-Unique
                $warn = $warn -Join ';'
            } else {
                $warn = $null
            }
            if ($Detached -eq $true) {
                [PSCustomObject]@{
                    ComputerName = $server.ComputerName
                    InstanceName = $server.ServiceName
                    SqlInstance  = $server.DomainInstanceName
                    DatabaseName = $db.Name
                    RW           = $db_status.RW
                    Status       = $db_status.Status
                    Access       = $db_status.Access
                    Notes        = $warn
                    Database     = $db
                } | Select-DefaultView -ExcludeProperty Database
            } else {
                $db.Refresh()
                if ($null -eq $warn) {
                    # we avoid reenumerating properties
                    $newstate = $db_status
                } else {
                    $newstate = Get-DbState -databaseName $db.Name -dbStatuses $dbStatuses[$server]
                }

                [PSCustomObject]@{
                    ComputerName = $server.ComputerName
                    InstanceName = $server.ServiceName
                    SqlInstance  = $server.DomainInstanceName
                    DatabaseName = $db.Name
                    RW           = $newstate.RW
                    Status       = $newstate.Status
                    Access       = $newstate.Access
                    Notes        = $warn
                    Database     = $db
                } | Select-DefaultView -ExcludeProperty Database
            }
        }

    }
}
# SIG # Begin signature block
# MIIjYAYJKoZIhvcNAQcCoIIjUTCCI00CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCA5Hg7PRNyFKOU0
# djaxkPRQdnDBRmKEEK7zhyT2KFX3jqCCHVkwggUaMIIEAqADAgECAhADBbuGIbCh
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
# BgorBgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCDm1vbMBN7Gwn7Ac5O2XfpM0zsV
# CKEjvVah3wvaeEmYSDANBgkqhkiG9w0BAQEFAASCAQBpIMx0WooE0MdDsZg+lQ6h
# Ex4Ub34LynviuqKB8alWgOlh4QkUOhNz2FIPLYGg41A59sAb2r7AfQIVBevTdAgR
# roD86fwWsJL/6BkN3X3FyT1pen4lGY1MH8QQ/GKG915pwd1BROhBQSFObTLVgyJ0
# fC0HTheldgw/QCYtEjsk9aVfjvrkU4pHYiefVL84iVkSOPTVNCNMTerXxw0OKB1l
# 6zpQQaCt7SwVI/r+U81PHlqt6T9YyEcjykLu3fSi68FCPRgbvx8yPttJxzJqdIHn
# oh966NmD9BEz4T+tN/BU0QZGXj/UhBnwHk0BK+1GzW5VYzeziL6XUXF2MVAl5AZj
# oYIDIDCCAxwGCSqGSIb3DQEJBjGCAw0wggMJAgEBMHcwYzELMAkGA1UEBhMCVVMx
# FzAVBgNVBAoTDkRpZ2lDZXJ0LCBJbmMuMTswOQYDVQQDEzJEaWdpQ2VydCBUcnVz
# dGVkIEc0IFJTQTQwOTYgU0hBMjU2IFRpbWVTdGFtcGluZyBDQQIQDE1pckuU+jwq
# Sj0pB4A9WjANBglghkgBZQMEAgEFAKBpMBgGCSqGSIb3DQEJAzELBgkqhkiG9w0B
# BwEwHAYJKoZIhvcNAQkFMQ8XDTIyMTExNzA4NTczMlowLwYJKoZIhvcNAQkEMSIE
# IPKhRpOexUHFgcRY63Z074G+IQWqnWz99Rq7YIgOCrS8MA0GCSqGSIb3DQEBAQUA
# BIICAEjVT/UPTJLBl05ZcJ9qqzleRR7c+fG+Y/ozLPE9RbncHW1vuS0eBlSq8wez
# lg3S0Txwr2U2vrIe7jzhFeJwmYhVs0eE08Qt4BFJWQsxDqw+eYMDUjc7n0Gzj8iM
# Pe9rJRk0D5YumwYxREbmprNeyt147c3BLw+xSpenbqy73Kr+aFZPGpctX04lyw23
# YMBLc2/wN4sTNtEuC7Bbp/RH93R9IRe+h7GswnkMDqkt2Gk9fmRmRp8kE02L+v+Z
# RapeaC676yGs2MiCt3FdgYdZ2FbhrkgGkX1WLBWd2BW1k9ztTR7nkvztOZ+3OTyY
# m9ZwVYzp3IPUOFdPtfXUWdWRH4Vn6ZjsQtwNaMTySwstvN1zgZCB1e5WTUG7c1tz
# JwMNyi/9f/Bnl7lTr8lekZXa7LZRZKIyQOhfDqMjimQAsrMmsOG/bpCuGm36kKQ4
# PXaSZnctWCV8yocTaQsbn3Kkkj9QfNcgBN0dUKrxmTKihQ4t4elNSRy4QjPIRT9V
# aWU5EBfErvWNmNYkS+qfcI2XtRscJgWJxJ/fyCiusBDigOdeRFbsW1LloXGHqXd+
# IqeMeEog/c6GS8zn7a5GynwOYU7e4QV+eFoTKT0eivqSfw1AVb6430Ha5n/eyTp3
# 9y/i4mBqq6l4sl2RUqNPckiQm6JyXv3KVvxFb4rnsOb1eepB
# SIG # End signature block
