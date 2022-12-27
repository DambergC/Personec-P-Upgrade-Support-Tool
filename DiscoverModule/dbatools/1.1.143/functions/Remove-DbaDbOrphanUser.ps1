function Remove-DbaDbOrphanUser {
    <#
    .SYNOPSIS
        Drop orphan users with no existing login to map

    .DESCRIPTION
        Allows the removal of orphan users from one or more databases

        Orphaned users in SQL Server occur when a database user is based on a login in the master database, but the login no longer exists in master.
        This can occur when the login is deleted, or when the database is moved to another server where the login does not exist.

        If user is the owner of the schema with the same name and if if the schema does not have any underlying objects the schema will be dropped.

        If user owns more than one schema, the owner of the schemas that does not have the same name as the user, will be changed to 'dbo'. If schemas have underlying objects, you must specify the -Force parameter so the user can be dropped.

        If a login of the same name exists (which could be re-mapped with Repair-DbaDbOrphanUser)  the drop will not be performed unless you specify the -Force parameter (only when calling from Repair-DbaDbOrphanUser.

    .PARAMETER SqlInstance
        The target SQL Server instance or instances.

    .PARAMETER SqlCredential
        Login to the target instance using alternative credentials. Accepts PowerShell credentials (Get-Credential).

        Windows Authentication, SQL Server Authentication, Active Directory - Password, and Active Directory - Integrated are all supported.

        For MFA support, please use Connect-DbaInstance.

    .PARAMETER Database
        Specifies the database(s) to process. Options for this list are auto-populated from the server. If unspecified, all databases will be processed.

    .PARAMETER ExcludeDatabase
        Specifies the database(s) to exclude from processing. Options for this list are auto-populated from the server

    .PARAMETER User
        Specifies the list of users to remove.

    .PARAMETER Force
        If this switch is enabled:
        If exists any schema which owner is the User, this will force the change of the owner to 'dbo'.
        If a login of the same name exists the drop will not be performed unless you specify this parameter.

    .PARAMETER WhatIf
        If this switch is enabled, no actions are performed but informational messages will be displayed that explain what would happen if the command were to run.

    .PARAMETER Confirm
        If this switch is enabled, you will be prompted for confirmation before executing any operations that change state.

    .PARAMETER EnableException
        By default, when something goes wrong we try to catch it, interpret it and give you a friendly warning message.
        This avoids overwhelming you with "sea of red" exceptions, but is inconvenient because it basically disables advanced scripting.
        Using this switch turns this "nice by default" feature off and enables you to catch exceptions with your own try/catch.

    .NOTES
        Tags: User, Orphan, Login
        Author: Claudio Silva (@ClaudioESSilva) | Simone Bizzotto (@niphlod)

        Website: https://dbatools.io
        Copyright: (c) 2018 by dbatools, licensed under MIT
        License: MIT https://opensource.org/licenses/MIT

    .LINK
        https://dbatools.io/Remove-DbaDbOrphanUser

    .EXAMPLE
        PS C:\> Remove-DbaDbOrphanUser -SqlInstance sql2005

        Finds and drops all orphan users without matching Logins in all databases present on server 'sql2005'.

    .EXAMPLE
        PS C:\> Remove-DbaDbOrphanUser -SqlInstance sqlserver2014a -SqlCredential $cred

        Finds and drops all orphan users without matching Logins in all databases present on server 'sqlserver2014a'. SQL Server authentication will be used in connecting to the server.

    .EXAMPLE
        PS C:\> Remove-DbaDbOrphanUser -SqlInstance sqlserver2014a -Database db1, db2 -Force

        Finds and drops orphan users even if they have a matching Login on both db1 and db2 databases.

    .EXAMPLE
        PS C:\> Remove-DbaDbOrphanUser -SqlInstance sqlserver2014a -ExcludeDatabase db1, db2 -Force

        Finds and drops orphan users even if they have a matching Login from all databases except db1 and db2.

    .EXAMPLE
        PS C:\> Remove-DbaDbOrphanUser -SqlInstance sqlserver2014a -User OrphanUser

        Removes user OrphanUser from all databases only if there is no matching login.

    .EXAMPLE
        PS C:\> Remove-DbaDbOrphanUser -SqlInstance sqlserver2014a -User OrphanUser -Force

        Removes user OrphanUser from all databases even if they have a matching Login. Any schema that the user owns will change ownership to dbo.

    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = "Medium")]
    param (
        [parameter(Mandatory, ValueFromPipeline)]
        [DbaInstanceParameter[]]$SqlInstance,
        [PSCredential]
        $SqlCredential,
        [object[]]$Database,
        [object[]]$ExcludeDatabase,
        [parameter(ValueFromPipeline)]
        [object[]]$User,
        [switch]$Force,
        [switch]$EnableException
    )
    begin {
        if ($Force) { $ConfirmPreference = 'none' }

        $eol = [System.Environment]::NewLine
    }
    process {
        foreach ($Instance in $SqlInstance) {
            try {
                $server = Connect-DbaInstance -SqlInstance $Instance -SqlCredential $SqlCredential
            } catch {
                Stop-Function -Message "Failure" -Category ConnectionError -ErrorRecord $_ -Target $instance -Continue
            }

            $DatabaseCollection = $server.Databases | Where-Object IsAccessible

            if ($Database) {
                $DatabaseCollection = $DatabaseCollection | Where-Object Name -In $Database
            }
            if ($ExcludeDatabase) {
                $DatabaseCollection = $DatabaseCollection | Where-Object Name -NotIn $ExcludeDatabase
            }

            $CallStack = Get-PSCallStack | Select-Object -Property *
            if ($CallStack.Count -eq 1) {
                $StackSource = $CallStack[0].Command
            } else {
                #-2 because index base is 0 and we want the one before the last (the last is the actual command)
                $StackSource = $CallStack[($CallStack.Count - 2)].Command
            }

            if ($DatabaseCollection) {
                foreach ($db in $DatabaseCollection) {
                    try {
                        #if SQL 2012 or higher only validate databases with ContainmentType = NONE
                        if ($server.versionMajor -gt 10) {
                            if ($db.ContainmentType -ne [Microsoft.SqlServer.Management.Smo.ContainmentType]::None) {
                                Write-Message -Level Warning -Message "Database '$db' is a contained database. Contained databases can't have orphaned users. Skipping validation."
                                Continue
                            }
                        }

                        if ($StackSource -eq "Repair-DbaDbOrphanUser") {
                            Write-Message -Level Verbose -Message "Call origin: Repair-DbaDbOrphanUser."
                            #Will use collection from parameter ($User)
                            $users = $User
                        } else {
                            Write-Message -Level Verbose -Message "Validating users on database $db."

                            $users = (Get-DbaDbOrphanUser -SqlInstance $server -Database $db.Name).SmoUser
                            if ($User.Count -gt 0) {
                                $users = $users | Where-Object { $User -contains $_.Name }
                            }
                        }

                        if ($users.Count -gt 0) {
                            Write-Message -Level Verbose -Message "Orphan users found."
                            foreach ($dbuser in $users) {
                                $SkipUser = $false

                                $ExistLogin = $null

                                if ($StackSource -ne "Repair-DbaDbOrphanUser") {
                                    #Need to validate Existing Login because the call does not came from Repair-DbaDbOrphanUser
                                    $ExistLogin = $server.logins | Where-Object {
                                        $_.Isdisabled -eq $False -and
                                        $_.IsSystemObject -eq $False -and
                                        $_.IsLocked -eq $False -and
                                        $_.Name -eq $dbuser.Name
                                    }
                                }

                                #Schemas only appears on SQL Server 2005 (v9.0)
                                if ($server.versionMajor -gt 8) {

                                    #reset variables
                                    $AlterSchemaOwner = ""
                                    $DropSchema = ""

                                    #Validate if user owns any schema
                                    $Schemas = @()
                                    $Schemas = $db.Schemas | Where-Object Owner -eq $dbuser.Name

                                    if (@($Schemas).Count -gt 0) {
                                        Write-Message -Level Verbose -Message "User $dbuser owns one or more schemas."

                                        foreach ($sch in $Schemas) {
                                            <#
                                                On sql server 2008 or lower the EnumObjects method does not accept empty parameter.
                                                0x1FFFFFFF is the way we can say we want everything known by those versions

                                                When it is a higher version we can use empty to get all
                                            #>
                                            if ($server.versionMajor -lt 11) {
                                                $NumberObjects = ($db.EnumObjects(0x1FFFFFFF) | Where-Object { $_.Schema -eq $sch.Name } | Measure-Object).Count
                                            } else {
                                                $NumberObjects = ($db.EnumObjects() | Where-Object { $_.Schema -eq $sch.Name } | Measure-Object).Count
                                            }

                                            if ($NumberObjects -gt 0) {
                                                if ($Force) {
                                                    Write-Message -Level Verbose -Message "Parameter -Force was used! The schema '$($sch.Name)' have $NumberObjects underlying objects. We will change schema owner to 'dbo' and drop the user."

                                                    if ($Pscmdlet.ShouldProcess($db.Name, "Changing schema '$($sch.Name)' owner to 'dbo'. -Force used.")) {
                                                        $AlterSchemaOwner += "ALTER AUTHORIZATION ON SCHEMA::[$($sch.Name)] TO [dbo]$eol"

                                                        [pscustomobject]@{
                                                            ComputerName      = $server.ComputerName
                                                            InstanceName      = $server.ServiceName
                                                            SqlInstance       = $server.DomainInstanceName
                                                            DatabaseName      = $db.Name
                                                            SchemaName        = $sch.Name
                                                            Action            = "ALTER OWNER"
                                                            SchemaOwnerBefore = $sch.Owner
                                                            SchemaOwnerAfter  = "dbo"
                                                        }
                                                    }
                                                } else {
                                                    Write-Message -Level Warning -Message "Schema '$($sch.Name)' owned by user $($dbuser.Name) have $NumberObjects underlying objects. If you want to change the schemas' owner to 'dbo' and drop the user anyway, use -Force parameter. Skipping user '$dbuser'."
                                                    $SkipUser = $true
                                                    break
                                                }
                                            } else {
                                                if ($sch.Name -eq $dbuser.Name) {
                                                    Write-Message -Level Verbose -Message "The schema '$($sch.Name)' have the same name as user $dbuser. Schema will be dropped."

                                                    if ($Pscmdlet.ShouldProcess($db.Name, "Dropping schema '$($sch.Name)'.")) {
                                                        $DropSchema += "DROP SCHEMA [$($sch.Name)]"

                                                        [pscustomobject]@{
                                                            ComputerName      = $server.ComputerName
                                                            InstanceName      = $server.ServiceName
                                                            SqlInstance       = $server.DomainInstanceName
                                                            DatabaseName      = $db.Name
                                                            SchemaName        = $sch.Name
                                                            Action            = "DROP"
                                                            SchemaOwnerBefore = $sch.Owner
                                                            SchemaOwnerAfter  = "N/A"
                                                        }
                                                    }
                                                } else {
                                                    Write-Message -Level Warning -Message "Schema '$($sch.Name)' does not have any underlying object. Ownership will be changed to 'dbo' so the user can be dropped. Remember to re-check permissions on this schema."

                                                    if ($Pscmdlet.ShouldProcess($db.Name, "Changing schema '$($sch.Name)' owner to 'dbo'.")) {
                                                        $AlterSchemaOwner += "ALTER AUTHORIZATION ON SCHEMA::[$($sch.Name)] TO [dbo]$eol"

                                                        [pscustomobject]@{
                                                            ComputerName      = $server.ComputerName
                                                            InstanceName      = $server.ServiceName
                                                            SqlInstance       = $server.DomainInstanceName
                                                            DatabaseName      = $db.Name
                                                            SchemaName        = $sch.Name
                                                            Action            = "ALTER OWNER"
                                                            SchemaOwnerBefore = $sch.Owner
                                                            SchemaOwnerAfter  = "dbo"
                                                        }
                                                    }
                                                }
                                            }
                                        }

                                    } else {
                                        Write-Message -Level Verbose -Message "User $dbuser does not own any schema. Will be dropped."
                                    }

                                    # https://github.com/dataplat/dbatools/issues/7130
                                    $dbUserName = $dbuser.ToString()
                                    if (-not ($dbUserName.StartsWith("[") -and $dbUserName.EndsWith("]"))) {
                                        $dbUserName = "[" + $dbUserName + "]"
                                    }

                                    $query = "$AlterSchemaOwner $eol$DropSchema $($eol)DROP USER " + $dbUserName

                                    Write-Message -Level Debug -Message $query
                                } else {
                                    $query = "EXEC master.dbo.sp_droplogin @loginame = N'$($dbuser.name)'"
                                }

                                if ($ExistLogin) {
                                    if (-not $SkipUser) {
                                        if ($Force) {
                                            if ($Pscmdlet.ShouldProcess($db.Name, "Dropping user $dbuser using -Force")) {
                                                $server.Databases[$db.Name].ExecuteNonQuery($query) | Out-Null
                                                Write-Message -Level Verbose -Message "User $dbuser was dropped from $($db.Name). -Force parameter was used."
                                            }
                                        } else {
                                            Write-Message -Level Warning -Message "Orphan user $($dbuser.Name) has a matching login. The user will not be dropped. If you want to drop anyway, use -Force parameter."
                                            Continue
                                        }
                                    }
                                } else {
                                    if (-not $SkipUser) {
                                        if ($Pscmdlet.ShouldProcess($db.Name, "Dropping user $dbuser")) {
                                            $server.Databases[$db.Name].ExecuteNonQuery($query) | Out-Null
                                            Write-Message -Level Verbose -Message "User $dbuser was dropped from $($db.Name)."
                                        }
                                    }
                                }
                            }
                        } else {
                            Write-Message -Level Verbose -Message "No orphan users found on database $db."
                        }
                        #reset collection
                        $users = $null
                    } catch {
                        Stop-Function -Message "Failure" -ErrorRecord $_ -Target $db -Continue
                    }
                }
            } else {
                Write-Message -Level Verbose -Message "There are no databases to analyse."
            }
        }
    }
}
# SIG # Begin signature block
# MIIjYAYJKoZIhvcNAQcCoIIjUTCCI00CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCAx2N5A0gosoOr/
# xcFHhMFBW2N412MkVpR5s3lj5hCRIKCCHVkwggUaMIIEAqADAgECAhADBbuGIbCh
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
# BgorBgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCCwtVKlRCVTR5WZkixmGg/8OC0J
# /DkNeOUGC3lWMkizpzANBgkqhkiG9w0BAQEFAASCAQAMD2YXtwaBE9rw07KKBJR9
# 3eoM12WbzGb/RTT6fkOWSCuauTPcNEtdBuVQxgthoP/49r8DHoxjuEBCb+Zua56p
# YhCzG+lhO5PupFoKpRtGkb8CpqIUY7ommrc/2TWVPvBIVDlQJJqf1ZxHp56cbH8g
# Eb1npnFEsQv8Q92IUmhf2mCVaPHIowxA52O6WgJ+muF6u3hRPBrKf/SzHKzqp4Gi
# oIlxbqleLuXDXkPdAhPs7pEMaY2qHhuFYIi8a1QIfHEx4Xbk1bBSKYv/r4DGrIYZ
# u0Hss1m90gFyXJSKGoNRjCfScb9Zw2FIKo+UeqRNDnVR1GH2nr5aKq/nYXTxYZJU
# oYIDIDCCAxwGCSqGSIb3DQEJBjGCAw0wggMJAgEBMHcwYzELMAkGA1UEBhMCVVMx
# FzAVBgNVBAoTDkRpZ2lDZXJ0LCBJbmMuMTswOQYDVQQDEzJEaWdpQ2VydCBUcnVz
# dGVkIEc0IFJTQTQwOTYgU0hBMjU2IFRpbWVTdGFtcGluZyBDQQIQDE1pckuU+jwq
# Sj0pB4A9WjANBglghkgBZQMEAgEFAKBpMBgGCSqGSIb3DQEJAzELBgkqhkiG9w0B
# BwEwHAYJKoZIhvcNAQkFMQ8XDTIyMTExNzA4NTcxM1owLwYJKoZIhvcNAQkEMSIE
# IISB+tLxwV4Ysl4MLuReIgiffkIFID+K5UKZa6/9luvZMA0GCSqGSIb3DQEBAQUA
# BIICAH4KOkQm5V2BqWJq+1WIULk6vHXPfELlGcgiGctXnDvy3sx2Cc8zKpcgTO/P
# mWIo77HiCK2KtyZcKBHr3TMRQdCwYwvgrtKh7NtrWA1H+FDKKtl94AA/KfbT8gl8
# CZgSj1hNS+AjbnWb/AT6DnHazspke1tggPz4FAjWzJchM6SfuG+8ZIaFRGkWnxYi
# bU0wpIJ9VzdhZ3+b5+mkL8g5WgpEEUqtq5WBQRBc6lsCNEr1V6jBbQiTMdq1R6Zp
# cr6WoGy05ygqAkNfL8sWRd6FJraJW+ZFlYb4weAXXGVKhFz6ja+zGD8C7HzsDtju
# AcGw9mOIKJtwXbCwcl2vpfTx+VbHSdKI8FyZsfk1wqpahZ5fpgPu14XijhMCcBaI
# tOwMpX9kdfoarqkYMZT2l/cKG6H0hzi6ZMQLfMS4xN88rk+TxubUetUQ2jiKhcx0
# Hsh2/y3wxEU8gDWW3OWia8u2XWq78b4KTV4P/FFVR987h1QZQgJBH2GqWgCbKrtb
# QNEm2YCa1v2Ie/P4scVZFmsctHxB4F9QGZsm0tnuwhdL1+0Or+Bj7fzVWuVhUhcM
# n4ljKgMT7DzKV6ai9gLBOcqv3vGCem+kMDnprLNOILMxLrarRTQPemVptltSQMT5
# 3WRrpvEkogznF9U0uz3WxmoF4PlZ/hlJAhuUtovSpiJPSk37
# SIG # End signature block
