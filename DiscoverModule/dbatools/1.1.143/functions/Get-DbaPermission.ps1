function Get-DbaPermission {
    <#
    .SYNOPSIS
        Get a list of Server and Database level permissions

    .DESCRIPTION
        Retrieves a list of permissions

        Permissions link principals to securables.
        Principals exist on Windows, Instance and Database level.
        Securables exist on Instance and Database level.
        A permission state can be GRANT, DENY or REVOKE.
        The permission type can be SELECT, CONNECT, EXECUTE and more.
        The CONTROL permission is also returned for dbo users, db_owners, and schema owners.
        To see server-level implicit permissions via fixed roles run the following command: Get-DbaServerRole -SqlInstance serverName | Select-Object *

        See https://msdn.microsoft.com/en-us/library/ms191291.aspx for more information

    .PARAMETER SqlInstance
        The target SQL Server instance or instances. Defaults to localhost.

    .PARAMETER SqlCredential
        Login to the target instance using alternative credentials. Accepts PowerShell credentials (Get-Credential).

        Windows Authentication, SQL Server Authentication, Active Directory - Password, and Active Directory - Integrated are all supported.

        For MFA support, please use Connect-DbaInstance.

    .PARAMETER Database
        Specifies one or more database(s) to process. If unspecified, all databases will be processed.

    .PARAMETER ExcludeDatabase
        Specifies one or more database(s) to exclude from processing.

    .PARAMETER IncludeServerLevel
        If this switch is enabled, information about Server Level Permissions will be output.

    .PARAMETER ExcludeSystemObjects
        If this switch is enabled, permissions on system securables will be excluded.

    .PARAMETER EnableException
        If this switch is enabled exceptions will be thrown to the caller, which will need to perform its own exception processing. Otherwise, the function will try to catch the exception, interpret it and provide a friendly error message.

    .NOTES
        Tags: Permissions, Instance, Database, Security
        Author: Klaas Vandenberghe (@PowerDBAKlaas)

        Website: https://dbatools.io
        Copyright: (c) 2018 by dbatools, licensed under MIT
        License: MIT https://opensource.org/licenses/MIT

    .LINK
        https://dbatools.io/Get-DbaPermission

    .EXAMPLE
        PS C:\> Get-DbaPermission -SqlInstance ServerA\sql987

        Returns a custom object with Server name, Database name, permission state, permission type, grantee and securable.

    .EXAMPLE
        PS C:\> Get-DbaPermission -SqlInstance ServerA\sql987 | Format-Table -AutoSize

        Returns a formatted table displaying Server, Database, permission state, permission type, grantee, granteetype, securable and securabletype.

    .EXAMPLE
        PS C:\> Get-DbaPermission -SqlInstance ServerA\sql987 -ExcludeSystemObjects -IncludeServerLevel

        Returns a custom object with Server name, Database name, permission state, permission type, grantee and securable
        in all databases and on the server level, but not on system securables.

    .EXAMPLE
        PS C:\> Get-DbaPermission -SqlInstance sql2016 -Database master

        Returns a custom object with permissions for the master database.

    #>
    [CmdletBinding()]
    param (
        [parameter(Mandatory, ValueFromPipeline)]
        [DbaInstance[]]$SqlInstance,
        [PSCredential]$SqlCredential,
        [object[]]$Database,
        [object[]]$ExcludeDatabase,
        [switch]$IncludeServerLevel,
        [switch]$ExcludeSystemObjects,
        [switch]$EnableException
    )
    begin {
        if ($ExcludeSystemObjects) {
            $ExcludeSystemObjectssql = "WHERE major_id > 0 "
        }

        $ServPermsql = "SELECT SERVERPROPERTY('MachineName') AS ComputerName,
                       ISNULL(SERVERPROPERTY('InstanceName'), 'MSSQLSERVER') AS InstanceName,
                       SERVERPROPERTY('ServerName') AS SqlInstance
                        , [Database] = ''
                        , [PermState] = state_desc
                        , [PermissionName] = permission_name
                        , [SecurableType] = COALESCE(o.type_desc,sp.class_desc)
                        , [Securable] = CASE    WHEN class = 100 THEN @@SERVERNAME
                                                WHEN class = 105 THEN OBJECT_NAME(major_id)
                                                ELSE OBJECT_NAME(major_id)
                                                END
                        , [Grantee] = SUSER_NAME(grantee_principal_id)
                        , [GranteeType] = pr.type_desc
                        , [revokeStatement] = 'REVOKE ' + permission_name + ' ' + COALESCE(OBJECT_NAME(major_id),'') + ' FROM [' + SUSER_NAME(grantee_principal_id) + ']'
                        , [grantStatement] = 'GRANT ' + permission_name + ' ' + COALESCE(OBJECT_NAME(major_id),'') + ' TO [' + SUSER_NAME(grantee_principal_id) + ']'
                            + CASE WHEN sp.state_desc = 'GRANT_WITH_GRANT_OPTION' THEN ' WITH GRANT OPTION' ELSE '' END
                    FROM sys.server_permissions sp
                        JOIN sys.server_principals pr ON pr.principal_id = sp.grantee_principal_id
                        LEFT OUTER JOIN sys.all_objects o ON o.object_id = sp.major_id

                    $ExcludeSystemObjectssql

                    UNION ALL
                    SELECT    SERVERPROPERTY('MachineName') AS ComputerName
                            , ISNULL(SERVERPROPERTY('InstanceName'), 'MSSQLSERVER') AS InstanceName
                            , SERVERPROPERTY('ServerName') AS SqlInstance
                            , [database] = ''
                            , [PermState] = 'GRANT'
                            , [PermissionName] = pb.[permission_name]
                            , [SecurableType] = pb.class_desc
                            , [Securable] = @@SERVERNAME
                            , [Grantee] = spr.name
                            , [GranteeType] = spr.type_desc
                            , [revokestatement] = ''
                            , [grantstatement] = ''
                    FROM sys.server_principals AS spr
                    INNER JOIN sys.fn_builtin_permissions('SERVER') AS pb ON
                        spr.[name]='bulkadmin' AND pb.[permission_name]='ADMINISTER BULK OPERATIONS'
                        OR
                        spr.[name]='dbcreator' AND pb.[permission_name]='CREATE ANY DATABASE'
                        OR
                        spr.[name]='diskadmin' AND pb.[permission_name]='ALTER RESOURCES'
                        OR
                        spr.[name]='processadmin' AND pb.[permission_name] IN ('ALTER ANY CONNECTION', 'ALTER SERVER STATE')
                        OR
                        spr.[name]='sysadmin' AND pb.[permission_name]='CONTROL SERVER'
                        OR
                        spr.[name]='securityadmin' AND pb.[permission_name]='ALTER ANY LOGIN'
                        OR
                        spr.[name]='serveradmin'  AND pb.[permission_name] IN ('ALTER ANY ENDPOINT', 'ALTER RESOURCES','ALTER SERVER STATE', 'ALTER SETTINGS','SHUTDOWN', 'VIEW SERVER STATE')
                        OR
                        spr.[name]='setupadmin' AND pb.[permission_name]='ALTER ANY LINKED SERVER'
                    WHERE spr.[type]='R'
                    ;"

        $DBPermsql = "SELECT SERVERPROPERTY('MachineName') AS ComputerName,
                    ISNULL(SERVERPROPERTY('InstanceName'), 'MSSQLSERVER') AS InstanceName,
                    SERVERPROPERTY('ServerName') AS SqlInstance
                    , [Database] = DB_NAME()
                    , [PermState] = state_desc
                    , [PermissionName] = permission_name
                    , [SecurableType] = COALESCE(o.type_desc,dp.class_desc)
                    , [Securable] = CASE    WHEN class = 0 THEN DB_NAME()
                                            WHEN class = 1 THEN ISNULL(s.name + '.','')+OBJECT_NAME(major_id)
                                            WHEN class = 3 THEN SCHEMA_NAME(major_id)
                                            WHEN class = 6 THEN SCHEMA_NAME(t.schema_id)+'.' + t.name
                                            END
                    , [Grantee] = USER_NAME(grantee_principal_id)
                    , [GranteeType] = pr.type_desc
                    , [RevokeStatement] = CASE WHEN class = 3 THEN 'REVOKE ' + permission_name + ' ON Schema::[' + isnull(SCHEMA_NAME(dp.major_id) COLLATE DATABASE_DEFAULT,'') + '] FROM [' + USER_NAME(grantee_principal_id) +']'
                                            ELSE 'REVOKE ' + permission_name + ' ON [' + isnull(schema_name(o.schema_id) COLLATE DATABASE_DEFAULT+'].[','')+OBJECT_NAME(major_id)+ '] FROM [' + USER_NAME(grantee_principal_id) +']'
                                            END
                    , [GrantStatement] = CASE WHEN class = 3 THEN 'GRANT ' + permission_name + ' ON Schema::' + isnull(SCHEMA_NAME(dp.major_id) COLLATE DATABASE_DEFAULT,'') + '] TO [' + USER_NAME(grantee_principal_id) + ']'
                                            ELSE 'GRANT ' + permission_name + ' ON [' + isnull(schema_name(o.schema_id) COLLATE DATABASE_DEFAULT+'].[','')+OBJECT_NAME(major_id)+ '] TO [' + USER_NAME(grantee_principal_id) + ']'
                                            END
                        + CASE WHEN dp.state_desc = 'GRANT_WITH_GRANT_OPTION' THEN ' WITH GRANT OPTION' ELSE '' END
                    FROM sys.database_permissions dp
                    JOIN sys.database_principals pr ON pr.principal_id = dp.grantee_principal_id
                    LEFT OUTER JOIN sys.all_objects o ON (o.object_id = dp.major_id AND dp.class NOT IN (0, 3))
                    LEFT OUTER JOIN sys.schemas s ON s.schema_id = o.schema_id
                    LEFT OUTER JOIN sys.types t on t.user_type_id = dp.major_id

                $ExcludeSystemObjectssql

                UNION ALL
                SELECT    SERVERPROPERTY('MachineName') AS ComputerName
                        , ISNULL(SERVERPROPERTY('InstanceName'), 'MSSQLSERVER') AS InstanceName
                        , SERVERPROPERTY('ServerName') AS SqlInstance
                        , [database] = DB_NAME()
                        , [PermState] = ''
                        , [PermissionName] = p.[permission_name]
                        , [SecurableType] = p.class_desc
                        , [Securable] = DB_NAME()
                        , [Grantee] = dp.name
                        , [GranteeType] = dp.type_desc
                        , [revokestatement] = ''
                        , [grantstatement] = ''
                FROM sys.database_principals AS dp
                INNER JOIN sys.fn_builtin_permissions('DATABASE') AS p ON
                    dp.[name]='db_accessadmin' AND p.[permission_name] IN ('ALTER ANY USER', 'CREATE SCHEMA')
                    OR
                    dp.[name]='db_backupoperator' AND p.[permission_name] IN ('BACKUP DATABASE', 'BACKUP LOG', 'CHECKPOINT')
                    OR
                    dp.[name] IN ('db_datareader', 'db_denydatareader') AND p.[permission_name]='SELECT'
                    OR
                    dp.[name] IN ('db_datawriter', 'db_denydatawriter') AND p.[permission_name] IN ('INSERT', 'DELETE', 'UPDATE')
                    OR
                    dp.[name]='db_ddladmin' AND
                    p.[permission_name] IN ('ALTER ANY ASSEMBLY', 'ALTER ANY ASYMMETRIC KEY',
                                            'ALTER ANY CERTIFICATE', 'ALTER ANY CONTRACT',
                                            'ALTER ANY DATABASE DDL TRIGGER', 'ALTER ANY DATABASE EVENT',
                                            'NOTIFICATION', 'ALTER ANY DATASPACE', 'ALTER ANY FULLTEXT CATALOG',
                                            'ALTER ANY MESSAGE TYPE', 'ALTER ANY REMOTE SERVICE BINDING',
                                            'ALTER ANY ROUTE', 'ALTER ANY SCHEMA', 'ALTER ANY SERVICE',
                                            'ALTER ANY SYMMETRIC KEY', 'CHECKPOINT', 'CREATE AGGREGATE',
                                            'CREATE DEFAULT', 'CREATE FUNCTION', 'CREATE PROCEDURE',
                                            'CREATE QUEUE', 'CREATE RULE', 'CREATE SYNONYM', 'CREATE TABLE',
                                            'CREATE TYPE', 'CREATE VIEW', 'CREATE XML SCHEMA COLLECTION',
                                            'REFERENCES')
                    OR
                    dp.[name]='db_owner' AND p.[permission_name]='CONTROL'
                    OR
                    dp.[name]='db_securityadmin' AND p.[permission_name] IN ('ALTER ANY APPLICATION ROLE', 'ALTER ANY ROLE', 'CREATE SCHEMA', 'VIEW DEFINITION')

                WHERE dp.[type]='R'
                    AND dp.is_fixed_role=1
                UNION ALL -- include the dbo user
                SELECT
                    [ComputerName]		= SERVERPROPERTY('MachineName')
                ,	[InstanceName]		= ISNULL(SERVERPROPERTY('InstanceName'), 'MSSQLSERVER')
                ,	[SqlInstance]		= SERVERPROPERTY('ServerName')
                ,	[database]			= DB_NAME()
                ,	[PermState]			= ''
                ,	[PermissionName]	= 'CONTROL'
                ,	[SecurableType]		= 'DATABASE'
                ,	[Securable]			= DB_NAME()
                ,	[Grantee]			= SUSER_SNAME(owner_sid)
                ,	[GranteeType]		= 'DATABASE OWNER (dbo user)'
                ,	[revokestatement]	= ''
                ,	[grantstatement]	= ''
                FROM
                    sys.databases
                WHERE
                    name = DB_NAME()
                UNION ALL -- include the users with the db_owner role
                SELECT
                    [ComputerName]		= SERVERPROPERTY('MachineName')
                ,	[InstanceName]		= ISNULL(SERVERPROPERTY('InstanceName'), 'MSSQLSERVER')
                ,	[SqlInstance]		= SERVERPROPERTY('ServerName')
                ,	[database]			= DB_NAME()
                ,	[PermState]			= ''
                ,	[PermissionName]	= 'CONTROL'
                ,	[SecurableType]		= 'DATABASE'
                ,	[Securable]			= DB_NAME()
                ,	[Grantee]			= databaseUser.name
                ,	[GranteeType]		= 'DATABASE OWNER (db_owner role)'
                ,	[revokestatement]	= ''
                ,	[grantstatement]	= ''
                FROM
                (
                    SELECT
                        member_principal_id
                    FROM
                        sys.database_role_members AS roleMembers
                    INNER JOIN
                        sys.database_principals AS roleFilter
                            ON roleMembers.role_principal_id = roleFilter.principal_id
                            AND roleFilter.name = 'db_owner'
                ) dbOwner
                INNER JOIN
                    sys.database_principals AS databaseUser
                        ON dbOwner.member_principal_id = databaseUser.principal_id
                WHERE
                    databaseUser.name <> 'dbo'
                UNION ALL -- include the schema owners
                SELECT
                    [ComputerName]		= SERVERPROPERTY('MachineName')
                ,	[InstanceName]		= ISNULL(SERVERPROPERTY('InstanceName'), 'MSSQLSERVER')
                ,	[SqlInstance]		= SERVERPROPERTY('ServerName')
                ,	[database]			= DB_NAME()
                ,	[PermState]			= ''
                ,	[PermissionName]	= 'CONTROL'
                ,	[SecurableType]		= 'SCHEMA'
                ,	[Securable]			= name
                ,	[Grantee]			= USER_NAME(principal_id)
                ,	[GranteeType]		= 'SCHEMA OWNER'
                ,	[revokestatement]	= ''
                ,	[grantstatement]	= ''
                FROM
                    sys.schemas
                WHERE
                    name NOT IN (SELECT name FROM sys.database_principals WHERE type = 'R')
                AND name NOT IN ('dbo', 'guest', 'INFORMATION_SCHEMA', 'sys')
                ;"
    }

    process {
        foreach ($instance in $SqlInstance) {
            try {
                $server = Connect-DbaInstance -SqlInstance $instance -SqlCredential $SqlCredential -MinimumVersion 9
            } catch {
                Stop-Function -Message "Failure" -Category ConnectionError -ErrorRecord $_ -Target $instance -Continue
            }

            if ($IncludeServerLevel) {
                Write-Message -Level Debug -Message "T-SQL: $ServPermsql"
                $server.Query($ServPermsql)
            }

            $dbs = $server.Databases

            if ($Database) {
                $dbs = $dbs | Where-Object Name -In $Database
            }

            if ($ExcludeDatabase) {
                $dbs = $dbs | Where-Object Name -NotIn $ExcludeDatabase
            }

            foreach ($db in $dbs) {
                Write-Message -Level Verbose -Message "Processing $db on $instance."

                if ($db.IsAccessible -eq $false) {
                    Write-Message -Level Warning -Message "The database $db is not accessible. Skipping database."
                    Continue
                }

                Write-Message -Level Debug -Message "T-SQL: $DBPermsql"
                try {
                    $db.ExecuteWithResults($DBPermsql).Tables.Rows
                } catch {
                    Stop-Function -Message "Failure executing against $($db.Name) on $instance" -ErrorRecord $_ -Continue
                }
            }
        }
    }
}
# SIG # Begin signature block
# MIIjYAYJKoZIhvcNAQcCoIIjUTCCI00CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCCkrAxoL0M+UchK
# 811zhxfAPG1c2jjA1pQzs4txDAGDr6CCHVkwggUaMIIEAqADAgECAhADBbuGIbCh
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
# BgorBgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCC112d2+qLFTluJ5k6mdUAHiftE
# kr57YjxxKifXhgPxRTANBgkqhkiG9w0BAQEFAASCAQBolzSd6zC3bm/s+5LDmxuA
# vq2xHRtQ2Gg2G/PAIZ6gtc3TPX2MN9N+JWcYeP3QPOCUA8hwVq2FheRAO3OsNMJL
# cONcV2pafYrkKeoqwX9+C2v/98Uu9TjReDNPM9Rg78Jsco98w5Z5rtyG1NsX1r/9
# b9LC+BICnym2t5/ifTPZkbvqLYzZJxZDDXBSJ5VZPXv/UXTdMTpB0KDLLWrfWT5s
# zrVoktZlzC60XPrpfzwBOnfIgBk6kIJ1HJPGY8vX6gIBqw8iZIfTgYIbIS10N2uL
# 8/0bebo+Iff7UwcRR2A2bJNyzDYVV2vF036MYz+/V2K/NFFvPRYImhPR3fRv3UU9
# oYIDIDCCAxwGCSqGSIb3DQEJBjGCAw0wggMJAgEBMHcwYzELMAkGA1UEBhMCVVMx
# FzAVBgNVBAoTDkRpZ2lDZXJ0LCBJbmMuMTswOQYDVQQDEzJEaWdpQ2VydCBUcnVz
# dGVkIEc0IFJTQTQwOTYgU0hBMjU2IFRpbWVTdGFtcGluZyBDQQIQDE1pckuU+jwq
# Sj0pB4A9WjANBglghkgBZQMEAgEFAKBpMBgGCSqGSIb3DQEJAzELBgkqhkiG9w0B
# BwEwHAYJKoZIhvcNAQkFMQ8XDTIyMTExNzA4NTYxN1owLwYJKoZIhvcNAQkEMSIE
# IA4y0SvcDJzJzNp3/saAVrisxQc8a0POUYQmsRXC/Fg6MA0GCSqGSIb3DQEBAQUA
# BIICAJHv0zw5VptAfxScK/Ab69ul7CLeoU7Wht6OHUUWiHwxrg3Y5WKlOSOAIb5/
# horE/aUoOrHGXF37Cdk68Va6D/9AKx0IS9ztUE38kZhdxDWa6IJwW7nwxsy8HG85
# brj73I7QgkLj6EAVhVx+uqybWBWTMWxw4PJcLkr4/gjUqR2q1XskbjE46AMZkabH
# 87VlWxc7tWCYEWDWi90thns9Qlu95Fo945S4JO2u4WhXdd89iN9onL4GedB6vqgz
# sGTRK1CqPt3MBxu3V3qkkE53NDdfdfOHbHmZ4LP2Yuqp1Gp1EcV3XiVCcO9gJbza
# t9/xjB9rsZpen7D3IHGFAqDOI+z8tyN8A8efD4EA+GyxBHJaZM2bArTi/GR/uKhP
# uovWbJVvpjLs6Ka2vWQCzR6fMxDmh5VWNoz6W/vvi+xeNyvMCDZFjNyBetVdzIHJ
# NfRhB9UaR6D/q5qeDn4bw/mWwmCO2muPTV0G17ZRZ1hF1TyoTWPkXjhk2wFLtmQl
# EEp9W+1gSU52YtjAPE3O9okqFeyziFY08K9ZQfDTbivmmT3Qvv5b00DuUj4xbvNS
# zYFhyEAj5C9+lrh9Vv3ckw0GCP4T5y6V2N1cp9jreNYLdnoOBM2VMNO2g1h4vBvQ
# LRh2ftUOJrTCqMaB3RfPC/+ZpZhalSNrR08t8d4a0lOULb/4
# SIG # End signature block
