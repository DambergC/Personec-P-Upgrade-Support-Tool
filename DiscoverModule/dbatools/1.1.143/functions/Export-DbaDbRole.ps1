function Export-DbaDbRole {
    <#
    .SYNOPSIS
        Exports database roles to a T-SQL file. Export includes Role creation, object permissions and Schema ownership.

    .DESCRIPTION
        Exports database roles to a T-SQL file. Export includes Role creation, object permissions and Schema ownership.

        This command is based off of John Eisbrener's post "Fully Script out a MSSQL Database Role"
        Reference:  https://dbaeyes.wordpress.com/2013/04/19/fully-script-out-a-mssql-database-role/

    .PARAMETER SqlInstance
        The target SQL Server instance or instances. SQL Server 2005 and above supported.
        Any databases in CompatibilityLevel 80 or lower will be skipped

    .PARAMETER SqlCredential
        Login to the target instance using alternative credentials. Accepts PowerShell credentials (Get-Credential).

        Windows Authentication, SQL Server Authentication, Active Directory - Password, and Active Directory - Integrated are all supported.

        For MFA support, please use Connect-DbaInstance.

    .PARAMETER InputObject
        Enables piping from Get-DbaDatabase and Get-DbaLogin.

     .PARAMETER ScriptingOptionsObject
        An SMO Scripting Object that can be used to customize the output - see New-DbaScriptingOption

    .PARAMETER Database
        The database(s) to process. Options for this list are auto-populated from the server. If unspecified, all databases will be processed.

    .PARAMETER Role
        The Role(s) to process. If unspecified, all Roles will be processed.

    .PARAMETER ExcludeRole
        The Role(s) to exclude.

    .PARAMETER ExcludeFixedRole
        Excludes all members of fixed roles.

    .PARAMETER IncludeRoleMember
        Include scripting of role members in script

    .PARAMETER Path
        Specifies the directory where the file or files will be exported.
        Will default to Path.DbatoolsExport Configuration entry

    .PARAMETER FilePath
        Specifies the full file path of the output file. If left blank then filename based on Instance name, Database name and date is created.
        If more than one database or instance is input then this parameter should normally be blank.

    .PARAMETER Passthru
        Output script to console only

    .PARAMETER BatchSeparator
        Batch separator for scripting output. Uses the value from configuration Formatting.BatchSeparator by default. This is normally "GO"

    .PARAMETER NoClobber
        If this switch is enabled, a file already existing at the path specified by Path will not be overwritten. This takes precedence over Append switch

    .PARAMETER Append
        If this switch is enabled, content will be appended to a file already existing at the path specified by FilePath. If the file does not exist, it will be created.

    .PARAMETER NoPrefix
        Do not include a Prefix

    .PARAMETER Encoding
        Specifies the file encoding. The default is UTF8.

        Valid values are:
        -- ASCII: Uses the encoding for the ASCII (7-bit) character set.
        -- BigEndianUnicode: Encodes in UTF-16 format using the big-endian byte order.
        -- Byte: Encodes a set of characters into a sequence of bytes.
        -- String: Uses the encoding type for a string.
        -- Unicode: Encodes in UTF-16 format using the little-endian byte order.
        -- UTF7: Encodes in UTF-7 format.
        -- UTF8: Encodes in UTF-8 format.
        -- Unknown: The encoding type is unknown or invalid. The data can be treated as binary.


    .PARAMETER EnableException
        By default, when something goes wrong we try to catch it, interpret it and give you a friendly warning message.
        This avoids overwhelming you with "sea of red" exceptions, but is inconvenient because it basically disables advanced scripting.
        Using this switch turns this "nice by default" feature off and enables you to catch exceptions with your own try/catch.

    .NOTES
        Tags: Export, Role
        Author: Patrick Flynn (@sqllensman)

        Website: https://dbatools.io
        Copyright: (c) 2018 by dbatools, licensed under MIT
        License: MIT https://opensource.org/licenses/MIT

    .LINK
        https://dbatools.io/Export-DbaDbRole

    .EXAMPLE
        PS C:\> Export-DbaDbRole -SqlInstance sql2005 -Path C:\temp

        Exports all the Database Roles for SQL Server "sql2005" and writes them to the file "C:\temp\sql2005-logins.sql"

    .EXAMPLE
        PS C:\> Export-DbaDbRole -SqlInstance sqlserver2014a -ExcludeRole realcajun -SqlCredential $scred -Path C:\temp\roles.sql -Append

        Authenticates to sqlserver2014a using SQL Authentication. Exports all roles except for realcajun to C:\temp\roles.sql, and appends to the file if it exists. If not, the file will be created.

    .EXAMPLE
        PS C:\> Export-DbaDbRole -SqlInstance sqlserver2014a -Role realcajun,netnerds -Path C:\temp\roles.sql

        Exports ONLY roles netnerds and realcajun FROM sqlserver2014a to the file C:\temp\roles.sql

    .EXAMPLE
        PS C:\> Export-DbaDbRole -SqlInstance sqlserver2014a -Role realcajun,netnerds -Database HR, Accounting

        Exports ONLY roles netnerds and realcajun FROM sqlserver2014a with the permissions on databases HR and Accounting

    .EXAMPLE
        PS C:\> Get-DbaDatabase -SqlInstance sqlserver2014a -Database HR, Accounting | Export-DbaDbRole

        Exports ONLY roles FROM sqlserver2014a with permissions on databases HR and Accounting

    .EXAMPLE
        PS C:\> Set-DbatoolsConfig -FullName formatting.batchseparator -Value $null
        PS C:\> Export-DbaDbRole -SqlInstance sqlserver2008 -Role realcajun,netnerds -Path C:\temp\roles.sql

        Sets the BatchSeparator configuration to null, removing the default "GO" value.
        Exports ONLY roles netnerds and realcajun FROM sqlserver2008 server, to the C:\temp\roles.sql file, without the "GO" batch separator.

    .EXAMPLE
        PS C:\> Export-DbaDbRole -SqlInstance sqlserver2008 -Role realcajun,netnerds -Path C:\temp\roles.sql -BatchSeparator $null

        Exports ONLY roles netnerds and realcajun FROM sqlserver2008 server, to the C:\temp\roles.sql file, without the "GO" batch separator.

    .EXAMPLE
        PS C:\> Get-DbaDatabase -SqlInstance sqlserver2008 | Export-DbaDbRole -Role realcajun

        Exports role realcajun for all databases on sqlserver2008

    .EXAMPLE
        PS C:\> Get-DbaDbRole -SqlInstance sqlserver2008 -ExcludeFixedRole | Export-DbaDbRole

        Exports all roles from all databases on sqlserver2008, excludes all roles marked as as FixedRole

    #>
    [CmdletBinding()]
    param (
        [parameter()]
        [DbaInstanceParameter[]]$SqlInstance,
        [PSCredential]$SqlCredential,
        [Parameter(ValueFromPipeline)]
        [object[]]$InputObject,
        [Microsoft.SqlServer.Management.Smo.ScriptingOptions]$ScriptingOptionsObject,
        [object[]]$Database,
        [object[]]$Role,
        [object[]]$ExcludeRole,
        [switch]$ExcludeFixedRole,
        [switch]$IncludeRoleMember,
        [string]$Path = (Get-DbatoolsConfigValue -FullName 'Path.DbatoolsExport'),
        [Alias("OutFile", "FileName")]
        [string]$FilePath,
        [switch]$Passthru,
        [string]$BatchSeparator = (Get-DbatoolsConfigValue -FullName 'Formatting.BatchSeparator'),
        [switch]$NoClobber,
        [switch]$Append,
        [switch]$NoPrefix,
        [ValidateSet('ASCII', 'BigEndianUnicode', 'Byte', 'String', 'Unicode', 'UTF7', 'UTF8', 'Unknown')]
        [string]$Encoding = 'UTF8',
        [switch]$EnableException
    )
    begin {
        $null = Test-ExportDirectory -Path $Path
        $outsql = @()
        $outputFileArray = @()
        $roleCollection = New-Object System.Collections.ArrayList
        if ($IsLinux -or $IsMacOs) {
            $executingUser = $env:USER
        } else {
            $executingUser = [Security.Principal.WindowsIdentity]::GetCurrent().Name
        }
        $commandName = $MyInvocation.MyCommand.Name

        $roleSQL = "SELECT
                        N'/*RoleName*/' as RoleName,
                        CASE dp.state
                            WHEN 'D' THEN 'DENY'
                            WHEN 'G' THEN 'GRANT'
                            WHEN 'R' THEN 'REVOKE'
                            WHEN 'W' THEN 'GRANT'
                        END as GrantState,
                        dp.permission_name as Permission,
                        CASE dp.class
                            WHEN 0 THEN ''
                            WHEN 1 THEN --table or column subset on the table
                                CASE WHEN dp.major_id < 0 THEN COALESCE('[sys].[' + OBJECT_NAME(dp.major_id) + ']', '')
                                    ELSE '[' + (SELECT SCHEMA_NAME(schema_id) + '].[' + name FROM sys.objects WHERE object_id = dp.major_id) + ']'
                                END + -- optionally concatenate column names
                                    CASE WHEN MAX(dp.minor_id) > 0 THEN ' (['
                                        + REPLACE((SELECT name + '], [' FROM sys.columns
                                                WHERE object_id = dp.major_id
                                                AND column_id IN (SELECT minor_id FROM sys.database_permissions WHERE major_id = dp.major_id AND USER_NAME(grantee_principal_id) = N'/*RoleName*/')
                                        FOR XML PATH('')) + '])', ', []', '')
                                        ELSE ''
                                    END
                            WHEN 3 THEN 'SCHEMA::[' + SCHEMA_NAME(dp.major_id) + ']'
                            WHEN 4 THEN '' + (SELECT RIGHT(type_desc, 4) + '::[' + name FROM sys.database_principals WHERE principal_id = dp.major_id) + ']'
                            WHEN 5 THEN 'ASSEMBLY::[' + (SELECT name FROM sys.assemblies WHERE assembly_id = dp.major_id) + ']'
                            WHEN 6 THEN 'TYPE::[' + (SELECT name FROM sys.types WHERE user_type_id = dp.major_id) + ']'
                            WHEN 10 THEN 'XML SCHEMA COLLECTION::[' + (SELECT SCHEMA_NAME(schema_id) + '.' + name FROM sys.xml_schema_collections WHERE xml_collection_id = dp.major_id) + ']'
                            WHEN 15 THEN 'MESSAGE TYPE::[' + (SELECT name FROM sys.service_message_types WHERE message_type_id = dp.major_id) + ']'
                            WHEN 16 THEN 'CONTRACT::[' + (SELECT name FROM sys.service_contracts WHERE service_contract_id = dp.major_id) + ']'
                            WHEN 17 THEN 'SERVICE::[' + (SELECT name FROM sys.services WHERE service_id = dp.major_id) + ']'
                            WHEN 18 THEN 'REMOTE SERVICE BINDING::[' + (SELECT name FROM sys.remote_service_bindings WHERE remote_service_binding_id = dp.major_id) + ']'
                            WHEN 19 THEN 'ROUTE::[' + (SELECT name FROM sys.routes WHERE route_id = dp.major_id) + ']'
                            WHEN 23 THEN 'FULLTEXT CATALOG::[' + (SELECT name FROM sys.fulltext_catalogs WHERE fulltext_catalog_id = dp.major_id) + ']'
                            WHEN 24 THEN 'SYMMETRIC KEY::[' + (SELECT name FROM sys.symmetric_keys WHERE symmetric_key_id = dp.major_id) + ']'
                            WHEN 25 THEN 'CERTIFICATE::[' + (SELECT name FROM sys.certificates WHERE certificate_id = dp.major_id) + ']'
                            WHEN 26 THEN 'ASYMMETRIC KEY::[' + (SELECT name FROM sys.asymmetric_keys WHERE asymmetric_key_id = dp.major_id) + ']'
                        END COLLATE DATABASE_DEFAULT  as Type,
                        CASE dp.state WHEN 'W' THEN ' WITH GRANT OPTION' ELSE '' END as GrantType
                    FROM sys.database_permissions dp
                    WHERE USER_NAME(dp.grantee_principal_id) = N'/*RoleName*/'
                    GROUP BY dp.state, dp.major_id, dp.permission_name, dp.class
                    UNION ALL
                    SELECT
                        N'/*RoleName*/' as RoleName,
                        'ALTER' as GrantState,
                        'AUTHORIZATION' as permission_name,
                        'SCHEMA::['+s.[name]+']' as Type,
                        '' as GrantType
                    from sys.schemas s
                    join sys.sysusers u on s.principal_id = u.[uid]
                    where u.[name] = N'/*RoleName*/'"

        $userSQL = "SELECT roles.name as RoleName, users.name as Member
                    FROM sys.database_principals users
                    INNER JOIN sys.database_role_members link
                        ON link.member_principal_id = users.principal_id
                    INNER JOIN sys.database_principals roles
                        ON roles.principal_id = link.role_principal_id
                    WHERE roles.name = N'/*RoleName*/'"

        if (Test-Bound -Not -ParameterName ScriptingOptionsObject) {
            $ScriptingOptionsObject = New-DbaScriptingOption
            $ScriptingOptionsObject.AllowSystemObjects = $false
            $ScriptingOptionsObject.IncludeDatabaseRoleMemberships = $true
            $ScriptingOptionsObject.ContinueScriptingOnError = $false
            $ScriptingOptionsObject.IncludeDatabaseContext = $true
            $ScriptingOptionsObject.IncludeIfNotExists = $false
        }

        if ($ScriptingOptionsObject.NoCommandTerminator) {
            $commandTerminator = ''
        } else {
            $commandTerminator = ';'
        }
        $outsql = @()
    }
    process {
        if (Test-FunctionInterrupt) {
            return
        }

        if (-not $InputObject -and -not $SqlInstance) {
            Stop-Function -Message "You must pipe in a role, database, or server or specify a SqlInstance"
            return
        }

        if ($SqlInstance) {
            $InputObject = $SqlInstance
        }

        foreach ($input in $InputObject) {
            $inputType = $input.GetType().FullName
            switch ($inputType) {
                'Sqlcollaborative.Dbatools.Parameter.DbaInstanceParameter' {
                    Write-Message -Level Verbose -Message "Processing DbaInstanceParameter through InputObject"
                    $databaseRoles = Get-DbaDbRole -SqlInstance $input -SqlCredential $SqlCredential -Database $Database -ExcludeDatabase $ExcludeDatabase -Role $Role -ExcludeRole $ExcludeRole -ExcludeFixedRole:$ExcludeFixedRole
                }
                'Microsoft.SqlServer.Management.Smo.Server' {
                    Write-Message -Level Verbose -Message "Processing Server through InputObject"
                    $databaseRoles = Get-DbaDbRole -SqlInstance $input -SqlCredential $SqlCredential -Database $Database -ExcludeDatabase $ExcludeDatabase -Role $Role -ExcludeRole $ExcludeRole -ExcludeFixedRole:$ExcludeFixedRole
                }
                'Microsoft.SqlServer.Management.Smo.Database' {
                    Write-Message -Level Verbose -Message "Processing Database through InputObject"
                    $databaseRoles = $input | Get-DbaDbRole -ExcludeDatabase $ExcludeDatabase -Role $Role -ExcludeRole $ExcludeRole -ExcludeFixedRole:$ExcludeFixedRole
                }
                'Microsoft.SqlServer.Management.Smo.DatabaseRole' {
                    Write-Message -Level Verbose -Message "Processing DatabaseRole through InputObject"
                    $databaseRoles = $input
                }
                default {
                    Stop-Function -Message "InputObject is not a server, database, or login."
                    return
                }
            }
            foreach ($dbRole in $databaseRoles) {
                try {
                    $server = $dbRole.Parent.Parent
                    $db = $dbRole.Parent
                    if ($server.VersionMajor -lt 9) {
                        Stop-Function -Message "SQL Server version 9 or higher required - $server not supported." -Continue
                    }
                    $dbCompatibilityLevel = [int]($db.CompatibilityLevel.ToString().Replace('Version', ''))
                    if ($dbCompatibilityLevel -lt 90) {
                        Stop-Function -Message "$db has a compatibility level lower than Version90 and will be skipped." -Target $db -Continue
                    }

                    $outsql += $dbRole.Script($ScriptingOptionsObject)

                    $query = $roleSQL.Replace('/*RoleName*/', "$($dbRole.Name)")
                    $rolePermissions = $($dbRole.Parent).Query($query)

                    foreach ($rolePermission in $rolePermissions) {
                        $script = $rolePermission.GrantState + " " + $rolePermission.Permission
                        if ($rolePermission.Type) {
                            $script += " ON " + $rolePermission.Type
                        }
                        if ($rolePermission.RoleName) {
                            $script += " TO [" + $rolePermission.RoleName + "]"
                        }
                        if ($rolePermission.GrantType) {
                            $script += " WITH GRANT OPTION" + $commandTerminator
                        } else {
                            $script += $commandTerminator
                        }
                        $outsql += "$script"
                    }

                    if ($IncludeRoleMember) {
                        $query = $userSQL.Replace('/*RoleName*/', "$($dbRole.Name)")
                        $roleUsers = $($dbRole.Parent).Query($query)

                        foreach ($roleUser in $roleUsers) {
                            if ($server.VersionMajor -lt 11) {
                                $script = "EXEC sys.sp_addrolemember @rolename=N'$($roleUser.RoleName)', @membername=N'$($roleUser.Member)'"
                            } else {
                                $script = 'ALTER ROLE [' + $roleUser.RoleName + "] ADD MEMBER [" + $roleUser.Member + "]" + $commandTerminator
                            }
                            $outsql += "$script"
                        }
                    }
                    $roleObject = [PSCustomObject]@{
                        Name     = $dbRole.Name
                        Instance = $dbRole.SqlInstance
                        Database = $dbRole.Database
                        Sql      = $outsql
                    }
                    $roleCollection.Add($roleObject) | Out-Null
                    $outsql = @()
                } catch {
                    $outsql = @()
                    Stop-Function -Message "Error occurred processing role $dbRole" -Category ConnectionError -ErrorRecord $_ -Target $server -Continue
                }
            }
        }
    }
    end {
        if (Test-FunctionInterrupt) { return }

        $eol = [System.Environment]::NewLine

        $timeNow = $(Get-Date -Format (Get-DbatoolsConfigValue -FullName 'Formatting.DateTime'))
        foreach ($dbRole in $roleCollection) {
            $instanceName = $dbRole.Instance
            $databaseName = $dbRole.Database

            $outputFileName = $instanceName.Replace('\', '$') + '-' + $databaseName.Replace('\', '$')

            if ($NoPrefix) {
                $prefix = $null
            } else {
                $prefix = "/*$eol`tCreated by $executingUser using dbatools $commandName for objects on $instanceName.$databaseName at $timeNow$eol`tSee https://dbatools.io/$commandName for more information$eol*/"
            }

            if ($BatchSeparator) {
                $sql = $dbRole.SQL -join "$eol$BatchSeparator$eol"
                #add the final GO
                $sql += "$eol$BatchSeparator"
            } else {
                $sql = $dbRole.SQL
            }

            if ($Passthru) {
                if ($null -ne $prefix) {
                    $sql = "$prefix$eol$sql"
                }
                $sql
            } elseif ($Path -Or $FilePath) {
                if ($outputFileArray -notcontains $outputFileName) {
                    $scriptPath = Get-ExportFilePath -Path $PSBoundParameters.Path -FilePath $PSBoundParameters.FilePath -Type sql -ServerName $outputFileName
                    Write-Message -Level Verbose -Message "New File $scriptPath"
                    if ($null -ne $prefix) {
                        $sql = "$prefix$eol$sql"
                    }
                    $sql | Out-File -Encoding $Encoding -LiteralPath $scriptPath -Append:$Append -NoClobber:$NoClobber
                    $outputFileArray += $outputFileName
                    Get-ChildItem $scriptPath
                } else {
                    Write-Message -Level Verbose -Message "Adding to $scriptPath"
                    $sql | Out-File -Encoding $Encoding -LiteralPath $scriptPath -Append
                }
            } else {
                $sql
            }
        }
    }
}
# SIG # Begin signature block
# MIIjYAYJKoZIhvcNAQcCoIIjUTCCI00CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCB8O305vqTx+R7z
# jCfYqxMBMM1v92XzT6HAvAf6oSYMyKCCHVkwggUaMIIEAqADAgECAhADBbuGIbCh
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
# BgorBgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCDVqLYj1JnEPpB6aV0HTlmifhR+
# kWl7ER8nc/lkqKwkSDANBgkqhkiG9w0BAQEFAASCAQCV54IxHlDyQ9Dt+qWFus95
# hvlKUFuMbuuiTNBpUWJSt7iz8OlQv3XgyT/o2CXhvwaTgsL2Czr+MCnmzMbHPLlE
# q3XMlN7A0vSmq9b7HWK/VRXseAS3qH6xCqcxKda15/gqdYqdJFFxwYCMHR19iZ7J
# IBI3HMtHpkG0V+k8GrY800l7ykf0WE0DfINS4hPv1zZwPsATY/7OMC7QIdzPtWWz
# 4he83Nb/h+5MDDCBaZp5lz6ZpvhwsPgwkjWCrrojYn0jDUBKGBEcBleJf6q+WBvX
# TQj4iP3wCI7lFdCHrm7RbQfLdulGGtgZsDY7rRy7ZjehmzTeFQRvw6uiSQUEhYw5
# oYIDIDCCAxwGCSqGSIb3DQEJBjGCAw0wggMJAgEBMHcwYzELMAkGA1UEBhMCVVMx
# FzAVBgNVBAoTDkRpZ2lDZXJ0LCBJbmMuMTswOQYDVQQDEzJEaWdpQ2VydCBUcnVz
# dGVkIEc0IFJTQTQwOTYgU0hBMjU2IFRpbWVTdGFtcGluZyBDQQIQDE1pckuU+jwq
# Sj0pB4A9WjANBglghkgBZQMEAgEFAKBpMBgGCSqGSIb3DQEJAzELBgkqhkiG9w0B
# BwEwHAYJKoZIhvcNAQkFMQ8XDTIyMTExNzA4NTUyOFowLwYJKoZIhvcNAQkEMSIE
# IGq3TXiWZ9QI/y0TT9SKqV8n2SoSCtCFFgdEbUGZsShyMA0GCSqGSIb3DQEBAQUA
# BIICAEikhMZL7T2O+6jkkEjNxVuHOF0Mr+EHk9AWZCFGfUFyxnxLxm3SuuZ47myD
# 90m1M+L5wm+PIFVQcR6JHOH9TfksieVhj7DizKdBi3MA75L4DIfFftfkATI6SxfG
# 1CrS1W9dQ7GdINafnSnjjJ7YgkLpWQazsB9g8XV1nSmpYmPWUnwixw6MSav3rIy4
# ZRaS6h/errlE/1RrEWjNmMmdDmaSpC+RHRg5QwsanExaDXXLV+Gsi/dCtP7D0qKV
# BMZ4lKLScKnpBCx1xJzIXE3v2hfP2/ENYCdeIO5p36acfPVyF2dwdbI7YEWA5Wlk
# HVjWWBn4PEIiK9CWkNRvkTNjEqN0T80EdPT6LKFIHCCEFBVWRtuOgbX7qXCsQlCe
# hmBzOw91bOdRba9D1lNqrMr2r1OE8R/ALIaMUUIlxgVt/ObMfCO06rsS0xtybAc2
# hD3rFIwmGo8Jf7XuVszfplzaqqy3wt7gNfFZe257M342/MW0XPdvPpoVPFEdJvx6
# O12v1IlLUsQSB6Nn0GmA3eHVJZs8fhbho8ZPh86uBkxm2C7Wzi5r40Sn89dNL/CF
# SidMQ4AOrwiB3fmVFPK/r1DZXUGb7PuHOxaWpTtPL2cWVzBxjdpjTwMrvX0/U1DF
# jE4okoVdQQEcQ13LC/d84leJK4w8gNLfj9iKrUqF+Fv/a68T
# SIG # End signature block
