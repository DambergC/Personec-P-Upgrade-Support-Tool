function Export-DbaLogin {
    <#
    .SYNOPSIS
        Exports Windows and SQL Logins to a T-SQL file. Export includes login, SID, password, default database, default language, server permissions, server roles, db permissions, db roles.

    .DESCRIPTION
        Exports Windows and SQL Logins to a T-SQL file. Export includes login, SID, password, default database, default language, server permissions, server roles, db permissions, db roles.

    .PARAMETER SqlInstance
        The target SQL Server instance or instances. SQL Server 2000 and above supported.

    .PARAMETER SqlCredential
        Login to the target instance using alternative credentials. Accepts PowerShell credentials (Get-Credential).

        Windows Authentication, SQL Server Authentication, Active Directory - Password, and Active Directory - Integrated are all supported.

        For MFA support, please use Connect-DbaInstance.

    .PARAMETER InputObject
        Enables piping from Get-DbaDatabase, Get-DbaLogin and more.

    .PARAMETER Login
        The login(s) to process. Options for this list are auto-populated from the server. If unspecified, all logins will be processed.

    .PARAMETER ExcludeLogin
        The login(s) to exclude. Options for this list are auto-populated from the server.

    .PARAMETER Database
        The database(s) to process. Options for this list are auto-populated from the server. If unspecified, all databases will be processed.

    .PARAMETER ExcludeJobs
        If this switch is enabled, Agent job ownership will not be exported.

    .PARAMETER ExcludeDatabase
        If this switch is enabled, mappings for databases will not be exported.

    .PARAMETER ExcludePassword
        If this switch is enabled, hashed passwords will not be exported.

   .PARAMETER DefaultDatabase
        If this switch is enabled, all logins will be scripted with specified default database,
        that could help to successfully import logins on server that is missing default database for login.

    .PARAMETER Path
        Specifies the directory where the file or files will be exported.
        Will default to Path.DbatoolsExport Configuration entry

    .PARAMETER FilePath
        Specifies the full file path of the output file. If left blank then filename based on Instance name and date is created.
        If more than one instance is input then this parameter should be blank.

    .PARAMETER Passthru
        Output script to console

    .PARAMETER BatchSeparator
        Batch separator for scripting output. Uses the value from configuration Formatting.BatchSeparator by default. This is normally "GO"

    .PARAMETER NoClobber
        If this switch is enabled, a file already existing at the path specified by Path will not be overwritten.

    .PARAMETER Append
        If this switch is enabled, content will be appended to a file already existing at the path specified by Path. If the file does not exist, it will be created.

    .PARAMETER DestinationVersion
        To say to which version the script should be generated. If not specified will use instance major version.

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

    .PARAMETER ObjectLevel
        Include object-level permissions for each user associated with copied login.

    .PARAMETER EnableException
        By default, when something goes wrong we try to catch it, interpret it and give you a friendly warning message.
        This avoids overwhelming you with "sea of red" exceptions, but is inconvenient because it basically disables advanced scripting.
        Using this switch turns this "nice by default" feature off and enables you to catch exceptions with your own try/catch.

    .PARAMETER WhatIf
        If this switch is enabled, no actions are performed but informational messages will be displayed that explain what would happen if the command were to run.

    .PARAMETER Confirm
        If this switch is enabled, you will be prompted for confirmation before executing any operations that change state.

    .NOTES
        Tags: Export, Login
        Author: Chrissy LeMaire (@cl), netnerds.net

        Website: https://dbatools.io
        Copyright: (c) 2018 by dbatools, licensed under MIT
        License: MIT https://opensource.org/licenses/MIT

    .LINK
        https://dbatools.io/Export-DbaLogin

    .EXAMPLE
        PS C:\> Export-DbaLogin -SqlInstance sql2005 -Path C:\temp\sql2005-logins.sql

        Exports the logins for SQL Server "sql2005" and writes them to the file "C:\temp\sql2005-logins.sql"

    .EXAMPLE
        PS C:\> Export-DbaLogin -SqlInstance sqlserver2014a -ExcludeLogin realcajun -SqlCredential $scred -Path C:\temp\logins.sql -Append

        Authenticates to sqlserver2014a using SQL Authentication. Exports all logins except for realcajun to C:\temp\logins.sql, and appends to the file if it exists. If not, the file will be created.

    .EXAMPLE
        PS C:\> Export-DbaLogin -SqlInstance sqlserver2014a -Login realcajun, netnerds -Path C:\temp\logins.sql

        Exports ONLY logins netnerds and realcajun FROM sqlserver2014a to the file  C:\temp\logins.sql

    .EXAMPLE
        PS C:\> Export-DbaLogin -SqlInstance sqlserver2014a -Login realcajun, netnerds -Database HR, Accounting

        Exports ONLY logins netnerds and realcajun FROM sqlserver2014a with the permissions on databases HR and Accounting

    .EXAMPLE
        PS C:\> Get-DbaDatabase -SqlInstance sqlserver2014a -Database HR, Accounting | Export-DbaLogin

        Exports ONLY logins FROM sqlserver2014a with permissions on databases HR and Accounting

    .EXAMPLE
        PS C:\> Set-DbatoolsConfig -FullName formatting.batchseparator -Value $null
        PS C:\> Export-DbaLogin -SqlInstance sqlserver2008 -Login realcajun, netnerds -Path C:\temp\login.sql

        Exports ONLY logins netnerds and realcajun FROM sqlserver2008 server, to the C:\temp\login.sql file without the 'GO' batch separator.

    .EXAMPLE
        PS C:\> Export-DbaLogin -SqlInstance sqlserver2008 -Login realcajun -Path C:\temp\users.sql -DestinationVersion SQLServer2016

        Exports login realcajun from sqlserver2008 to the file C:\temp\users.sql with syntax to run on SQL Server 2016

    .EXAMPLE
        PS C:\> Get-DbaDatabase -SqlInstance sqlserver2008 -Login realcajun | Export-DbaLogin

        Exports login realcajun from sqlserver2008

    .EXAMPLE
        PS C:\> Get-DbaLogin -SqlInstance sqlserver2008, sqlserver2012  | Where-Object { $_.IsDisabled -eq $false } | Export-DbaLogin

        Exports all enabled logins from sqlserver2008 and sqlserver2008

    #>
    [CmdletBinding(SupportsShouldProcess)]
    param (
        [parameter()]
        [DbaInstanceParameter[]]$SqlInstance,
        [PSCredential]$SqlCredential,
        [Parameter(ValueFromPipeline)]
        [object[]]$InputObject,
        [object[]]$Login,
        [object[]]$ExcludeLogin,
        [object[]]$Database,
        [switch]$ExcludeJobs,
        [Alias("ExcludeDatabases")]
        [switch]$ExcludeDatabase,
        [switch]$ExcludePassword,
        [string]$DefaultDatabase,
        [string]$Path = (Get-DbatoolsConfigValue -FullName 'Path.DbatoolsExport'),
        [Alias("OutFile", "FileName")]
        [string]$FilePath,
        [ValidateSet('ASCII', 'BigEndianUnicode', 'Byte', 'String', 'Unicode', 'UTF7', 'UTF8', 'Unknown')]
        [string]$Encoding = 'UTF8',
        [Alias("NoOverwrite")]
        [switch]$NoClobber,
        [switch]$Append,
        [string]$BatchSeparator = (Get-DbatoolsConfigValue -FullName 'Formatting.BatchSeparator'),
        [ValidateSet('SQLServer2000', 'SQLServer2005', 'SQLServer2008/2008R2', 'SQLServer2012', 'SQLServer2014', 'SQLServer2016', 'SQLServer2017', 'SQLServer2019')]
        [string]$DestinationVersion,
        [switch]$NoPrefix,
        [switch]$Passthru,
        [switch]$ObjectLevel,
        [switch]$EnableException
    )

    begin {
        $null = Test-ExportDirectory -Path $Path
        $outsql = @()
        $instanceArray = @()
        $logonCollection = New-Object System.Collections.ArrayList
        if ($IsLinux -or $IsMacOs) {
            $executingUser = $env:USER
        } else {
            $executingUser = [Security.Principal.WindowsIdentity]::GetCurrent().Name
        }
        $commandName = $MyInvocation.MyCommand.Name

        $eol = [System.Environment]::NewLine
    }
    process {
        if (Test-FunctionInterrupt) { return }

        if (-not $InputObject -and -not $SqlInstance) {
            Stop-Function -Message "You must pipe in a login, database, or server or specify a SqlInstance"
            return
        }

        if ($SqlInstance) {
            $InputObject = $SqlInstance
        }

        foreach ($input in $InputObject) {
            $inputType = $input.GetType().FullName
            switch ($inputType) {
                'Sqlcollaborative.Dbatools.Parameter.DbaInstanceParameter' {
                    Write-Message -Level Verbose -Message "Processing Server through InputObject"
                    try {
                        $server = Connect-DbaInstance -SqlInstance $input -SqlCredential $SqlCredential
                    } catch {
                        Stop-Function -Message "Failure" -Category ConnectionError -ErrorRecord $_ -Target $input -Continue
                    }
                }
                'Microsoft.SqlServer.Management.Smo.Server' {
                    Write-Message -Level Verbose -Message "Processing Server through InputObject"
                    $server = Connect-DbaInstance -SqlInstance $input -SqlCredential $SqlCredential
                }
                'Microsoft.SqlServer.Management.Smo.Database' {
                    Write-Message -Level Verbose -Message "Processing Database through InputObject"
                    $server = $input.Parent
                    $Database = $input
                }
                'Microsoft.SqlServer.Management.Smo.Login' {
                    Write-Message -Level Verbose -Message "Processing Login through InputObject"
                    $server = $input.Parent
                    $Login = $input
                }
                default {
                    Stop-Function -Message "InputObject is not a server, database, or login."
                    return
                }
            }

            if ($ExcludeDatabase -eq $false -or $Database) {
                # if we got a database or a list of databases passed
                # and we need to enumerate mappings, login.enumdatabasemappings() takes forever
                # the cool thing though is that database.enumloginmappings() is fast. A lot.
                # if we get a list of databases passed (or even the default list of all the databases)
                # we save ourself a call to enumloginmappings if there is no map at all
                $DbMapping = @()
                $DbsToMap = $server.Databases
                if ($Database) {
                    if ($Database[0].GetType().FullName -eq 'Microsoft.SqlServer.Management.Smo.Database') {
                        $DbsToMap = $DbsToMap | Where-Object Name -in $Database.Name
                    } else {
                        $DbsToMap = $DbsToMap | Where-Object Name -in $Database
                    }
                }
                foreach ($db in $DbsToMap) {
                    if ($db.IsAccessible -eq $false) {
                        continue
                    }
                    $dbmap = $db.EnumLoginMappings()
                    foreach ($el in $dbmap) {
                        $DbMapping += [pscustomobject]@{
                            Database  = $db.Name
                            UserName  = $el.Username
                            LoginName = $el.LoginName
                        }
                    }
                }
            }

            $serverLogins = $server.Logins

            if ($Login) {
                if ($Login[0].GetType().FullName -eq 'Microsoft.SqlServer.Management.Smo.Login') {
                    $serverLogins = $serverLogins | Where-Object { $_.Name -in $Login.Name }
                } else {
                    $serverLogins = $serverLogins | Where-Object { $_.Name -in $Login }
                }
            }

            if ($Database) {
                $serverLogins = $serverLogins | Where-Object { $_.Name -in $DbMapping.LoginName }
            }

            foreach ($sourceLogin in $serverLogins) {
                Write-Message -Level Verbose -Message "Processing login $sourceLogin"
                $userName = $sourceLogin.name

                if ($ExcludeLogin -contains $userName) {
                    Write-Message -Level Warning -Message "Skipping $userName"
                    continue
                }

                if ($userName.StartsWith("##") -or $userName -eq 'sa') {
                    Write-Message -Level Warning -Message "Skipping $userName"
                    continue
                }

                $serverName = $server

                $userBase = ($userName.Split("\")[0]).ToLowerInvariant()
                if ($serverName -eq $userBase -or $userName.StartsWith("NT ")) {
                    if ($Pscmdlet.ShouldProcess("console", "Stating $userName is skipped because it is a local machine name")) {
                        Write-Message -Level Warning -Message "$userName is skipped because it is a local machine name"
                        continue
                    }
                }

                if ($Pscmdlet.ShouldProcess("Outfile", "Adding T-SQL for login $userName")) {
                    if ($Path -or $FilePath) {
                        Write-Message -Level Verbose -Message "Exporting $userName"
                    }

                    $outsql += "$($eol)USE master$eol"
                    # Getting some attributes
                    if ($DefaultDatabase) {
                        $defaultDb = $DefaultDatabase
                    } else {
                        $defaultDb = $sourceLogin.DefaultDatabase
                    }
                    $language = $sourceLogin.Language

                    if ($sourceLogin.PasswordPolicyEnforced -eq $false) {
                        $checkPolicy = "OFF"
                    } else {
                        $checkPolicy = "ON"
                    }

                    if (!$sourceLogin.PasswordExpirationEnabled) {
                        $checkExpiration = "OFF"
                    } else {
                        $checkExpiration = "ON"
                    }

                    # Attempt to script out SQL Login
                    if ($sourceLogin.LoginType -eq "SqlLogin") {
                        if (!$ExcludePassword) {
                            $sourceLoginName = $sourceLogin.name

                            switch ($server.versionMajor) {
                                0 {
                                    $sql = "SELECT CONVERT(VARBINARY(256),password) AS hashedpass FROM master.dbo.syslogins WHERE loginname='$sourceLoginName'"
                                }
                                8 {
                                    $sql = "SELECT CONVERT(VARBINARY(256),password) AS hashedpass FROM dbo.syslogins WHERE name='$sourceLoginName'"
                                }
                                9 {
                                    $sql = "SELECT CONVERT(VARBINARY(256),password_hash) as hashedpass FROM sys.sql_logins WHERE name='$sourceLoginName'"
                                }
                                default {
                                    $sql = "SELECT CAST(CONVERT(varchar(256), CAST(LOGINPROPERTY(name,'PasswordHash') AS VARBINARY(256)), 1) AS NVARCHAR(max)) AS hashedpass FROM sys.server_principals WHERE principal_id = $($sourceLogin.id)"
                                }
                            }

                            try {
                                $hashedPass = $server.ConnectionContext.ExecuteScalar($sql)
                            } catch {
                                $hashedPassDt = $server.Databases['master'].ExecuteWithResults($sql)
                                $hashedPass = $hashedPassDt.Tables[0].Rows[0].Item(0)
                            }

                            if ($hashedPass.GetType().Name -ne "String") {
                                $passString = "0x"; $hashedPass | ForEach-Object {
                                    $passString += ("{0:X}" -f $_).PadLeft(2, "0")
                                }
                                $hashedPass = $passString
                            }
                        } else {
                            $hashedPass = '#######'
                        }

                        $sid = "0x"; $sourceLogin.sid | ForEach-Object {
                            $sid += ("{0:X}" -f $_).PadLeft(2, "0")
                        }
                        $outsql += "IF NOT EXISTS (SELECT loginname FROM master.dbo.syslogins WHERE name = '$userName') CREATE LOGIN [$userName] WITH PASSWORD = $hashedPass HASHED, SID = $sid, DEFAULT_DATABASE = [$defaultDb], CHECK_POLICY = $checkPolicy, CHECK_EXPIRATION = $checkExpiration, DEFAULT_LANGUAGE = [$language]"
                    }
                    # Attempt to script out Windows User
                    elseif ($sourceLogin.LoginType -eq "WindowsUser" -or $sourceLogin.LoginType -eq "WindowsGroup") {
                        $outsql += "IF NOT EXISTS (SELECT loginname FROM master.dbo.syslogins WHERE name = '$userName') CREATE LOGIN [$userName] FROM WINDOWS WITH DEFAULT_DATABASE = [$defaultDb], DEFAULT_LANGUAGE = [$language]"
                    }
                    # This script does not currently support certificate mapped or asymmetric key users.
                    else {
                        Write-Message -Level Warning -Message "$($sourceLogin.LoginType) logins not supported. $($sourceLogin.Name) skipped"
                        continue
                    }

                    if ($sourceLogin.IsDisabled) {
                        $outsql += "ALTER LOGIN [$userName] DISABLE"
                    }

                    if ($sourceLogin.DenyWindowsLogin) {
                        $outsql += "DENY CONNECT SQL TO [$userName]"
                    }
                }

                # Server Roles: sysadmin, bulklogin, etc
                foreach ($role in $server.Roles) {
                    $roleName = $role.Name

                    # SMO changed over time
                    try {
                        $roleMembers = $role.EnumMemberNames()
                    } catch {
                        $roleMembers = $role.EnumServerRoleMembers()
                    }

                    if ($roleMembers -contains $userName) {
                        if (($server.VersionMajor -lt 11 -and [string]::IsNullOrEmpty($destinationVersion)) -or ($DestinationVersion -in "SQLServer2000", "SQLServer2005", "SQLServer2008/2008R2")) {
                            $outsql += "EXEC sys.sp_addsrvrolemember @rolename=N'$roleName', @loginame=N'$userName'"
                        } else {
                            $outsql += "ALTER SERVER ROLE [$roleName] ADD MEMBER [$userName]"
                        }
                    }
                }

                if ($ExcludeJobs -eq $false) {
                    $ownedJobs = $server.JobServer.Jobs | Where-Object { $_.OwnerLoginName -eq $userName }

                    foreach ($ownedJob in $ownedJobs) {
                        $ownedJob = $ownedJob -replace ("'", "''")
                        $outsql += "$($eol)USE msdb$eol"
                        $outsql += "EXEC msdb.dbo.sp_update_job @job_name=N'$ownedJob', @owner_login_name=N'$userName'"
                    }
                }

                if ($server.VersionMajor -ge 9) {
                    # These operations are only supported by SQL Server 2005 and above.
                    # Securables: Connect SQL, View any database, Administer Bulk Operations, etc.

                    $perms = $server.EnumServerPermissions($userName)
                    $outsql += "$($eol)USE master$eol"
                    foreach ($perm in $perms) {
                        $permState = $perm.permissionstate
                        $permType = $perm.PermissionType
                        $grantor = $perm.grantor

                        if ($permState -eq "GrantWithGrant") {
                            $grantWithGrant = "WITH GRANT OPTION"
                            $permState = "GRANT"
                        } else {
                            $grantWithGrant = $null
                        }

                        $outsql += "$permState $permType TO [$userName] $grantWithGrant AS [$grantor]"
                    }

                    # Credential mapping. Credential removal not currently supported for Syncs.
                    $loginCredentials = $server.Credentials | Where-Object { $_.Identity -eq $sourceLogin.Name }
                    foreach ($credential in $loginCredentials) {
                        $credentialName = $credential.Name
                        $outsql += "PRINT '$userName is associated with the $credentialName credential'"
                    }
                }

                if ($ExcludeDatabase -eq $false) {
                    $dbs = $sourceLogin.EnumDatabaseMappings() | Sort-Object DBName

                    if ($Database) {
                        if ($Database[0].GetType().FullName -eq 'Microsoft.SqlServer.Management.Smo.Database') {
                            $dbs = $dbs | Where-Object { $_.DBName -in $Database.Name }
                        } else {
                            $dbs = $dbs | Where-Object { $_.DBName -in $Database }
                        }
                    }

                    # Adding database mappings and securables
                    foreach ($db in $dbs) {
                        $dbName = $db.dbname
                        $sourceDb = $server.Databases[$dbName]
                        $dbUserName = $db.username

                        $outsql += "$($eol)USE [$dbName]$eol"

                        $scriptOptions = New-DbaScriptingOption
                        $scriptVersion = $sourceDb.CompatibilityLevel
                        $scriptOptions.TargetServerVersion = [Microsoft.SqlServer.Management.Smo.SqlServerVersion]::$scriptVersion
                        $scriptOptions.ContinueScriptingOnError = $false
                        $scriptOptions.IncludeDatabaseContext = $false
                        $scriptOptions.IncludeIfNotExists = $true

                        if ($ObjectLevel) {
                            # Exporting all permissions
                            $scriptOptions.AllowSystemObjects = $true
                            $scriptOptions.IncludeDatabaseRoleMemberships = $true

                            $exportSplat = @{
                                SqlInstance            = $server
                                Database               = $dbName
                                User                   = $dbUsername
                                ScriptingOptionsObject = $scriptOptions
                            }
                            # remove batch separator if the $BatchSeparator string is empty
                            if (-Not $BatchSeparator) {
                                $scriptOptions.NoCommandTerminator = $true
                                $exportSplat.ExcludeGoBatchSeparator = $true
                            }
                            try {
                                $userScript = Export-DbaUser @exportSplat -Passthru -EnableException
                                $outsql += $userScript
                            } catch {
                                Stop-Function -Message "Failed to extract permissions for user $dbUserName in database $dbName" -Continue -ErrorRecord $_
                            }
                        } else {
                            try {
                                $sql = $server.Databases[$dbName].Users[$dbUserName].Script($scriptOptions)
                                $outsql += $sql
                            } catch {
                                Write-Message -Level Warning -Message "User cannot be found in selected database"
                            }

                            # Skipping updating dbowner

                            # Database Roles: db_owner, db_datareader, etc
                            foreach ($role in $sourceDb.Roles) {
                                if ($role.EnumMembers() -contains $dbUserName) {
                                    $roleName = $role.Name
                                    if (($server.VersionMajor -lt 11 -and [string]::IsNullOrEmpty($destinationVersion)) -or ($DestinationVersion -in "SQLServer2000", "SQLServer2005", "SQLServer2008/2008R2")) {
                                        $outsql += "EXEC sys.sp_addrolemember @rolename=N'$roleName', @membername=N'$dbUserName'"
                                    } else {
                                        $outsql += "ALTER ROLE [$roleName] ADD MEMBER [$dbUserName]"
                                    }
                                }
                            }

                            # Connect, Alter Any Assembly, etc
                            $perms = $sourceDb.EnumDatabasePermissions($dbUserName)
                            foreach ($perm in $perms) {
                                $permState = $perm.PermissionState
                                $permType = $perm.PermissionType
                                $grantor = $perm.Grantor

                                if ($permState -eq "GrantWithGrant") {
                                    $grantWithGrant = "WITH GRANT OPTION"
                                    $permState = "GRANT"
                                } else {
                                    $grantWithGrant = $null
                                }

                                $outsql += "$permState $permType TO [$userName] $grantWithGrant AS [$grantor]"
                            }
                        }
                    }
                }
                $loginObject = [PSCustomObject]@{
                    Name     = $userName
                    Instance = $server.Name
                    Sql      = $outsql
                }
                $logonCollection.Add($loginObject) | Out-Null
                $outsql = @()
            }
        }
    }
    end {
        foreach ($login in $logonCollection) {
            if ($NoPrefix) {
                $prefix = $null
            } else {
                $prefix = "/*$eol`tCreated by $executingUser using dbatools $commandName for objects on $($login.Instance) at $(Get-Date -Format (Get-DbatoolsConfigValue -FullName 'Formatting.DateTime'))$eol`tSee https://dbatools.io/$commandName for more information$eol*/"
            }

            if ($BatchSeparator) {
                $sql = $login.SQL -join "$eol$BatchSeparator$eol"
                #add the final GO
                $sql += "$eol$BatchSeparator"
            } else {
                $sql = $login.SQL
            }



            if ($Passthru) {
                if ($null -ne $prefix) {
                    $sql = $prefix + $sql
                }
                $sql
            } elseif ($Path -Or $FilePath) {
                if ($instanceArray -notcontains $($login.Instance)) {
                    if ($null -ne $prefix) {
                        $sql = $prefix + $sql
                    }
                    $scriptPath = Get-ExportFilePath -Path $PSBoundParameters.Path -FilePath $PSBoundParameters.FilePath -Type sql -ServerName $login.Instance
                    $sql | Out-File -Encoding $Encoding -FilePath $scriptPath -Append:$Append -NoClobber:$NoClobber
                    $instanceArray += $login.Instance
                    Get-ChildItem $scriptPath
                } else {
                    $sql | Out-File -Encoding $Encoding -FilePath $scriptPath -Append
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
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCAKJQvMY9GhJEKP
# KHpRrGQH/jSkB7wSizhiBWuN3ako36CCHVkwggUaMIIEAqADAgECAhADBbuGIbCh
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
# BgorBgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCBaZJ1DijU21hqAt8UftVAQ3pJX
# nohQVDNAqF87fxRfSjANBgkqhkiG9w0BAQEFAASCAQAY1AUGZN536H3QS/5aSjRi
# pWud4Mczzurww5rl5sFr6VVhO4ZN595+vX/Fi4cQBE1kBNudnuG5V9LlLh2e6BH5
# 666fUT09pGkBkOuTlP24YTZ/ucydiP1L+4BCkNLtN1PfeKh5A2TiH/4DxXDu5xXv
# G0wcwaJOQvBqeWFN47kvqMmuDCASovd9RtC5LB+J903WZVP8ar5Yg3XycxtGK6Qu
# Az7DkCYyB73gMN4ibIX3XJSKHrA4EDXvi9kiXLEZo86rjbatXaJtvs988TpGIiDQ
# AA0pvTtz6Rzij/zrE3ah4lp0IfWNHCKF5tlqrmBfXqwzRIBc/Pvq1z04hly+sr/0
# oYIDIDCCAxwGCSqGSIb3DQEJBjGCAw0wggMJAgEBMHcwYzELMAkGA1UEBhMCVVMx
# FzAVBgNVBAoTDkRpZ2lDZXJ0LCBJbmMuMTswOQYDVQQDEzJEaWdpQ2VydCBUcnVz
# dGVkIEc0IFJTQTQwOTYgU0hBMjU2IFRpbWVTdGFtcGluZyBDQQIQDE1pckuU+jwq
# Sj0pB4A9WjANBglghkgBZQMEAgEFAKBpMBgGCSqGSIb3DQEJAzELBgkqhkiG9w0B
# BwEwHAYJKoZIhvcNAQkFMQ8XDTIyMTExNzA4NTUyOVowLwYJKoZIhvcNAQkEMSIE
# IGbiR4Kg+AEM+LXcfTyWX3ZbysfJyohjsMo699H8RSFWMA0GCSqGSIb3DQEBAQUA
# BIICAKbcRq6VBqAjZCSBg5+jyen08pglLGT8qeKPJUgMhAivAL/2Tnp65A4Ai28k
# +nUh75HtddIL0sMSHdAzt++kJzntCbkd8J8KfeXdZ3DLW0w1ttTlD+4dgVvX9X41
# 85PJgwniWOKA/vIoHXnIs7J2cH9AkRJVaV718qDOjQq/llVGq6xYxLc87yZ6FUxK
# F4Uo5E/3nF0nLkZcXKNpHPgLDgU2fLbQJDXza9dvd7Nsuu0xb9kvwRrlxkRmTk9m
# BDcP6w9JhvY0NJINvBXn77tEo3PIFwKAgisrJaGWizjCsIXxFcv85mZdU8QU171L
# jH03gITrzJsquc6fC+pIJeB4nebOvpT0qGFLS50+XDzekls0CNXvPZ4RHyB1Pn9J
# SPYx/0M2cz5mgZr+9lDUYEEbp+3CEg7sQYpnjdJHpmEwBbB+USnPe9I7MNxYHfUZ
# v9HMOOW4n/BO9UY76qcI8YygQMqQNUjaNEYKORSRF239WnV2Iiq0XQqKtEjYuLI7
# y6VM7TxqRf8lwIF5ZoAk5w7jD9vG+VHeZg/J2/GgLCyI8d8EwUlnQueuR/VRtqRx
# hXEwEuSB4X3W1v8N9kIqE2HDi66QArHdixLTumCEfYurjcf+AXAJnozK1pzD9iHq
# sRq8I8YKjL5pziWTDDW59L1SnlSbn1XrEILvRi3FWIkjykAM
# SIG # End signature block
