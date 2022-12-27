function New-DbaLogin {
    <#
    .SYNOPSIS
        Creates a new SQL Server login

    .DESCRIPTION
        Creates a new SQL Server login with provided specifications

    .PARAMETER SqlInstance
        The target SQL Server(s)

    .PARAMETER SqlCredential
        Login to the target instance using alternative credentials. Accepts PowerShell credentials (Get-Credential).

        Windows Authentication, SQL Server Authentication, Active Directory - Password, and Active Directory - Integrated are all supported.

        For MFA support, please use Connect-DbaInstance.

    .PARAMETER Login
        The Login name(s)

    .PARAMETER SecurePassword
        Secure string used to authenticate the Login

    .PARAMETER HashedPassword
        Hashed password string used to authenticate the Login

    .PARAMETER InputObject
        Takes the parameters required from a Login object that has been piped into the command

    .PARAMETER LoginRenameHashtable
        Pass a hash table into this parameter to change login names when piping objects into the procedure

    .PARAMETER MapToCertificate
        Map the login to a certificate

    .PARAMETER MapToAsymmetricKey
        Map the login to an asymmetric key

    .PARAMETER MapToCredential
        Map the login to a credential

    .PARAMETER Sid
        Provide an explicit Sid that should be used when creating the account. Can be [byte[]] or hex [string] ('0xFFFF...')

    .PARAMETER DefaultDatabase
        Default database for the login

    .PARAMETER Language
        Login's default language

    .PARAMETER PasswordExpirationEnabled
        Enforces password expiration policy. Requires PasswordPolicyEnforced to be enabled. Can be $true or $false(default)

    .PARAMETER PasswordPolicyEnforced
        Enforces password complexity policy. Can be $true or $false(default)

    .PARAMETER PasswordMustChange
        Enforces user must change password at next login.
        When specified will enforce PasswordExpirationEnabled and PasswordPolicyEnforced as they are required for the must change.

    .PARAMETER Disabled
        Create the login in a disabled state

    .PARAMETER DenyWindowsLogin
        Create the login and deny Windows login ability

    .PARAMETER NewSid
        Ignore sids from the piped login object to generate new sids on the server. Useful when copying login onto the same server

    .PARAMETER ExternalProvider
        Specifies that the login is for Azure AD Authentication.
        Equivalent to T-SQL: 'CREATE LOGIN [claudio@********.onmicrosoft.com] FROM EXTERNAL PROVIDER`

    .PARAMETER Force
        If login exists, drop and recreate

    .PARAMETER WhatIf
        Shows what would happen if the command were to run. No actions are actually performed

    .PARAMETER Confirm
        Prompts you for confirmation before executing any changing operations within the command

    .PARAMETER EnableException
        By default, when something goes wrong we try to catch it, interpret it and give you a friendly warning message.
        This avoids overwhelming you with "sea of red" exceptions, but is inconvenient because it basically disables advanced scripting.
        Using this switch turns this "nice by default" feature off and enables you to catch exceptions with your own try/catch.

    .NOTES
        Tags: Login
        Author: Kirill Kravtsov (@nvarscar)

        Website: https://dbatools.io
        Copyright: (c) 2018 by dbatools, licensed under MIT
        License: MIT https://opensource.org/licenses/MIT

    .LINK
        https://dbatools.io/New-DbaLogin

    .EXAMPLE
        PS C:\> New-DbaLogin -SqlInstance Server1,Server2 -Login Newlogin

        You will be prompted to securely enter the password for a login [Newlogin]. The login would be created on servers Server1 and Server2 with default parameters.

    .EXAMPLE
        PS C:\> $securePassword = Read-Host "Input password" -AsSecureString
        PS C:\> New-DbaLogin -SqlInstance Server1\sql1 -Login Newlogin -SecurePassword $securePassword -PasswordPolicyEnforced -PasswordExpirationEnabled

        Creates a login on Server1\sql1 with a predefined password. The login will have password and expiration policies enforced onto it.

    .EXAMPLE
        PS C:\> Get-DbaLogin -SqlInstance sql1 -Login Oldlogin | New-DbaLogin -SqlInstance sql1 -LoginRenameHashtable @{Oldlogin = 'Newlogin'} -Force -NewSid -Disabled:$false

        Copies a login [Oldlogin] to the same instance sql1 with the same parameters (including password). New login will have a new sid, a new name [Newlogin] and will not be disabled. Existing login [Newlogin] will be removed prior to creation.

    .EXAMPLE
        PS C:\> Get-DbaLogin -SqlInstance sql1 -Login Login1,Login2 | New-DbaLogin -SqlInstance sql2 -PasswordPolicyEnforced -PasswordExpirationEnabled -DefaultDatabase tempdb -Disabled

        Copies logins [Login1] and [Login2] from instance sql1 to instance sql2, but enforces password and expiration policies for the new logins. New logins will also have a default database set to [tempdb] and will be created in a disabled state.

    .EXAMPLE
        PS C:\> New-DbaLogin -SqlInstance sql1 -Login domain\user

        Creates a new Windows Authentication backed login on sql1. The login will be part of the public server role.

    .EXAMPLE
        PS C:\> New-DbaLogin -SqlInstance sql1 -Login domain\user1, domain\user2 -DenyWindowsLogin

        Creates two new Windows Authentication backed login on sql1. The logins would be denied from logging in.

    .EXAMPLE
        PS C:\> New-DbaLogin -SqlInstance sql1 -Login "claudio@********.onmicrosoft.com" -ExternalProvider

        Creates a new login named 'claudio@********.onmicrosoft.com' mapped to Azure Active Directory (AAD).
    #>
    [CmdletBinding(SupportsShouldProcess, DefaultParameterSetName = "Password", ConfirmImpact = "Low")]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSAvoidUsingPlainTextForPassword", "", Justification = "For Parameters Password and MapToCredential")]
    param (
        [parameter(Mandatory, Position = 1)]
        [DbaInstanceParameter[]]$SqlInstance,
        [PSCredential]$SqlCredential,
        [Alias("Name", "LoginName")]
        [parameter(ParameterSetName = "Password", Position = 2)]
        [parameter(ParameterSetName = "PasswordHash")]
        [parameter(ParameterSetName = "MapToCertificate")]
        [parameter(ParameterSetName = "MapToAsymmetricKey")]
        [string[]]$Login,
        [parameter(ValueFromPipeline)]
        [parameter(ParameterSetName = "Password")]
        [parameter(ParameterSetName = "PasswordHash")]
        [parameter(ParameterSetName = "MapToCertificate")]
        [parameter(ParameterSetName = "MapToAsymmetricKey")]
        [object[]]$InputObject,
        [Alias("Rename")]
        [hashtable]$LoginRenameHashtable,
        [parameter(ParameterSetName = "Password", Position = 3)]
        [Alias("Password")]
        [Security.SecureString]$SecurePassword,
        [Alias("Hash", "PasswordHash")]
        [parameter(ParameterSetName = "PasswordHash")]
        [string]$HashedPassword,
        [parameter(ParameterSetName = "MapToCertificate")]
        [string]$MapToCertificate,
        [parameter(ParameterSetName = "MapToAsymmetricKey")]
        [string]$MapToAsymmetricKey,
        [string]$MapToCredential,
        [object]$Sid,
        [Alias("DefaultDB")]
        [parameter(ParameterSetName = "Password")]
        [parameter(ParameterSetName = "PasswordHash")]
        [string]$DefaultDatabase,
        [parameter(ParameterSetName = "Password")]
        [parameter(ParameterSetName = "PasswordHash")]
        [string]$Language,
        [Alias("Expiration", "CheckExpiration")]
        [parameter(ParameterSetName = "Password")]
        [parameter(ParameterSetName = "PasswordHash")]
        [switch]$PasswordExpirationEnabled,
        [Alias("Policy", "CheckPolicy")]
        [parameter(ParameterSetName = "Password")]
        [parameter(ParameterSetName = "PasswordHash")]
        [switch]$PasswordPolicyEnforced,
        [Alias("MustChange")]
        [parameter(ParameterSetName = "Password")]
        [switch]$PasswordMustChange,
        [Alias("Disable")]
        [switch]$Disabled,
        [switch]$DenyWindowsLogin,
        [switch]$NewSid,
        [switch]$ExternalProvider,
        [switch]$Force,
        [switch]$EnableException
    )

    begin {
        if ($Force) { $ConfirmPreference = 'none' }

        if ($Sid) {
            if ($Sid.GetType().Name -ne 'Byte[]') {
                foreach ($symbol in $Sid.TrimStart("0x").ToCharArray()) {
                    if ($symbol -notin "0123456789ABCDEF".ToCharArray()) {
                        Stop-Function -Message "Sid has invalid character '$symbol', cannot proceed." -Category InvalidArgument -EnableException $EnableException
                        return
                    }
                }
                $Sid = Convert-HexStringToByte $Sid
            }
        }

        if ($HashedPassword) {
            if ($HashedPassword.GetType().Name -eq 'Byte[]') {
                $HashedPassword = Convert-ByteToHexString $HashedPassword
            }
        }
    }

    process {
        if (Test-FunctionInterrupt) { return }

        #At least one of those should be specified
        if (!($Login -or $InputObject)) {
            Stop-Function -Message "No logins have been specified." -Category InvalidArgument -EnableException $EnableException
            Return
        }

        if ($PasswordMustChange -and (-not $SecurePassword)) {
            Stop-Function -Message "You need to specified -SecurePassword when using -PasswordMustChange parameter." -Category InvalidArgument -EnableException $EnableException
            Return
        }

        $loginCollection = @()
        if ($InputObject) {
            $loginCollection += $InputObject
            if ($Login) {
                Stop-Function -Message "Parameter -Login is not supported when processing objects from -InputObject. If you need to rename the logins, please use -LoginRenameHashtable." -Category InvalidArgument -EnableException $EnableException
                Return
            }
        } else {
            $loginCollection += $Login
        }
        foreach ($instance in $SqlInstance) {
            try {
                $server = Connect-DbaInstance -SqlInstance $instance -SqlCredential $SqlCredential
            } catch {
                Stop-Function -Message "Failure" -Category ConnectionError -ErrorRecord $_ -Target $instance -Continue
            }

            foreach ($loginItem in $loginCollection) {
                $usedTsql = $false
                #check if $loginItem is an SMO Login object
                if ($loginItem.GetType().Name -eq 'Login') {
                    #Get all the necessary fields
                    $loginName = $loginItem.Name
                    $loginType = $loginItem.LoginType
                    $currentSid = $loginItem.Sid
                    $currentDefaultDatabase = $loginItem.DefaultDatabase
                    $currentLanguage = $loginItem.Language
                    $currentPasswordExpirationEnabled = $loginItem.PasswordExpirationEnabled
                    $currentPasswordPolicyEnforced = $loginItem.PasswordPolicyEnforced
                    $currentPasswordMustChange = $loginItem.MustChangePassword
                    $currentDisabled = $loginItem.IsDisabled
                    $currentDenyWindowsLogin = $loginItem.DenyWindowsLogin
                    #Get previous password
                    if ($loginType -eq 'SqlLogin' -and !($SecurePassword -or $HashedPassword)) {
                        $sourceServer = $loginItem.Parent
                        switch ($sourceServer.versionMajor) {
                            0 { $sql = "SELECT CONVERT(VARBINARY(256),password) as hashedpass FROM master.dbo.syslogins WHERE loginname='$loginName'" }
                            8 { $sql = "SELECT CONVERT(VARBINARY(256),password) as hashedpass FROM dbo.syslogins WHERE name='$loginName'" }
                            9 { $sql = "SELECT CONVERT(VARBINARY(256),password_hash) as hashedpass FROM sys.sql_logins where name='$loginName'" }
                            default {
                                $sql = "SELECT CAST(CONVERT(VARCHAR(256), CAST(LOGINPROPERTY(name,'PasswordHash')
                                    AS VARBINARY(256)), 1) AS NVARCHAR(max)) AS hashedpass
                                    FROM sys.server_principals
                                    WHERE principal_id = $($loginItem.id)"
                            }
                        }

                        try {
                            $hashedPass = $sourceServer.ConnectionContext.ExecuteScalar($sql)
                        } catch {
                            $hashedPassDt = $sourceServer.Databases['master'].ExecuteWithResults($sql)
                            $hashedPass = $hashedPassDt.Tables[0].Rows[0].Item(0)
                        }

                        if ($hashedPass.GetType().Name -ne "String") {
                            $hashedPass = Convert-ByteToHexString $hashedPass
                        }
                        $currentHashedPassword = $hashedPass
                    }

                    #Get cryptography and attached credentials
                    if ($loginType -eq 'AsymmetricKey') {
                        $currentAsymmetricKey = $loginItem.AsymmetricKey
                    }
                    if ($loginType -eq 'Certificate') {
                        $currentCertificate = $loginItem.Certificate
                    }
                    #This method or property is accessible only while working with SQL Server 2008 or later.
                    if ($sourceServer.versionMajor -gt 9) {
                        if ($loginItem.EnumCredentials()) {
                            $currentCredential = $loginItem.EnumCredentials()
                        }
                    }
                } else {
                    $loginName = $loginItem
                    $currentSid = $currentDefaultDatabase = $currentLanguage = $currentPasswordExpirationEnabled = $currentAsymmetricKey = $currentCertificate = $currentCredential = $currentDisabled = $currentPasswordPolicyEnforced = $currentDenyWindowsLogin = $null

                    if ($PsCmdlet.ParameterSetName -eq "MapToCertificate") { $loginType = 'Certificate' }
                    elseif ($PsCmdlet.ParameterSetName -eq "MapToAsymmetricKey") { $loginType = 'AsymmetricKey' }
                    elseif ($ExternalProvider) { $loginType = 'ExternalUser' } # Before 'SqlLogin' check otherwise will assume it's a SqlLogin and will rquest pwd
                    elseif ($loginItem.IndexOf('\') -eq -1) { $loginType = 'SqlLogin' }
                    else { $loginType = 'WindowsUser' }
                }

                if ((-not $server.IsAzure) -and ($server.LoginMode -ne [Microsoft.SqlServer.Management.Smo.ServerLoginMode]::Mixed) -and ($loginType -eq 'SqlLogin')) {
                    Write-Message -Level Warning -Message "$instance does not have Mixed Mode enabled. [$loginName] is an SQL Login. Enable mixed mode authentication after the migration completes to use this type of login."
                }

                if ($Sid) {
                    $currentSid = $Sid
                }
                if ($DefaultDatabase) {
                    $currentDefaultDatabase = $DefaultDatabase
                }
                if ($Language) {
                    $currentLanguage = $Language
                }
                if ($PSBoundParameters.Keys -contains 'PasswordExpirationEnabled') {
                    $currentPasswordExpirationEnabled = $PasswordExpirationEnabled
                }
                if ($PSBoundParameters.Keys -contains 'PasswordPolicyEnforced') {
                    $currentPasswordPolicyEnforced = $PasswordPolicyEnforced
                }
                if ($PSBoundParameters.Keys -contains 'PasswordMustChange') {
                    $currentPasswordMustChange = $PasswordMustChange
                    # Enforce Expiration and Policy properties as they are needed when we want to use "Must Change" property
                    Write-Message -Level Verbose -Message "Forcing 'Expiration' and 'Policy' properties to 'ON' because MustChange was specified."
                    $currentPasswordExpirationEnabled = $true
                    $currentPasswordPolicyEnforced = $true
                }
                if ($PSBoundParameters.Keys -contains 'MapToAsymmetricKey') {
                    $currentAsymmetricKey = $MapToAsymmetricKey
                }
                if ($PSBoundParameters.Keys -contains 'MapToCertificate') {
                    $currentCertificate = $MapToCertificate
                }
                if ($PSBoundParameters.Keys -contains 'MapToCredential') {
                    $currentCredential = $MapToCredential
                }
                if ($PSBoundParameters.Keys -contains 'Disabled') {
                    $currentDisabled = $Disabled
                }
                if (Test-Bound -Parameter DenyWindowsLogin) {
                    $currentDenyWindowsLogin = $DenyWindowsLogin
                }

                #Apply renaming if necessary
                if ($LoginRenameHashtable.Keys -contains $loginName) {
                    $loginName = $LoginRenameHashtable[$loginName]
                }

                #Requesting password if required
                if ($loginItem.GetType().Name -ne 'Login' -and $loginType -eq 'SqlLogin' -and !($SecurePassword -or $HashedPassword)) {
                    $SecurePassword = Read-Host -AsSecureString -Prompt "Enter a new password for the SQL Server login(s)"
                }

                #verify if login exists on the server
                if (($existingLogin = $server.Logins[$loginName])) {
                    if ($force) {
                        if ($Pscmdlet.ShouldProcess($existingLogin, "Dropping existing login $loginName on $instance because -Force was used")) {
                            try {
                                $existingLogin.Drop()
                            } catch {
                                Stop-Function -Message "Could not remove existing login $loginName on $instance, skipping." -Target $loginName -Continue
                            }
                        }
                    } else {
                        Stop-Function -Message "Login $loginName already exists on $instance and -Force was not specified" -Target $loginName -Continue
                    }
                }


                if ($Pscmdlet.ShouldProcess($SqlInstance, "Creating login $loginName on $instance")) {
                    try {
                        $loginName = $loginName.Replace('[', '').Replace(']', '')
                        $newLogin = New-Object Microsoft.SqlServer.Management.Smo.Login($server, $loginName)
                        $newLogin.LoginType = $loginType

                        $withParams = ""

                        if ($loginType -eq 'SqlLogin' -and $currentSid -and !$NewSid) {
                            Write-Message -Level Verbose -Message "Setting $loginName SID"
                            $withParams += ", SID = " + (Convert-ByteToHexString $currentSid)
                            $newLogin.Set_Sid($currentSid)
                        }

                        if ($loginType -in ("WindowsUser", "WindowsGroup", "SqlLogin", "ExternalUser")) {
                            if ($currentDefaultDatabase) {
                                Write-Message -Level Verbose -Message "Setting $loginName default database to $currentDefaultDatabase"
                                $withParams += ", DEFAULT_DATABASE = [$currentDefaultDatabase]"
                                $newLogin.DefaultDatabase = $currentDefaultDatabase
                            }

                            if ($currentLanguage) {
                                Write-Message -Level Verbose -Message "Setting $loginName language to $currentLanguage"
                                $withParams += ", DEFAULT_LANGUAGE = [$currentLanguage]"
                                $newLogin.Language = $currentLanguage
                            }

                            #CHECK_EXPIRATION: default - OFF
                            if ($currentPasswordExpirationEnabled) {
                                $withParams += ", CHECK_EXPIRATION = ON"
                                $newLogin.PasswordExpirationEnabled = $true
                            } elseif ($loginType -eq 'SqlLogin') {
                                $withParams += ", CHECK_EXPIRATION = OFF"
                                $newLogin.PasswordExpirationEnabled = $false
                            }

                            #CHECK_POLICY: default - ON
                            if ($currentPasswordPolicyEnforced) {
                                $withParams += ", CHECK_POLICY = ON"
                                $newLogin.PasswordPolicyEnforced = $true
                            } elseif ($loginType -eq 'SqlLogin') {
                                $withParams += ", CHECK_POLICY = OFF"
                                $newLogin.PasswordPolicyEnforced = $false
                            }

                            # DENY CONNECT SQL
                            if ($currentDenyWindowsLogin) {
                                Write-Message -Level VeryVerbose -Message "Setting $loginName DenyWindowsLogin to $currentDenyWindowsLogin"
                                $newLogin.DenyWindowsLogin = $currentDenyWindowsLogin
                            }

                            #Generate hashed password if necessary
                            if ($SecurePassword) {
                                $currentHashedPassword = Get-PasswordHash $SecurePassword $server.versionMajor
                            } elseif ($HashedPassword) {
                                $currentHashedPassword = $HashedPassword
                            }
                        } elseif ($loginType -eq 'AsymmetricKey') {
                            $newLogin.AsymmetricKey = $currentAsymmetricKey
                        } elseif ($loginType -eq 'Certificate') {
                            $newLogin.Certificate = $currentCertificate
                        }

                        #Add credential
                        if ($currentCredential) {
                            $withParams += ", CREDENTIAL = [$currentCredential]"
                        }

                        Write-Message -Level Verbose -Message "Adding as login type $loginType"

                        # Attempt to add login using SMO, then T-SQL
                        try {
                            if ($loginType -in ("WindowsUser", "WindowsGroup", "AsymmetricKey", "Certificate", "ExternalUser")) {
                                if ($withParams) { $withParams = " WITH " + $withParams.TrimStart(',') }
                                $newLogin.Create()
                            } elseif ($loginType -eq "SqlLogin") {
                                $newLogin.Create($currentHashedPassword, [Microsoft.SqlServer.Management.Smo.LoginCreateOptions]::IsHashed)
                            }
                            $newLogin.Refresh()

                            #Adding credential
                            if ($currentCredential) {
                                try {
                                    $newLogin.AddCredential($currentCredential)
                                } catch {
                                    $newLogin.Drop()
                                    Stop-Function -Message "Failed to add $loginName to $instance." -Category InvalidOperation -ErrorRecord $_ -Target $instance -Continue
                                }
                            }
                            Write-Message -Level Verbose -Message "Successfully added $loginName to $instance."
                        } catch {
                            Write-Message -Level Verbose -Message "Failed to create $loginName on $instance using SMO, trying T-SQL."
                            try {
                                if ($loginType -eq 'AsymmetricKey') { $sql = "CREATE LOGIN [$loginName] FROM ASYMMETRIC KEY [$currentAsymmetricKey]" }
                                elseif ($loginType -eq 'Certificate') { $sql = "CREATE LOGIN [$loginName] FROM CERTIFICATE [$currentCertificate]" }
                                elseif ($loginType -eq 'SqlLogin' -and $server.DatabaseEngineType -eq 'SqlAzureDatabase') {
                                    # Azure SQL doesn't support HASHED so we have to dump out the plain text password :(
                                    $sql = "CREATE LOGIN [$loginName] WITH PASSWORD = '$($SecurePassword | ConvertFrom-SecurePass)'"
                                } elseif ($loginType -eq 'ExternalUser' -and ($server.DatabaseEngineType -eq 'SqlAzureDatabase' -or $server.DatabaseEngineEdition -eq 'SqlManagedInstance')) {
                                    # Azure SQL DB and Azure SQL Managed Instance are the only ones that currently support FROM EXTERNAL PROVIDER syntax
                                    $sql = "CREATE LOGIN [$loginName] FROM EXTERNAL PROVIDER" + $withParams
                                } elseif ($loginType -eq 'SqlLogin' ) {
                                    $sql = "CREATE LOGIN [$loginName] WITH PASSWORD = $currentHashedPassword HASHED" + $withParams
                                } else {
                                    $sql = "CREATE LOGIN [$loginName] FROM WINDOWS" + $withParams
                                }
                                $null = $server.Query($sql)
                                $newLogin = $server.logins[$loginName]
                                Write-Message -Level Verbose -Message "Successfully added $loginName to $instance."
                                $usedTsql = $true
                            } catch {
                                Stop-Function -Message "Failed to add $loginName to $instance." -Category InvalidOperation -ErrorRecord $_ -Target $instance -Continue
                            }
                        }

                        #Process the Disabled property
                        if ($currentDisabled) {
                            try {
                                $newLogin.Disable()
                                Write-Message -Level Verbose -Message "Login $loginName has been disabled on $instance."
                            } catch {
                                Write-Message -Level Verbose -Message "Failed to disable $loginName on $instance using SMO, trying T-SQL."
                                try {
                                    $sql = "ALTER LOGIN [$loginName] DISABLE"
                                    $null = $server.Query($sql)
                                    Write-Message -Level Verbose -Message "Login $loginName has been disabled on $instance."
                                    $usedTsql = $true
                                } catch {
                                    Stop-Function -Message "Failed to disable $loginName on $instance." -Category InvalidOperation -ErrorRecord $_ -Target $instance -Continue
                                }
                            }
                        }
                        #Process the DenyWindowsLogin property
                        if ($currentDenyWindowsLogin -ne $newLogin.DenyWindowsLogin) {
                            try {
                                $newLogin.DenyWindowsLogin = $currentDenyWindowsLogin
                                $newLogin.Alter()
                                Write-Message -Level Verbose -Message "Login $loginName has been denied from logging in on $instance."
                            } catch {
                                Write-Message -Level Verbose -Message "Failed to deny from logging in $loginName on $instance using SMO, trying T-SQL."
                                try {
                                    $sql = "DENY CONNECT SQL TO [{0}]" -f $newLogin.Name
                                    $null = $server.Query($sql)
                                    Write-Message -Level Verbose -Message "Login $loginName has been denied from logging in on $instance."
                                    $usedTsql = $true
                                } catch {
                                    Stop-Function -Message "Failed to set deny windows login priviledge $loginName on $instance." -Category InvalidOperation -ErrorRecord $_ -Target $instance -Continue
                                }
                            }
                        }

                        #Process the MustChangePassword property
                        if ($currentPasswordMustChange -ne $newLogin.MustChangePassword) {
                            try {
                                $newLogin.ChangePassword($SecurePassword, $true, $true)
                                Write-Message -Level Verbose -Message "Login $loginName has been marked as must change password."

                                # We need to refresh login after ChangePassword. Otherwise, MustChangePassword will appear as False
                                $server.Logins[$loginName].Refresh()
                            } catch {
                                Write-Message -Level Verbose -Message "Failed to marked as must change password in $loginName on $instance using SMO."
                            }
                        }

                        #Display results
                        # If we ever used T-SQL, the smo is some times not up to date and should be refreshed
                        if ($usedTsql) {
                            $server.Logins.Refresh()
                        }

                        Add-TeppCacheItem -SqlInstance $server -Type login -Name $loginName

                        Get-DbaLogin -SqlInstance $server -Login $loginName

                    } catch {
                        Stop-Function -Message "Failed to create login $loginName on $instance." -Target $credential -InnerErrorRecord $_ -Continue
                    }
                }
            }
        }
    }
}
# SIG # Begin signature block
# MIIjYAYJKoZIhvcNAQcCoIIjUTCCI00CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCCgN9ekNpGtaho6
# vN6lgDEz9783BvbF5iEuYlE2WU/sP6CCHVkwggUaMIIEAqADAgECAhADBbuGIbCh
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
# BgorBgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCCB7YROKL7Y/vt2XSjym3DRi6oc
# CWMl+gDC3fGzVEeB1DANBgkqhkiG9w0BAQEFAASCAQCPsaYcU0UJFijFtEkFTvpg
# wLptfCxE/AmtznvvqHCzFjV2C3TQxIkX7CE+Egsh1A5nxlfdaE5lQBSGJLCilFWo
# B/s4myNZtLZUgk3NA3GuyXVAt27dv5Ml6hwAoS5K76Rd643C5LbGIYPLNjlO4RQN
# iRTofmNVNpTYre0CjjWZGd1zR6yOMxTy4nGiIvxBo/174KpCHAzzUCHCSLv6YQq4
# +4KFbpnT1KGo22oUm+d3R+5jKFEACyxISb57raMyh5Ulp9SJ/I+LeZJ0m/18mfbs
# L7cx1fLSSJ7HUwHoj61bqwSsI2r+jcNJmLEnHvKEloXgzlFuGgXVpje8hBU6Zod6
# oYIDIDCCAxwGCSqGSIb3DQEJBjGCAw0wggMJAgEBMHcwYzELMAkGA1UEBhMCVVMx
# FzAVBgNVBAoTDkRpZ2lDZXJ0LCBJbmMuMTswOQYDVQQDEzJEaWdpQ2VydCBUcnVz
# dGVkIEc0IFJTQTQwOTYgU0hBMjU2IFRpbWVTdGFtcGluZyBDQQIQDE1pckuU+jwq
# Sj0pB4A9WjANBglghkgBZQMEAgEFAKBpMBgGCSqGSIb3DQEJAzELBgkqhkiG9w0B
# BwEwHAYJKoZIhvcNAQkFMQ8XDTIyMTExNzA4NTcwMFowLwYJKoZIhvcNAQkEMSIE
# IBh8NKJmwOJBcKe+aKRVJoKw2iGhfo7xZuOObwPQGS8rMA0GCSqGSIb3DQEBAQUA
# BIICAA9UeuPai1mk7R0YLvOT5mTdBp2eYcCB8+kc+Ho3ZhpPnaljbZLrC2PE5CtZ
# yo9mDIZhUURH/UWUOkWvtHieKFnpwTf0gxbqkXKGSBYoWq/NIs8LDOfrsQEcVysC
# 3/hyOE3leV/3DWqAVoHvzR+fWn40cSRMUc6hbi25VIo5+IfvvR/cpfrluJMAEgVI
# QNzNbm10Ct3h0T6gxvtKl+2mDNGFP1GTPqb2kPTn3WYFOrcsPpPPmmSLj96NLNyX
# aAiJzuYJnCQtLFEGy5nXzbtO4n83f4Ap1fJqsSLG9MKOz3EOuCd6Gk2t87v5PpKK
# H3QwAgfrqmcg9dFgnAKeZUxCLuNSQ3V5TsbrR6y+7MyqdnpkUR5bW0MV4/56j0XY
# I0XpOS9j2LxeniFzV3YQ7g1kcKYvFyqWP/AVqLggyvpKQVbXv2OcpMJmocCSLamd
# L/2audgRGJcrIYfQH/yw0Vgytk/yHmqg76EKQAWkeHKkPtDaD4kbMPgyNpWpMluF
# TA7WUwx28FwB650YeKHNdS/Ok+0ppFlyF+I76iS2lDvB3gOOI8qjZRKCC5w7sQIp
# VpL0HtNfuGFtU4cuDeDzP5Zaga/+wyREL+lJmAARzw0DzV7YgcbIviUErwBXnOdL
# 7cA38qYyMg7ztizegkni6fEt8EfYKnxZz8avFsfEY+t6jrYp
# SIG # End signature block
