function Set-DbaLogin {
    <#
    .SYNOPSIS
        Set-DbaLogin makes it possible to make changes to one or more logins.
        SQL Azure DB is not supported.

    .DESCRIPTION
        Set-DbaLogin will enable you to change the password, unlock, rename, disable or enable, deny or grant login privileges to the login. It's also possible to add or remove server roles from the login.

    .PARAMETER SqlInstance
        The target SQL Server instance or instances. You must have sysadmin access and server version must be SQL Server version 2000 or greater.

    .PARAMETER SqlCredential
        Login to the target instance using alternative credentials. Accepts PowerShell credentials (Get-Credential).

        Windows Authentication, SQL Server Authentication, Active Directory - Password, and Active Directory - Integrated are all supported.

        For MFA support, please use Connect-DbaInstance.

    .PARAMETER Login
        The login that needs to be changed

    .PARAMETER SecurePassword
        The new password for the login This can be either a credential or a secure string.

    .PARAMETER DefaultDatabase
        Default database for the login

    .PARAMETER Unlock
        Switch to unlock an account. This can be used in conjunction with the -SecurePassword or -Force parameters.
        The default is false.

    .PARAMETER PasswordMustChange
        Does the user need to change his/her password. This will only be used in conjunction with the -SecurePassword parameter.
        It is required that the login have both PasswordPolicyEnforced (check_policy) and PasswordExpirationEnabled (check_expiration) enabled for the login. See the Microsoft documentation for ALTER LOGIN for more details.
        The default is false.

    .PARAMETER NewName
        The new name for the login.

    .PARAMETER Disable
        Disable the login

    .PARAMETER Enable
        Enable the login

    .PARAMETER DenyLogin
        Deny access to SQL Server

    .PARAMETER GrantLogin
        Grant access to SQL Server

    .PARAMETER PasswordPolicyEnforced
        Enable the password policy on the login (check_policy = ON). This option must be enabled in order for -PasswordExpirationEnabled to be used.

    .PARAMETER PasswordExpirationEnabled
        Enable the password expiration check on the login (check_expiration = ON). In order to enable this option the PasswordPolicyEnforced (check_policy) must also be enabled for the login.

    .PARAMETER AddRole
        Add one or more server roles to the login
        The following roles can be used "bulkadmin", "dbcreator", "diskadmin", "processadmin", "public", "securityadmin", "serveradmin", "setupadmin", "sysadmin".

    .PARAMETER RemoveRole
        Remove one or more server roles to the login
        The following roles can be used "bulkadmin", "dbcreator", "diskadmin", "processadmin", "public", "securityadmin", "serveradmin", "setupadmin", "sysadmin".

    .PARAMETER InputObject
        Allows logins to be piped in from Get-DbaLogin

    .PARAMETER WhatIf
        If this switch is enabled, no actions are performed but informational messages will be displayed that explain what would happen if the command were to run.

    .PARAMETER Confirm
        If this switch is enabled, you will be prompted for confirmation before executing any operations that change state.

    .PARAMETER Force
        This switch is used with -Unlock to unlock a login without providing a password. This command will temporarily disable and enable the policy settings as described at https://www.mssqltips.com/sqlservertip/2758/how-to-unlock-a-sql-login-without-resetting-the-password/.

    .PARAMETER EnableException
        By default, when something goes wrong we try to catch it, interpret it and give you a friendly warning message.
        This avoids overwhelming you with "sea of red" exceptions, but is inconvenient because it basically disables advanced scripting.
        Using this switch turns this "nice by default" feature off and enables you to catch exceptions with your own try/catch.

    .NOTES
        Tags: Login
        Author: Sander Stad (@sqlstad), sqlstad.nl

        Website: https://dbatools.io
        Copyright: (c) 2018 by dbatools, licensed under MIT
        License: MIT https://opensource.org/licenses/MIT

    .LINK
        https://dbatools.io/Set-DbaLogin

    .EXAMPLE
        PS C:\> $SecurePassword = (Get-Credential NoUsernameNeeded).Password
        PS C:\> $cred = New-Object System.Management.Automation.PSCredential ("username", $SecurePassword)
        PS C:\> Set-DbaLogin -SqlInstance sql1 -Login login1 -SecurePassword $cred -Unlock -PasswordMustChange

        Set the new password for login1 using a credential, unlock the account and set the option
        that the user must change password at next logon.

    .EXAMPLE
        PS C:\> Set-DbaLogin -SqlInstance sql1 -Login login1 -Enable

        Enable the login

    .EXAMPLE
        PS C:\> Set-DbaLogin -SqlInstance sql1 -Login login1, login2, login3, login4 -Enable

        Enable multiple logins

    .EXAMPLE
        PS C:\> Set-DbaLogin -SqlInstance sql1, sql2, sql3 -Login login1, login2, login3, login4 -Enable

        Enable multiple logins on multiple instances

    .EXAMPLE
        PS C:\> Set-DbaLogin -SqlInstance sql1 -Login login1 -Disable

        Disable the login

    .EXAMPLE
        PS C:\> Set-DbaLogin -SqlInstance sql1 -Login login1 -DenyLogin

        Deny the login to connect to the instance

    .EXAMPLE
        PS C:\> Set-DbaLogin -SqlInstance sql1 -Login login1 -GrantLogin

        Grant the login to connect to the instance

    .EXAMPLE
        PS C:\> Set-DbaLogin -SqlInstance sql1 -Login login1 -PasswordPolicyEnforced

        Enforces the password policy on a login

    .EXAMPLE
        PS C:\> Set-DbaLogin -SqlInstance sql1 -Login login1 -PasswordPolicyEnforced:$false

        Disables enforcement of the password policy on a login

    .EXAMPLE
        PS C:\> Set-DbaLogin -SqlInstance sql1 -Login test -AddRole serveradmin

        Add the server role "serveradmin" to the login

    .EXAMPLE
        PS C:\> Set-DbaLogin -SqlInstance sql1 -Login test -RemoveRole bulkadmin

        Remove the server role "bulkadmin" to the login

    .EXAMPLE
        PS C:\> $login = Get-DbaLogin -SqlInstance sql1 -Login test
        PS C:\> $login | Set-DbaLogin -Disable

        Disable the login from the pipeline

    .EXAMPLE
        PS C:\> Set-DbaLogin -SqlInstance sql1 -Login login1 -DefaultDatabase master

        Set the default database to master on a login

    .EXAMPLE
        PS C:\> Set-DbaLogin -SqlInstance sql1 -Login login1 -Unlock -Force

        Unlocks the login1 on the sql1 instance using the technique described at https://www.mssqltips.com/sqlservertip/2758/how-to-unlock-a-sql-login-without-resetting-the-password/
    #>

    [CmdletBinding(SupportsShouldProcess)]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSAvoidUsingPlainTextForPassword", "", Justification = "For Parameter Password")]
    param (
        [DbaInstanceParameter[]]$SqlInstance,
        [PSCredential]$SqlCredential,
        [string[]]$Login,
        [Alias("Password")]
        [object]$SecurePassword, #object so that it can accept credential or securestring
        [Alias("DefaultDB")]
        [string]$DefaultDatabase,
        [switch]$Unlock,
        [Alias("MustChange")]
        [switch]$PasswordMustChange,
        [string]$NewName,
        [switch]$Disable,
        [switch]$Enable,
        [switch]$DenyLogin,
        [switch]$GrantLogin,
        [switch]$PasswordPolicyEnforced,
        [switch]$PasswordExpirationEnabled,
        [ValidateSet('bulkadmin', 'dbcreator', 'diskadmin', 'processadmin', 'public', 'securityadmin', 'serveradmin', 'setupadmin', 'sysadmin')]
        [string[]]$AddRole,
        [ValidateSet('bulkadmin', 'dbcreator', 'diskadmin', 'processadmin', 'public', 'securityadmin', 'serveradmin', 'setupadmin', 'sysadmin')]
        [string[]]$RemoveRole,
        [parameter(ValueFromPipeline)]
        [Microsoft.SqlServer.Management.Smo.Login[]]$InputObject,
        [switch]$Force,
        [switch]$EnableException
    )

    begin {
        # Check the parameters
        if ((Test-Bound -ParameterName 'SqlInstance') -and (Test-Bound -ParameterName 'Login' -Not)) {
            Stop-Function -Message 'You must specify a Login when using SqlInstance'
        }

        if ((Test-Bound -ParameterName 'NewName') -and $Login -eq $NewName) {
            Stop-Function -Message 'Login name is the same as the value in -NewName' -Target $Login -Continue
        }

        if ((Test-Bound -ParameterName 'Disable') -and (Test-Bound -ParameterName 'Enable')) {
            Stop-Function -Message 'You cannot use both -Enable and -Disable together' -Target $Login -Continue
        }

        if ((Test-Bound -ParameterName 'GrantLogin') -and (Test-Bound -ParameterName 'DenyLogin')) {
            Stop-Function -Message 'You cannot use both -GrantLogin and -DenyLogin together' -Target $Login -Continue
        }

        if (Test-bound -ParameterName 'SecurePassword') {
            switch ($SecurePassword.GetType().Name) {
                'PSCredential' { $NewSecurePassword = $SecurePassword.Password }
                'SecureString' { $NewSecurePassword = $SecurePassword }
                default {
                    Stop-Function -Message 'Password must be a PSCredential or SecureString' -Target $Login
                }
            }
        }

        if ((Test-Bound Unlock) -and (Test-Bound SecurePassword -Not) -and (Test-Bound Force -Not)) {
            Stop-Function -Message 'You must specify a password when using the -Unlock parameter or use the -Force parameter. See the help documentation for this command.'
        }

        if ((Test-Bound PasswordMustChange) -and (Test-Bound SecurePassword -Not)) {
            Stop-Function -Message 'You must specify a password when using the -PasswordMustChange parameter. See the command help for more details.'
        }
    }

    process {
        if (Test-FunctionInterrupt) { return }

        $allLogins = @{ }
        foreach ($instance in $SqlInstance) {
            # Try connecting to the instance
            try {
                $server = Connect-DbaInstance -SqlInstance $instance -SqlCredential $SqlCredential -MinimumVersion 9 -AzureUnsupported
            } catch {
                Stop-Function -Message "Failure" -Category ConnectionError -ErrorRecord $_ -Target $instance -Continue
            }
            $allLogins[$instance.ToString()] = Get-DbaLogin -SqlInstance $server
            $InputObject += $allLogins[$instance.ToString()] | Where-Object { ($_.Name -in $Login) -and ($_.Name -notlike '##*') }
        }

        # Loop through all the logins
        foreach ($l in $InputObject) {
            if ($Pscmdlet.ShouldProcess($l, "Setting Changes to Login on $($server.name)")) {
                $server = $l.Parent

                # Create the notes
                $notes = @()

                # caller wants to unlock a login without a password and has specified the -Force param
                if ((Test-Bound Unlock) -and (Test-Bound SecurePassword -Not) -and (Test-Bound Force)) {
                    if (-not $l.IsLocked) {
                        Write-Message -Message "Login $l is not locked" -Level Warning
                    } else {
                        try {
                            # save the current state of the policy options for check_policy and check_expiration
                            $checkPolicy = $l.PasswordPolicyEnforced
                            $checkExpiration = $l.PasswordExpirationEnabled

                            # alter the login to switch off the check_policy and check_expiration. Ref: https://www.mssqltips.com/sqlservertip/2758/how-to-unlock-a-sql-login-without-resetting-the-password/
                            $l.PasswordPolicyEnforced = $false
                            $l.PasswordExpirationEnabled = $false
                            $l.Alter()

                            # restore the settings immediately
                            $l.PasswordPolicyEnforced = $checkPolicy
                            $l.PasswordExpirationEnabled = $checkExpiration
                            $l.Alter()

                            # out of an abundance of caution let's refresh the login and double check the settings to see if they match what they were before
                            $l.Refresh()

                            if ($checkPolicy -ne $l.PasswordPolicyEnforced) {
                                Stop-Function -Message "Unable to restore the check_policy setting for $l" -Target $l -Continue
                            }

                            if ($checkExpiration -ne $l.PasswordExpirationEnabled) {
                                Stop-Function -Message "Unable to restore the check_expiration setting for $l" -Target $l -Continue
                            }
                        } catch {
                            $notes += "Unable to unlock"
                            Stop-Function -Message "Unable to unlock $l. Review the 'Enforce password policy' and 'Enforce password expiration' settings for $l" -Target $l -ErrorRecord $_ -Continue
                        }
                    }
                }

                # Change the name
                if (Test-Bound -ParameterName 'NewName') {
                    # Check if the new name doesn't already exist
                    if ($allLogins[$server.Name].Name -notcontains $NewName) {
                        try {
                            $l.Rename($NewName)
                        } catch {
                            $notes += "Couldn't rename login"
                            Stop-Function -Message "Something went wrong changing the name for $l" -Target $l -ErrorRecord $_ -Continue
                        }
                    } else {
                        $notes += 'New login name already exists'
                        Write-Message -Message "New login name $NewName already exists on $instance" -Level Verbose
                    }
                }

                # Disable the login
                if (Test-Bound -ParameterName 'Disable') {
                    if ($l.IsDisabled) {
                        Write-Message -Message "Login $l is already disabled" -Level Verbose
                    } else {
                        try {
                            $l.Disable()
                        } catch {
                            $notes += "Couldn't disable login"
                            Stop-Function -Message "Something went wrong disabling $l" -Target $l -ErrorRecord $_ -Continue
                        }
                    }
                }

                # Enable the login
                if (Test-Bound -ParameterName 'Enable') {
                    if (-not $l.IsDisabled) {
                        Write-Message -Message "Login $l is already enabled" -Level Verbose
                    } else {
                        try {
                            $l.Enable()
                        } catch {
                            $notes += "Couldn't enable login"
                            Stop-Function -Message "Something went wrong enabling $l" -Target $l -ErrorRecord $_ -Continue
                        }
                    }
                }

                # Deny access
                if (Test-Bound -ParameterName 'DenyLogin') {
                    if ($l.DenyWindowsLogin) {
                        Write-Message -Message "Login $l already has login access denied" -Level Verbose
                    } else {
                        $l.DenyWindowsLogin = $true
                    }
                }

                # Grant access
                if (Test-Bound -ParameterName 'GrantLogin') {
                    if (-not $l.DenyWindowsLogin) {
                        Write-Message -Message "Login $l already has login access granted" -Level Verbose
                    } else {
                        $l.DenyWindowsLogin = $false
                    }
                }

                # Enforce password policy
                if (Test-Bound -ParameterName 'PasswordPolicyEnforced') {
                    if ($l.PasswordPolicyEnforced -eq $PasswordPolicyEnforced) {
                        Write-Message -Message "Login $l password policy is already set to $($l.PasswordPolicyEnforced)" -Level Verbose
                    } else {
                        $l.PasswordPolicyEnforced = $PasswordPolicyEnforced
                    }
                }

                # Enforce password expiration
                if (Test-Bound -ParameterName 'PasswordExpirationEnabled') {

                    if ($PasswordExpirationEnabled -and $l.PasswordPolicyEnforced -eq $false) {
                        $notes += "Couldn't set check_expiration = ON because check_policy = OFF for $l. See the command description for more details on these settings."
                        Stop-Function -Message "Couldn't set check_expiration = ON because check_policy = OFF for $l. See the command description for more details on these settings." -Target $l -Continue
                    }

                    if ($l.PasswordExpirationEnabled -eq $PasswordExpirationEnabled) {
                        Write-Message -Message "Login $l password expiration check is already set to $($l.PasswordExpirationEnabled)" -Level Verbose
                    } else {
                        $l.PasswordExpirationEnabled = $PasswordExpirationEnabled
                    }
                }

                # Add server roles to login
                if ($AddRole) {
                    # Loop through each of the roles
                    foreach ($role in $AddRole) {
                        try {
                            $l.AddToRole($role)
                        } catch {
                            $notes += "Couldn't add role $role"
                            Stop-Function -Message "Something went wrong adding role $role to $l" -Target $l -ErrorRecord $_ -Continue
                        }
                    }
                }

                # Remove server roles from login
                if ($RemoveRole) {
                    # Loop through each of the roles
                    foreach ($role in $RemoveRole) {
                        try {
                            $server.Roles[$role].DropMember($l.Name)
                        } catch {
                            $notes += "Couldn't remove role $role"
                            Stop-Function -Message "Something went wrong removing role $role to $l" -Target $l -ErrorRecord $_ -Continue
                        }
                    }
                }

                # Set the default database
                if (Test-Bound -ParameterName 'DefaultDatabase') {
                    if ($l.DefaultDatabase -eq $DefaultDatabase) {
                        Write-Message -Message "Login $l default database is already set to $($l.DefaultDatabase)" -Level Verbose
                    } else {
                        $l.DefaultDatabase = $DefaultDatabase
                    }
                }

                # Alter the login to make the changes
                $l.Alter()
                $l.Refresh()

                # Change the password after the Alter() because the must_change requires the policy settings to be enabled first.
                if (Test-bound -ParameterName 'SecurePassword') {
                    if (Test-Bound PasswordMustChange) {
                        # Validate if the check_policy and check_expiration options are enabled on the login. These are required for the must_change option for alter login.
                        if ((-not $l.PasswordPolicyEnforced) -or (-not $l.PasswordExpirationEnabled)) {
                            Stop-Function -Message "Unable to change the password and set the must_change option for $l because check_policy = $($l.PasswordPolicyEnforced) and check_expiration = $($l.PasswordExpirationEnabled). See the command help for additional information on the -MustChange parameter." -Target $l -Continue
                        }
                    }

                    try {
                        $l.ChangePassword($NewSecurePassword, $Unlock, $PasswordMustChange)
                        $passwordChanged = $true

                        if (Test-Bound PasswordMustChange) {
                            $l.Refresh()  # necessary so that the read only property PasswordMustChange is updated
                        }
                    } catch {
                        $notes += "Couldn't change password"
                        $passwordChanged = $false
                        Stop-Function -Message "Something went wrong changing the password for $l" -Target $l -ErrorRecord $_ -Continue
                    }
                }

                # Retrieve the server roles for the login
                $roles = Get-DbaServerRoleMember -SqlInstance $server | Where-Object { $_.Name -eq $l.Name }

                # Check if there were any notes to include in the results
                if ($notes) {
                    $notes = $notes | Get-Unique
                    $notes = $notes -Join ';'
                } else {
                    $notes = $null
                }
                $rolenames = $roles.Role | Select-Object -Unique

                Add-Member -Force -InputObject $l -MemberType NoteProperty -Name ComputerName -Value $server.ComputerName
                Add-Member -Force -InputObject $l -MemberType NoteProperty -Name InstanceName -Value $server.ServiceName
                Add-Member -Force -InputObject $l -MemberType NoteProperty -Name SqlInstance -Value $server.DomainInstanceName
                Add-Member -Force -InputObject $l -MemberType NoteProperty -Name PasswordChanged -Value $passwordChanged
                Add-Member -Force -InputObject $l -MemberType NoteProperty -Name ServerRole -Value ($rolenames -join ', ')
                Add-Member -Force -InputObject $l -MemberType NoteProperty -Name Notes -Value $notes

                # backwards compatibility: LoginName, DenyLogin
                Add-Member -Force -InputObject $l -MemberType NoteProperty -Name LoginName -Value $l.Name
                Add-Member -Force -InputObject $l -MemberType NoteProperty -Name DenyLogin -Value $l.DenyWindowsLogin

                $defaults = 'ComputerName', 'InstanceName', 'SqlInstance', 'Name', 'DenyLogin', 'IsDisabled', 'IsLocked',
                'PasswordPolicyEnforced', 'PasswordExpirationEnabled', 'MustChangePassword', 'PasswordChanged', 'ServerRole', 'Notes'

                Select-DefaultView -InputObject $l -Property $defaults
            }
        }
    }
}
# SIG # Begin signature block
# MIIjYAYJKoZIhvcNAQcCoIIjUTCCI00CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCBH5mHJBY5IdSE8
# /h8mSiQMfy/pFbFI5P1uPoJRY66AGaCCHVkwggUaMIIEAqADAgECAhADBbuGIbCh
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
# BgorBgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCAwGOilkCdzykhdeDeyLSnsqrvn
# Sq7utVRe+0a7rNZX5zANBgkqhkiG9w0BAQEFAASCAQBGdwV7Xulzx6er7YmmJIKv
# NmQ39wfsfzzH2iC/EDUm9QgoIogJl/4jodJhyxFkXMcjjTQkhmb6v8oubTYZqRKs
# OvuRk6YUsvDVQVV4UAeX4LAb6rlUcFFuN+ctVA50fX0KCrznhE3B3vfWoAY+2Laj
# FiLP6H/4EJJLvoSdeufSm65F2l82iyKbYSw1SzzGu2CR3pds8wfGJErnPeWu8TDW
# MptGWrhZzhcsvyF7rgJ8F/GhYJCLX2JeNIckM6Ct0V21TeilGmB4grVzlGAxHxOj
# hezRu0ndMafX49Ph1EWns3biLC+qq5YCk3NI8PBGAL+SB5TgCOZi8KY82YNPtPaT
# oYIDIDCCAxwGCSqGSIb3DQEJBjGCAw0wggMJAgEBMHcwYzELMAkGA1UEBhMCVVMx
# FzAVBgNVBAoTDkRpZ2lDZXJ0LCBJbmMuMTswOQYDVQQDEzJEaWdpQ2VydCBUcnVz
# dGVkIEc0IFJTQTQwOTYgU0hBMjU2IFRpbWVTdGFtcGluZyBDQQIQDE1pckuU+jwq
# Sj0pB4A9WjANBglghkgBZQMEAgEFAKBpMBgGCSqGSIb3DQEJAzELBgkqhkiG9w0B
# BwEwHAYJKoZIhvcNAQkFMQ8XDTIyMTExNzA4NTczNFowLwYJKoZIhvcNAQkEMSIE
# IL8EF7qFEmKzy/YSq95MkmHpU3v+x0w3a7KZi6aRjK09MA0GCSqGSIb3DQEBAQUA
# BIICAMPEPKSR5UmhKf9k750Hs4LDj8yAC8FNOZVXBLoAQK29T7ve/i2yTXS1SuKc
# 6yyFLyg374/zXMNZ7szRfTOSiktg0KU5gU68Bh/0BF7Y5i9TyMdbkMmY/tA9m/th
# rocCAgl2vWiXQwibLJVvfPw6CieG9Lzx39HLcCl4rSrdhA/3TviKuYlNznVKEGL6
# qRlsI6Ia4D7fCpYZJsmtjjEvw4Sa5TB9lzkGEHMxLwtCUx9Gxi4KYpBZH34WH1TS
# p3mng29W5J9gQLBhPlbMNli9Z3nHUSJhAEcKDkUavCRBEHr3nDaugN4pdCiiPBcq
# Wd3PF0PiHCJadI2+CDO3LhlvTohxNjZzrm2V3UyI0O3kf3a9EP+z+5ocs/Eeiu+t
# DZ+uQHCAphFBVNrUnIw5rQwQhBMCzrvncaKfwL5N2G/DXAnLFBGY84hgCtVTGh28
# uTK831EKc5ryh88Av7/Y02H7Zwh9WNuqg55z85Npu6maRkyvDyGY5WD2SSv/hbjK
# eVBPaM7cnWMH9O8YTP7FV6OxOPNnYK5DJSJTNC73z/0h/jpcJ6vDrzSPLDD0NxMA
# tmqtSwfpJFyxPfJkP70Fe1El5wSSJBHUHdPpKcRzKO+bxmFmKENEP9T7vlmzfeMy
# Fezqcl4Y/9/bozWvllXxXNDX44nDejlT2Rt8+xfM6dcErnMa
# SIG # End signature block
