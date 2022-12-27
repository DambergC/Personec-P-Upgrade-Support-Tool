function Test-DbaWindowsLogin {
    <#
    .SYNOPSIS
        Test-DbaWindowsLogin finds any logins on SQL instance that are AD logins with either disabled AD user accounts or ones that no longer exist

    .DESCRIPTION
        The purpose of this function is to find SQL Server logins that are used by active directory users that are either disabled or removed from the domain. It allows you to keep your logins accurate and up to date by removing accounts that are no longer needed.

    .PARAMETER SqlInstance
        The SQL Server instance you're checking logins on. You must have sysadmin access and server version must be SQL Server version 2000 or higher.

    .PARAMETER SqlCredential
        Login to the target instance using alternative credentials. Accepts PowerShell credentials (Get-Credential).

        Windows Authentication, SQL Server Authentication, Active Directory - Password, and Active Directory - Integrated are all supported.

        For MFA support, please use Connect-DbaInstance.

    .PARAMETER Login
        Specifies a list of logins to include in the results. Options for this list are auto-populated from the server.

    .PARAMETER ExcludeLogin
        Specifies a list of logins to exclude from the results. Options for this list are auto-populated from the server.

    .PARAMETER FilterBy
        Specifies the object types to return. By default, both Logins and Groups are returned. Valid options for this parameter are 'GroupsOnly' and 'LoginsOnly'.

    .PARAMETER IgnoreDomains
        Specifies a list of Active Directory domains to ignore. By default, all domains in the forest as well as all trusted domains are traversed.

    .PARAMETER EnableException
        By default, when something goes wrong we try to catch it, interpret it and give you a friendly warning message.
        This avoids overwhelming you with "sea of red" exceptions, but is inconvenient because it basically disables advanced scripting.
        Using this switch turns this "nice by default" feature off and enables you to catch exceptions with your own try/catch.

    .NOTES
        Tags: Login
        Author: Stephen Bennett, sqlnotesfromtheunderground.wordpress.com | Chrissy LeMaire (@cl)

        Website: https://dbatools.io
        Copyright: (c) 2018 by dbatools, licensed under MIT
        License: MIT https://opensource.org/licenses/MIT

    .LINK
        https://dbatools.io/Test-DbaWindowsLogin

    .EXAMPLE
        PS C:\> Test-DbaWindowsLogin -SqlInstance Dev01

        Tests all logins in the current Active Directory domain that are either disabled or do not exist on the SQL Server instance Dev01

    .EXAMPLE
        PS C:\> Test-DbaWindowsLogin -SqlInstance Dev01 -FilterBy GroupsOnly | Select-Object -Property *

        Tests all Active Directory groups that have logins on Dev01, and shows all information for those logins

    .EXAMPLE
        PS C:\> Test-DbaWindowsLogin -SqlInstance Dev01 -IgnoreDomains testdomain

        Tests all Domain logins excluding any that are from the testdomain

    #>
    [CmdletBinding()]
    param (
        [parameter(Mandatory, ValueFromPipeline)]
        [DbaInstanceParameter[]]$SqlInstance,
        [PSCredential]$SqlCredential,
        [object[]]$Login,
        [object[]]$ExcludeLogin,
        [ValidateSet("LoginsOnly", "GroupsOnly", "None")]
        [string]$FilterBy = "None",
        [string[]]$IgnoreDomains,
        [switch]$EnableException
    )

    begin {
        if ($IgnoreDomains) {
            $IgnoreDomainsNormalized = $IgnoreDomains.ToUpper()
            Write-Message -Message ("Excluding logins for domains " + ($IgnoreDomains -join ',')) -Level Verbose
        }

        $mappingRaw = @{
            'SCRIPT'                                 = 1
            'ACCOUNTDISABLE'                         = 2
            'HOMEDIR_REQUIRED'                       = 8
            'LOCKOUT'                                = 16
            'PASSWD_NOTREQD'                         = 32
            'PASSWD_CANT_CHANGE'                     = 64
            'ENCRYPTED_TEXT_PASSWORD_ALLOWED'        = 128
            'TEMP_DUPLICATE_ACCOUNT'                 = 256
            'NORMAL_ACCOUNT'                         = 512
            'INTERDOMAIN_TRUST_ACCOUNT'              = 2048
            'WORKSTATION_TRUST_ACCOUNT'              = 4096
            'SERVER_TRUST_ACCOUNT'                   = 8192
            'DONT_EXPIRE_PASSWD'                     = 65536
            'MNS_LOGON_ACCOUNT'                      = 131072
            'SMARTCARD_REQUIRED'                     = 262144
            'TRUSTED_FOR_DELEGATION'                 = 524288
            'NOT_DELEGATED'                          = 1048576
            'USE_DES_KEY_ONLY'                       = 2097152
            'DONT_REQUIRE_PREAUTH'                   = 4194304
            'PASSWORD_EXPIRED'                       = 8388608
            'TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION' = 16777216
            'NO_AUTH_DATA_REQUIRED'                  = 33554432
            'PARTIAL_SECRETS_ACCOUNT'                = 67108864
        }
    }
    process {
        foreach ($instance in $SqlInstance) {
            try {
                $server = Connect-DbaInstance -SqlInstance $instance -SqlCredential $SqlCredential
            } catch {
                Stop-Function -Message "Failure" -Category ConnectionError -ErrorRecord $_ -Target $instance -Continue
            }


            # we can only validate AD logins
            $allWindowsLoginsGroups = $server.Logins | Where-Object { $_.LoginType -in ('WindowsUser', 'WindowsGroup') }

            # we cannot validate local users
            $allWindowsLoginsGroups = $allWindowsLoginsGroups | Where-Object { $_.Name.StartsWith("NT ") -eq $false -and $_.Name.StartsWith($server.ComputerName) -eq $false -and $_.Name.StartsWith("BUILTIN") -eq $false }
            if ($Login) {
                $allWindowsLoginsGroups = $allWindowsLoginsGroups | Where-Object Name -In $Login
            }
            if ($ExcludeLogin) {
                $allWindowsLoginsGroups = $allWindowsLoginsGroups | Where-Object Name -NotIn $ExcludeLogin
            }
            switch ($FilterBy) {
                "LoginsOnly" {
                    Write-Message -Message "Search restricted to logins." -Level Verbose
                    $windowsLogins = $allWindowsLoginsGroups | Where-Object LoginType -eq 'WindowsUser'
                }
                "GroupsOnly" {
                    Write-Message -Message "Search restricted to groups." -Level Verbose
                    $windowsGroups = $allWindowsLoginsGroups | Where-Object LoginType -eq 'WindowsGroup'
                }
                "None" {
                    Write-Message -Message "Search both logins and groups." -Level Verbose
                    $windowsLogins = $allWindowsLoginsGroups | Where-Object LoginType -eq 'WindowsUser'
                    $windowsGroups = $allWindowsLoginsGroups | Where-Object LoginType -eq 'WindowsGroup'
                }
            }
            foreach ($login in $windowsLogins) {
                $adLogin = $login.Name
                $loginSid = $login.Sid -join ''
                $domain, $username = $adLogin.Split("\")
                if ($domain.ToUpper() -in $IgnoreDomainsNormalized) {
                    Write-Message -Message "Skipping Login $adLogin." -Level Verbose
                    continue
                }
                Write-Message -Message "Parsing Login $adLogin." -Level Verbose
                $exists = $false
                try {
                    $loginBinary = [byte[]]$login.Sid
                    $SID = New-Object Security.Principal.SecurityIdentifier($loginBinary, 0)
                    $SIDForAD = $SID.Value
                    Write-Message -Message "SID for AD is $SIDForAD" -Level Debug
                    $u = Get-DbaADObject -ADObject "$domain\$SIDForAD" -Type User -IdentityType Sid -EnableException
                    if ($null -eq $u -and $adLogin -like '*$') {
                        Write-Message -Message "Parsing Login as computer" -Level Verbose
                        $u = Get-DbaADObject -ADObject $adLogin -Type Computer -EnableException
                        $adType = 'Computer'
                    } else {
                        $adType = 'User'
                    }
                    $foundUser = $u.GetUnderlyingObject()
                    $foundSid = $foundUser.ObjectSid.Value -join ''
                    if ($foundUser) {
                        $exists = $true
                    }
                    if ($foundSid -ne $loginSid) {
                        Write-Message -Message "SID mismatch detected for $adLogin." -Level Warning
                        Write-Message -Message "SID mismatch detected for $adLogin (MSSQL: $loginSid, AD: $foundSid)." -Level Debug
                        $exists = $false
                    }
                    if ($u.SamAccountName -ne $username) {
                        Write-Message -Message "SamAccountName mismatch detected for $adLogin." -Level Warning
                        Write-Message -Message "SamAccountName mismatch detected for $adLogin (MSSQL: $username, AD: $($u.SamAccountName))." -Level Debug
                    }
                } catch {
                    Write-Message -Message "AD Searcher Error for $username." -Level Warning
                }

                $uac = $foundUser.Properties.UserAccountControl

                $additionalProps = @{
                    AccountNotDelegated               = $null
                    AllowReversiblePasswordEncryption = $null
                    CannotChangePassword              = $null
                    PasswordExpired                   = $null
                    LockedOut                         = $null
                    Enabled                           = $null
                    PasswordNeverExpires              = $null
                    PasswordNotRequired               = $null
                    SmartcardLogonRequired            = $null
                    TrustedForDelegation              = $null
                }
                if ($uac) {
                    $additionalProps = @{
                        AccountNotDelegated               = [bool]($uac.Value -band $mappingRaw['NOT_DELEGATED'])
                        AllowReversiblePasswordEncryption = [bool]($uac.Value -band $mappingRaw['ENCRYPTED_TEXT_PASSWORD_ALLOWED'])
                        CannotChangePassword              = [bool]($uac.Value -band $mappingRaw['PASSWD_CANT_CHANGE'])
                        PasswordExpired                   = [bool]($uac.Value -band $mappingRaw['PASSWORD_EXPIRED'])
                        LockedOut                         = [bool]($uac.Value -band $mappingRaw['LOCKOUT'])
                        Enabled                           = !($uac.Value -band $mappingRaw['ACCOUNTDISABLE'])
                        PasswordNeverExpires              = [bool]($uac.Value -band $mappingRaw['DONT_EXPIRE_PASSWD'])
                        PasswordNotRequired               = [bool]($uac.Value -band $mappingRaw['PASSWD_NOTREQD'])
                        SmartcardLogonRequired            = [bool]($uac.Value -band $mappingRaw['SMARTCARD_REQUIRED'])
                        TrustedForDelegation              = [bool]($uac.Value -band $mappingRaw['TRUSTED_FOR_DELEGATION'])
                        UserAccountControl                = $uac.Value
                    }
                }
                $rtn = [PSCustomObject]@{
                    Server                            = $server.DomainInstanceName
                    Domain                            = $domain
                    Login                             = $username
                    Type                              = $adType
                    Found                             = $exists
                    DisabledInSQLServer               = $login.IsDisabled
                    AccountNotDelegated               = $additionalProps.AccountNotDelegated
                    AllowReversiblePasswordEncryption = $additionalProps.AllowReversiblePasswordEncryption
                    CannotChangePassword              = $additionalProps.CannotChangePassword
                    PasswordExpired                   = $additionalProps.PasswordExpired
                    LockedOut                         = $additionalProps.LockedOut
                    Enabled                           = $additionalProps.Enabled
                    PasswordNeverExpires              = $additionalProps.PasswordNeverExpires
                    PasswordNotRequired               = $additionalProps.PasswordNotRequired
                    SmartcardLogonRequired            = $additionalProps.SmartcardLogonRequired
                    TrustedForDelegation              = $additionalProps.TrustedForDelegation
                    UserAccountControl                = $additionalProps.UserAccountControl
                }

                Select-DefaultView -InputObject $rtn -ExcludeProperty AccountNotDelegated, AllowReversiblePasswordEncryption, CannotChangePassword, PasswordNeverExpires, SmartcardLogonRequired, TrustedForDelegation, UserAccountControl

            }

            foreach ($login in $windowsGroups) {
                $adLogin = $login.Name
                $loginSid = $login.Sid -join ''
                $domain, $groupName = $adLogin.Split("\")
                if ($domain.ToUpper() -in $IgnoreDomainsNormalized) {
                    Write-Message -Message "Skipping Login $adLogin." -Level Verbose
                    continue
                }
                Write-Message -Message "Parsing Login $adLogin on $server." -Level Verbose
                $exists = $false
                try {
                    $loginBinary = [byte[]]$login.Sid
                    $SID = New-Object Security.Principal.SecurityIdentifier($loginBinary, 0)
                    $SIDForAD = $SID.Value
                    Write-Message -Message "SID for AD is $SIDForAD" -Level Debug
                    $u = Get-DbaADObject -ADObject "$domain\$SIDForAD" -Type Group -IdentityType Sid -EnableException
                    $foundUser = $u.GetUnderlyingObject()
                    $foundSid = $foundUser.objectSid.Value -join ''
                    if ($foundUser) {
                        $exists = $true
                    }
                    if ($foundSid -ne $loginSid) {
                        Write-Message -Message "SID mismatch detected for $adLogin." -Level Warning
                        Write-Message -Message "SID mismatch detected for $adLogin (MSSQL: $loginSid, AD: $foundSid)." -Level Debug
                        $exists = $false
                    }
                    if ($u.SamAccountName -ne $groupName) {
                        Write-Message -Message "SamAccountName mismatch detected for $adLogin." -Level Warning
                        Write-Message -Message "SamAccountName mismatch detected for $adLogin (MSSQL: $groupName, AD: $($u.SamAccountName))." -Level Debug
                    }
                } catch {
                    Write-Message -Message "AD Searcher Error for $groupName on $server" -Level Warning
                }
                $rtn = [PSCustomObject]@{
                    Server                            = $server.DomainInstanceName
                    Domain                            = $domain
                    Login                             = $groupName
                    Type                              = "Group"
                    Found                             = $exists
                    DisabledInSQLServer               = $login.IsDisabled
                    AccountNotDelegated               = $null
                    AllowReversiblePasswordEncryption = $null
                    CannotChangePassword              = $null
                    PasswordExpired                   = $null
                    LockedOut                         = $null
                    Enabled                           = $null
                    PasswordNeverExpires              = $null
                    PasswordNotRequired               = $null
                    SmartcardLogonRequired            = $null
                    TrustedForDelegation              = $null
                    UserAccountControl                = $null
                }

                Select-DefaultView -InputObject $rtn -ExcludeProperty AccountNotDelegated, AllowReversiblePasswordEncryption, CannotChangePassword, PasswordNeverExpires, SmartcardLogonRequired, TrustedForDelegation, UserAccountControl

            }
        }
    }
}
# SIG # Begin signature block
# MIIjYAYJKoZIhvcNAQcCoIIjUTCCI00CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCAjnqMGAz27zi36
# 8NeG6ar4ixqFgpXY4+Xu67mEhbOiJaCCHVkwggUaMIIEAqADAgECAhADBbuGIbCh
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
# BgorBgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCC7e7ay3j2zF4MO/4+AwE3//ez0
# BaWdMiAUgA0OmdYGPTANBgkqhkiG9w0BAQEFAASCAQCaSeMr/ojYayicSBtZSvhF
# fjTBOJFXAHCSGAwAAwX2I5aPsDMtqhb1iufeELAvetfj31ma6d8g1ENCPHGC/8ka
# 8QUbEgi3Je/h8AOKsVvZ8gHILneLfKtHOwWwwr2cTTTTWdhfy0DLyx+9U5ZHA0rq
# lsdvMxMZoZlhRnea15m9FSBb1Y47TNY6eOF/IlXu5PIUyAt2L0F3EBU4TxPEsiBP
# WBInmdeie9rQULd95fwMalQIX+8MwaMYE2gGdDPDp3NQEdPvdhovEF0D4UfLlGH0
# dy9vMQHTpuBvc2zEDDKruFUrr7dcJRlVC1hogIl4eE3Me2gS697dyKtV1Vs3Ioja
# oYIDIDCCAxwGCSqGSIb3DQEJBjGCAw0wggMJAgEBMHcwYzELMAkGA1UEBhMCVVMx
# FzAVBgNVBAoTDkRpZ2lDZXJ0LCBJbmMuMTswOQYDVQQDEzJEaWdpQ2VydCBUcnVz
# dGVkIEc0IFJTQTQwOTYgU0hBMjU2IFRpbWVTdGFtcGluZyBDQQIQDE1pckuU+jwq
# Sj0pB4A9WjANBglghkgBZQMEAgEFAKBpMBgGCSqGSIb3DQEJAzELBgkqhkiG9w0B
# BwEwHAYJKoZIhvcNAQkFMQ8XDTIyMTExNzA4NTc1NFowLwYJKoZIhvcNAQkEMSIE
# IKn/oNv4xHrlQPybRJg+MOlnrRXfyziUaGCs/K6lPHXtMA0GCSqGSIb3DQEBAQUA
# BIICACvPqOXnAjYTDFmlQ2t1jATU4nsXf5EMpfoxYv8cPwpXP7jxxEkt1FJRqY1o
# DxGfsv3VQuD8pXkv5FOquJ9GirhEquRtW+PE8+APpxAqokhOtYkdvO3gjP5BVsuG
# lqqM/yJQVgAtaPr3bHSeCg9/CpQBEMloE5b9WeAZClfjn1d2RBqQ9R6pqQ64IU/H
# 38Yc5OtH57OPCOwDPguI840ydvqIch89EW+Gf2wwD/xcER9ydm5qunXho8/ygvrF
# 71Mqh6aBbuPtF4Lwtv8iCDL2qCJJLJsGEiuUxl/XpkWBdOD08M709+r0RNXaV2pU
# pkIEunWaqV9bNW8wFOsOz8gnpH+sBi4u0ORaUdeiycBRkoIIFHcB/CSBm6GYUez4
# gwUh8lp/jhU1Xj58esTxW9koPPLD6/ljLX3EvvZIg+Y0QG8euW3G5e7zvc/QFt8/
# VfdmBCvxfcnuNldlgP65mOvkj2LuznPiSvEGCTUC70ObF7wEJS0myTBT+SJFgggm
# sCi0r4GPNVzJQzDCgTXRSAvZiXmciqjYtL/UDo+0IcI13LZ/jcKhwbJIpdCnj1aw
# 8svtTTklXGQUe3vxnyGUGe/0+PtVOmXOY5Z7sxIBXEra4/uDe7bThaTVM+LwBn1j
# lQf7H02S5AFPcDPKLr55UlwKHuyCr08vrpFrWMFpBQBu//vx
# SIG # End signature block
