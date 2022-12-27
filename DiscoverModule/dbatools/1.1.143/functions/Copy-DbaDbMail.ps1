function Copy-DbaDbMail {
    <#
    .SYNOPSIS
        Migrates Mail Profiles, Accounts, Mail Servers and Mail Server Configs from one SQL Server to another.

    .DESCRIPTION
        By default, all mail configurations for Profiles, Accounts, Mail Servers and Configs are copied.

    .PARAMETER Source
        Source SQL Server. You must have sysadmin access and server version must be SQL Server version 2000 or higher.

    .PARAMETER SourceSqlCredential
        Login to the target instance using alternative credentials. Accepts PowerShell credentials (Get-Credential).

        Windows Authentication, SQL Server Authentication, Active Directory - Password, and Active Directory - Integrated are all supported.

        For MFA support, please use Connect-DbaInstance.

    .PARAMETER Destination
        Destination SQL Server. You must have sysadmin access and the server must be SQL Server 2000 or higher.

    .PARAMETER DestinationSqlCredential
        Login to the target instance using alternative credentials. Accepts PowerShell credentials (Get-Credential).

        Windows Authentication, SQL Server Authentication, Active Directory - Password, and Active Directory - Integrated are all supported.

        For MFA support, please use Connect-DbaInstance.

    .PARAMETER Type
        Specifies the object type to migrate. Valid options are 'ConfigurationValues', 'Profiles', 'Accounts', and 'MailServers'. When Type is specified, all categories from the selected type will be migrated.

    .PARAMETER WhatIf
        If this switch is enabled, no actions are performed but informational messages will be displayed that explain what would happen if the command were to run.

    .PARAMETER Confirm
        If this switch is enabled, you will be prompted for confirmation before executing any operations that change state.

    .PARAMETER EnableException
        By default, when something goes wrong we try to catch it, interpret it and give you a friendly warning message.
        This avoids overwhelming you with "sea of red" exceptions, but is inconvenient because it basically disables advanced scripting.
        Using this switch turns this "nice by default" feature off and enables you to catch exceptions with your own try/catch.

    .PARAMETER Force
        If this switch is enabled, existing objects on Destination with matching names from Source will be dropped.

    .NOTES
        Tags: Migration, Mail
        Author: Chrissy LeMaire (@cl), netnerds.net

        Website: https://dbatools.io
        Copyright: (c) 2018 by dbatools, licensed under MIT
        License: MIT https://opensource.org/licenses/MIT

        Requires: sysadmin access on SQL Servers

    .LINK
        https://dbatools.io/Copy-DbaDbMail

    .EXAMPLE
        PS C:\> Copy-DbaDbMail -Source sqlserver2014a -Destination sqlcluster

        Copies all database mail objects from sqlserver2014a to sqlcluster using Windows credentials. If database mail objects with the same name exist on sqlcluster, they will be skipped.

    .EXAMPLE
        PS C:\> Copy-DbaDbMail -Source sqlserver2014a -Destination sqlcluster -SourceSqlCredential $cred

        Copies all database mail objects from sqlserver2014a to sqlcluster using SQL credentials for sqlserver2014a and Windows credentials for sqlcluster.

    .EXAMPLE
        PS C:\> Copy-DbaDbMail -Source sqlserver2014a -Destination sqlcluster -WhatIf

        Shows what would happen if the command were executed.

    .EXAMPLE
        PS C:\> Copy-DbaDbMail -Source sqlserver2014a -Destination sqlcluster -EnableException

        Performs execution of function, and will throw a terminating exception if something breaks

    #>
    [cmdletbinding(DefaultParameterSetName = "Default", SupportsShouldProcess, ConfirmImpact = "Medium")]
    param (
        [parameter(Mandatory)]
        [DbaInstanceParameter]$Source,
        [parameter(Mandatory)]
        [DbaInstanceParameter[]]$Destination,
        [Parameter(ParameterSetName = 'SpecificTypes')]
        [ValidateSet('ConfigurationValues', 'Profiles', 'Accounts', 'MailServers')]
        [string[]]$Type,
        [PSCredential]$SourceSqlCredential,
        [PSCredential]$DestinationSqlCredential,
        [switch]$Force,
        [switch]$EnableException
    )
    begin {
        if ($Force) { $ConfirmPreference = 'none' }
        function Copy-DbaDbMailConfig {
            [cmdletbinding(SupportsShouldProcess)]
            param ()

            Write-Message -Message "Migrating mail server configuration values." -Level Verbose
            $copyMailConfigStatus = [pscustomobject]@{
                SourceServer      = $sourceServer.Name
                DestinationServer = $destServer.Name
                Name              = "Server Configuration"
                Type              = "Mail Configuration"
                Status            = $null
                Notes             = $null
                DateTime          = [Sqlcollaborative.Dbatools.Utility.DbaDateTime](Get-Date)
            }
            if ($pscmdlet.ShouldProcess($destinstance, "Migrating all mail server configuration values.")) {
                try {
                    $sql = $mail.ConfigurationValues.Script() | Out-String
                    $sql = $sql -replace [Regex]::Escape("'$source'"), "'$destinstance'"
                    Write-Message -Message $sql -Level Debug
                    $destServer.Query($sql) | Out-Null
                    $mail.ConfigurationValues.Refresh()
                    $copyMailConfigStatus.Status = "Successful"
                } catch {
                    $copyMailConfigStatus.Status = "Failed"
                    $copyMailConfigStatus | Select-DefaultView -Property DateTime, SourceServer, DestinationServer, Name, Type, Status, Notes -TypeName MigrationObject
                    Stop-Function -Message "Unable to migrate mail configuration." -Category InvalidOperation -InnerErrorRecord $_ -Target $destServer
                }
                $copyMailConfigStatus | Select-DefaultView -Property DateTime, SourceServer, DestinationServer, Name, Type, Status, Notes -TypeName MigrationObject
            }
        }

        function Copy-DbaDatabaseAccount {
            [cmdletbinding(SupportsShouldProcess)]
            $sourceAccounts = $sourceServer.Mail.Accounts
            $destAccounts = $destServer.Mail.Accounts

            Write-Message -Message "Migrating accounts." -Level Verbose
            foreach ($account in $sourceAccounts) {
                $accountName = $account.name
                $newAccountName = $accountName -replace [Regex]::Escape($source), $destinstance
                Write-Message -Message "Updating account name from '$accountName' to '$newAccountName'." -Level Verbose
                $copyMailAccountStatus = [pscustomobject]@{
                    SourceServer      = $sourceServer.Name
                    DestinationServer = $destServer.Name
                    Name              = $accountName
                    Type              = "Mail Account"
                    Status            = $null
                    Notes             = $null
                    DateTime          = [Sqlcollaborative.Dbatools.Utility.DbaDateTime](Get-Date)
                }

                if ($accounts.count -gt 0 -and $accounts -notcontains $newAccountName) {
                    continue
                }

                if ($destAccounts.name -contains $newAccountName) {
                    if ($force -eq $false) {
                        If ($pscmdlet.ShouldProcess($destinstance, "Account '$newAccountName' exists at destination. Use -Force to drop and migrate.")) {
                            $copyMailAccountStatus.Status = "Skipped"
                            $copyMailAccountStatus.Notes = "Already exists on destination"
                            $copyMailAccountStatus | Select-DefaultView -Property DateTime, SourceServer, DestinationServer, Name, Type, Status, Notes -TypeName MigrationObject
                            Write-Message -Message "Account $newAccountName exists at destination. Use -Force to drop and migrate." -Level Verbose
                        }
                        continue
                    }

                    If ($pscmdlet.ShouldProcess($destinstance, "Dropping account '$newAccountName' and recreating.")) {
                        try {
                            Write-Message -Message "Dropping account '$newAccountName'." -Level Verbose
                            $destServer.Mail.Accounts[$newAccountName].Drop()
                            $destServer.Mail.Accounts.Refresh()
                        } catch {
                            $copyMailAccountStatus.Status = "Failed"
                            $copyMailAccountStatus | Select-DefaultView -Property DateTime, SourceServer, DestinationServer, Name, Type, Status, Notes -TypeName MigrationObject
                            Stop-Function -Message "Issue dropping account." -Target $accountName -Category InvalidOperation -InnerErrorRecord $_ -Continue
                        }
                    }
                }

                if ($pscmdlet.ShouldProcess($destinstance, "Migrating account '$accountName'.")) {
                    try {
                        Write-Message -Message "Copying mail account '$accountName'." -Level Verbose
                        $sql = $account.Script() | Out-String
                        $sql = $sql -replace "(?<=@account_name=N'[\d\w\s']*)$sourceRegEx(?=[\d\w\s']*',)", $destinstance
                        Write-Message -Message $sql -Level Debug
                        $destServer.Query($sql) | Out-Null
                        $copyMailAccountStatus.Status = "Successful"
                    } catch {
                        $copyMailAccountStatus.Status = "Failed"
                        $copyMailAccountStatus | Select-DefaultView -Property DateTime, SourceServer, DestinationServer, Name, Type, Status, Notes -TypeName MigrationObject
                        Stop-Function -Message "Issue copying mail account." -Target $newAccountName -Category InvalidOperation -InnerErrorRecord $_
                    }
                    $copyMailAccountStatus | Select-DefaultView -Property DateTime, SourceServer, DestinationServer, Name, Type, Status, Notes -TypeName MigrationObject
                }
            }
        }

        function Copy-DbaDbMailProfile {

            $sourceProfiles = $sourceServer.Mail.Profiles
            $destProfiles = $destServer.Mail.Profiles

            Write-Message -Message "Migrating mail profiles." -Level Verbose
            foreach ($profile in $sourceProfiles) {

                $profileName = $profile.name
                $newProfileName = $profileName -replace [Regex]::Escape($source), $destinstance
                Write-Message -Message "Updating profile name from '$profileName' to '$newProfileName'." -Level Verbose
                $copyMailProfileStatus = [pscustomobject]@{
                    SourceServer      = $sourceServer.Name
                    DestinationServer = $destServer.Name
                    Name              = $profileName
                    Type              = "Mail Profile"
                    Status            = $null
                    Notes             = $null
                    DateTime          = [Sqlcollaborative.Dbatools.Utility.DbaDateTime](Get-Date)
                }

                if ($profiles.count -gt 0 -and $profiles -notcontains $newProfileName) {
                    continue
                }

                if ($destProfiles.name -contains $newProfileName) {
                    if ($force -eq $false) {
                        If ($pscmdlet.ShouldProcess($destinstance, "Profile '$newProfileName' exists at destination. Use -Force to drop and migrate.")) {
                            $copyMailProfileStatus.Status = "Skipped"
                            $copyMailProfileStatus.Notes = "Already exists on destination"
                            $copyMailProfileStatus | Select-DefaultView -Property DateTime, SourceServer, DestinationServer, Name, Type, Status, Notes -TypeName MigrationObject
                            Write-Message -Message "Profile '$newProfileName' exists at destination. Use -Force to drop and migrate." -Level Verbose
                        }
                        continue
                    }

                    If ($pscmdlet.ShouldProcess($destinstance, "Dropping profile '$newProfileName' and recreating.")) {
                        try {
                            Write-Message -Message "Dropping profile '$newProfileName'." -Level Verbose
                            $destServer.Mail.Profiles[$newProfileName].Drop()
                            $destServer.Mail.Profiles.Refresh()
                        } catch {
                            $copyMailProfileStatus.Status = "Failed"
                            $copyMailProfileStatus | Select-DefaultView -Property DateTime, SourceServer, DestinationServer, Name, Type, Status, Notes -TypeName MigrationObject
                            Stop-Function -Message "Issue dropping profile." -Target $newProfileName -Category InvalidOperation -InnerErrorRecord $_ -Continue
                        }
                    }
                }

                if ($pscmdlet.ShouldProcess($destinstance, "Migrating mail profile '$profileName'.")) {
                    try {
                        Write-Message -Message "Copying mail profile '$profileName'." -Level Verbose
                        $sql = $profile.Script() | Out-String
                        $sql = $sql -replace "(?<=@account_name=N'[\d\w\s']*)$sourceRegEx(?=[\d\w\s']*',)", $destinstance
                        $sql = $sql -replace "(?<=@profile_name=N'[\d\w\s']*)$sourceRegEx(?=[\d\w\s']*',)", $destinstance
                        Write-Message -Message $sql -Level Debug
                        $destServer.Query($sql) | Out-Null
                        $destServer.Mail.Profiles.Refresh()
                        $copyMailProfileStatus.Status = "Successful"
                    } catch {
                        $copyMailProfileStatus.Status = "Failed"
                        $copyMailProfileStatus | Select-DefaultView -Property DateTime, SourceServer, DestinationServer, Name, Type, Status, Notes -TypeName MigrationObject
                        Stop-Function -Message "Issue copying mail profile." -Target $profileName -Category InvalidOperation -InnerErrorRecord $_
                    }
                    $copyMailProfileStatus | Select-DefaultView -Property DateTime, SourceServer, DestinationServer, Name, Type, Status, Notes -TypeName MigrationObject
                }
            }
        }

        function Copy-DbaDbMailServer {
            [cmdletbinding(SupportsShouldProcess)]
            $sourceMailServers = $sourceServer.Mail.Accounts.MailServers
            $destMailServers = $destServer.Mail.Accounts.MailServers

            Write-Message -Message "Getting mail server credentials." -Level Verbose
            $sql = "SELECT credentials.name AS credential_name, sysmail_server.account_id FROM sys.credentials JOIN msdb.dbo.sysmail_server ON credentials.credential_id = sysmail_server.credential_id"
            $credentialAccounts = @($sourceServer.Query($sql))
            if ($credentialAccounts.Count -gt 0) {
                $decryptedCredentials = Get-DecryptedObject -SqlInstance $sourceServer -Type Credential | Where-Object { $_.Name -in $credentialAccounts.credential_name }
            }

            Write-Message -Message "Migrating mail servers." -Level Verbose
            foreach ($mailServer in $sourceMailServers) {
                $mailServerName = $mailServer.name
                $copyMailServerStatus = [pscustomobject]@{
                    SourceServer      = $sourceServer.Name
                    DestinationServer = $destServer.Name
                    Name              = $mailServerName
                    Type              = "Mail Server"
                    Status            = $null
                    Notes             = $null
                    DateTime          = [Sqlcollaborative.Dbatools.Utility.DbaDateTime](Get-Date)
                }
                if ($mailServers.count -gt 0 -and $mailServers -notcontains $mailServerName) {
                    continue
                }

                if ($destMailServers.name -contains $mailServerName) {
                    if ($force -eq $false) {
                        if ($pscmdlet.ShouldProcess($destinstance, "Mail server $mailServerName exists at destination. Use -Force to drop and migrate.")) {
                            $copyMailServerStatus.Status = "Skipped"
                            $copyMailServerStatus.Notes = "Already exists on destination"
                            $copyMailServerStatus | Select-DefaultView -Property DateTime, SourceServer, DestinationServer, Name, Type, Status, Notes -TypeName MigrationObject
                            Write-Message -Message "Mail server $mailServerName exists at destination. Use -Force to drop and migrate." -Level Verbose
                        }
                        continue
                    }

                    If ($pscmdlet.ShouldProcess($destinstance, "Dropping mail server $mailServerName and recreating.")) {
                        try {
                            Write-Message -Message "Dropping mail server $mailServerName." -Level Verbose
                            $destServer.Mail.Accounts.MailServers[$mailServerName].Drop()
                        } catch {
                            $copyMailServerStatus.Status = "Failed"
                            $copyMailServerStatus | Select-DefaultView -Property DateTime, SourceServer, DestinationServer, Name, Type, Status, Notes -TypeName MigrationObject
                            Stop-Function -Message "Issue dropping mail server." -Target $mailServerName -Category InvalidOperation -InnerErrorRecord $_ -Continue
                        }
                    }
                }

                if ($pscmdlet.ShouldProcess($destinstance, "Migrating account mail server $mailServerName.")) {
                    try {
                        Write-Message -Message "Copying mail server $mailServerName." -Level Verbose
                        $sql = $mailServer.Script() | Out-String
                        $sql = $sql -replace "(?<=@account_name=N'[\d\w\s']*)$sourceRegEx(?=[\d\w\s']*',)", $destinstance
                        $credentialName = ($credentialAccounts | Where-Object { $_.account_id -eq $mailServer.Parent.ID }).credential_name
                        if ($credentialName) {
                            $decryptedCred = $decryptedCredentials | Where-Object { $_.Name -eq $credentialName }
                            if ($decryptedCred) {
                                $password = $decryptedCred.Password.Replace("'", "''")
                                $sql = $sql -replace "@password=N''", "@password=N'$($password)'"
                            } else {
                                Write-Message -Level Warning -Message "Failed to get mail server password, it will need to be entered manually on the destination."
                            }
                        }
                        Write-Message -Message $sql -Level Debug
                        $destServer.Query($sql) | Out-Null
                        $copyMailServerStatus.Status = "Successful"
                    } catch {
                        $copyMailServerStatus.Status = "Failed"
                        $copyMailServerStatus | Select-DefaultView -Property DateTime, SourceServer, DestinationServer, Name, Type, Status, Notes -TypeName MigrationObject
                        Stop-Function -Message "Issue copying mail server" -Target $mailServerName -Category InvalidOperation -InnerErrorRecord $_
                    }
                    $copyMailServerStatus | Select-DefaultView -Property DateTime, SourceServer, DestinationServer, Name, Type, Status, Notes -TypeName MigrationObject
                }
            }
        }

        try {
            $sourceServer = Connect-DbaInstance -SqlInstance $Source -SqlCredential $SourceSqlCredential -MinimumVersion 9
        } catch {
            Stop-Function -Message "Failure" -Category ConnectionError -ErrorRecord $_ -Target $Source
            return
        }
        $mail = $sourceServer.mail
        $sourceRegEx = [RegEx]::Escape($source)
    }
    process {
        if (Test-FunctionInterrupt) { return }
        foreach ($destinstance in $Destination) {
            try {
                $destServer = Connect-DbaInstance -SqlInstance $destinstance -SqlCredential $DestinationSqlCredential -MinimumVersion 9
            } catch {
                Stop-Function -Message "Failure" -Category ConnectionError -ErrorRecord $_ -Target $destinstance -Continue
            }

            if ($type.Count -gt 0) {

                switch ($type) {
                    "ConfigurationValues" {
                        Copy-DbaDbMailConfig
                        $destServer.Mail.ConfigurationValues.Refresh()
                    }

                    "Profiles" {
                        Copy-DbaDbMailProfile
                        $destServer.Mail.Profiles.Refresh()
                    }

                    "Accounts" {
                        Copy-DbaDatabaseAccount
                        $destServer.Mail.Accounts.Refresh()
                    }

                    "mailServers" {
                        Copy-DbaDbMailServer
                    }
                }

                continue
            }

            if (($profiles.count + $accounts.count + $mailServers.count) -gt 0) {

                if ($profiles.count -gt 0) {
                    Copy-DbaDbMailProfile -Profiles $profiles
                    $destServer.Mail.Profiles.Refresh()
                }

                if ($accounts.count -gt 0) {
                    Copy-DbaDatabaseAccount -Accounts $accounts
                    $destServer.Mail.Accounts.Refresh()
                }

                if ($mailServers.count -gt 0) {
                    Copy-DbaDbMailServer -mailServers $mailServers
                }

                continue
            }

            Copy-DbaDbMailConfig
            $destServer.Mail.ConfigurationValues.Refresh()
            Copy-DbaDatabaseAccount
            $destServer.Mail.Accounts.Refresh()
            Copy-DbaDbMailProfile
            $destServer.Mail.Profiles.Refresh()
            Copy-DbaDbMailServer
            $copyMailConfigStatus
            $copyMailAccountStatus
            $copyMailProfileStatus
            $copyMailServerStatus
            $enableDBMailStatus

            <# ToDo: Use Get/Set-DbaSpConfigure once the dynamic parameters are replaced. #>

            if (($sourceDbMailEnabled -eq 1) -and ($destDbMailEnabled -eq 0)) {
                if ($pscmdlet.ShouldProcess($destinstance, "Enabling Database Mail")) {
                    $sourceDbMailEnabled = ($sourceServer.Configuration.DatabaseMailEnabled).ConfigValue
                    Write-Message -Message "$sourceServer DBMail configuration value: $sourceDbMailEnabled." -Level Verbose

                    $destDbMailEnabled = ($destServer.Configuration.DatabaseMailEnabled).ConfigValue
                    Write-Message -Message "$destServer DBMail configuration value: $destDbMailEnabled." -Level Verbose
                    $enableDBMailStatus = [pscustomobject]@{
                        SourceServer      = $sourceServer.name
                        DestinationServer = $destServer.name
                        Name              = "Enabled on Destination"
                        Type              = "Mail Configuration"
                        Status            = if ($destDbMailEnabled -eq 1) { "Enabled" } else { $null }
                        DateTime          = [Sqlcollaborative.Dbatools.Utility.DbaDateTime](Get-Date)
                    }
                    try {
                        Write-Message -Message "Enabling Database Mail on $destServer." -Level Verbose
                        $destServer.Configuration.DatabaseMailEnabled.ConfigValue = 1
                        $destServer.Alter()
                        $enableDBMailStatus.Status = "Successful"
                    } catch {
                        $enableDBMailStatus.Status = "Failed"
                        $enableDBMailStatus | Select-DefaultView -Property DateTime, SourceServer, DestinationServer, Name, Type, Status, Notes -TypeName MigrationObject
                        Stop-Function -Message "Cannot enable Database Mail." -Category InvalidOperation -ErrorRecord $_ -Target $destServer
                    }
                    $enableDBMailStatus | Select-DefaultView -Property DateTime, SourceServer, DestinationServer, Name, Type, Status, Notes -TypeName MigrationObject
                }
            }
        }
    }
}
# SIG # Begin signature block
# MIIjYAYJKoZIhvcNAQcCoIIjUTCCI00CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCBqKKl5nP/7d2qL
# /ddD3QwLo5S/2Gb0IAPKavTCE1FxBqCCHVkwggUaMIIEAqADAgECAhADBbuGIbCh
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
# BgorBgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCD89gRSfIjmWPf1IMtCK2szt2de
# ZEwyArFDwqhnzkj5IzANBgkqhkiG9w0BAQEFAASCAQCUPPnkYvJ8YCjaQXK56ZHV
# J2MqMs74CLsntQ6Dly3M90643kyzj3RoPkMN/+CJu1cU1D2nCbbDiH4o6/OtBXSB
# /Y+zfVH66CqRtE2PTwBGupIhr28GKjmQZ0717+e5Eg9dF10sM3NaQkWZu+ngOdDH
# Zf23Qr6WdWffO9oENz1wvPnZghzNtQ8/WfK+2Nb5KJrYo8ScQ7ctVkmPbIiYrGxv
# RAjOy/u/mi73ttwMxBXGw7hWO/ZR8+bd7zqK5Fb83PGMku5xP0S1KOIKcolowRGb
# cNLSQKltZYuRHTVya4k00gHysYGDe/6ze7SPxclNFnlAbzZARF/TB1aPZidkkpLT
# oYIDIDCCAxwGCSqGSIb3DQEJBjGCAw0wggMJAgEBMHcwYzELMAkGA1UEBhMCVVMx
# FzAVBgNVBAoTDkRpZ2lDZXJ0LCBJbmMuMTswOQYDVQQDEzJEaWdpQ2VydCBUcnVz
# dGVkIEc0IFJTQTQwOTYgU0hBMjU2IFRpbWVTdGFtcGluZyBDQQIQDE1pckuU+jwq
# Sj0pB4A9WjANBglghkgBZQMEAgEFAKBpMBgGCSqGSIb3DQEJAzELBgkqhkiG9w0B
# BwEwHAYJKoZIhvcNAQkFMQ8XDTIyMTExNzA4NTUxOFowLwYJKoZIhvcNAQkEMSIE
# IAlvarcI6vSQf7RPkv0tBWnuEvA/HP/z+rr6XAYTltu7MA0GCSqGSIb3DQEBAQUA
# BIICAHVfHEuHFT3uF4O7l+wTxJbEfCy6jTFKiN/LX8TJZi8UVBNLuoKnUK++SLP8
# cotzLmtUSA9RG0rztiYP2+FTA9tecK/rZ/ajRLJZj5B8cqLZE/HuTH1BEsGOMWJS
# S80fMNNdLxJSlF7mkoiUONVSF62zvHl24Zw0T9e7SKQ6ozN+4vZb3MZMNnwZq6GR
# Kh70M+MFqU/9XXd7jPjPta8bTcA0O9yw4Rs4b6fD+xzN6gxoKyF8K9DMFtPtbzjk
# X54bqAsDwsmi02o7LCqEakztWSy+UlD8eqa2M/nfbl7dEeJ2bciXihxkg4PzkZGQ
# B120UxNBZVoZR71NLwXJ8w0xzNUlOyoykCxpdBZ70SbxwvfwM9jeGwHjV8GjQ7WY
# ngdG7sBzVAXPN5AM3gZSMJLmlj5nR4ZqunkvFGW3gFreUVr4qojUr6CFJA3ZUygW
# K6Bz+x6ntooTwuhDss0+C3V4Sp33K74mLiFyDCWn9nxzwZw8yfDTZC3SXJuCV1BF
# Ixp7Ei2jBRTAr6weAJ7P+aWoSNFDcfa8ouQ/fJyHGqckg6tly1T8xjn3/gkXUzvH
# nCGcC4TIbKvfPWuGTmepJcG5l35DiLBBFE+K+4qEKXVzL83KRng+rG7wgKurL3Uk
# uGY7gnV/NRfaZ5OZqU6aH/5e6qP6Bw7d8geIVY7TUBxsbPgk
# SIG # End signature block
