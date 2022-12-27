function Set-DbaAgentOperator {
    <#
    .SYNOPSIS
        Updates/modifies agent operators on an instance.

    .DESCRIPTION
        Updates/modifies agent operators on an instance.

    .PARAMETER SqlInstance
        The target SQL Server instance or instances.

    .PARAMETER SqlCredential
        Login to the target instance using alternative credentials. Accepts PowerShell credentials (Get-Credential).

        Windows Authentication, SQL Server Authentication, Active Directory - Password, and Active Directory - Integrated are all supported.

        For MFA support, please use Connect-DbaInstance.

    .PARAMETER Operator
        Name of the operator in SQL Agent.

    .PARAMETER Name
        The new name of the agent operator.

    .PARAMETER EmailAddress
        The email address the SQL Agent will use to email alerts to the operator.

    .PARAMETER NetSendAddress
        The net send address the SQL Agent will use for the operator to net send alerts.

    .PARAMETER PagerAddress
        The pager email address the SQL Agent will use to send alerts to the operator.

    .PARAMETER PagerDay
        Defines what days the pager portion of the operator will be used. The default is 'Everyday'. Valid parameters
        are 'EveryDay', 'Weekdays', 'Weekend', 'Sunday', 'Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', and
        'Saturday'.

    .PARAMETER SaturdayStartTime
        This a string that takes the Saturday Pager Start Time.

    .PARAMETER SaturdayEndTime
        This a string that takes the Saturday Pager End Time.

    .PARAMETER SundayStartTime
        This a string that takes the Sunday Pager Start Time.

    .PARAMETER SundayEndTime
        This a string that takes the Sunday Pager End Time.

    .PARAMETER WeekdayStartTime
        This a string that takes the Weekdays Pager Start Time.

    .PARAMETER WeekdayEndTime
        This a string that takes the Weekdays Pager End Time.

    .PARAMETER IsFailsafeOperator
        If this switch is enabled, this operator will be your failsafe operator and replace the one that existed before.

    .PARAMETER FailsafeNotificationMethod
        Defines the notification method(s) for the failsafe operator. The default is 'NotifyEmail'.
        Valid parameter values are 'None', 'NotifyEmail', 'Pager', 'NetSend', 'NotifyAll'.
        Values 'NotifyEmail', 'Pager', 'NetSend' can be specified in any combination.
        Values 'None' and 'NotifyAll' cannot be specified in conjunction with any other value.

    .PARAMETER WhatIf
        Shows what would happen if the command were to run. No actions are actually performed.

    .PARAMETER Confirm
        Prompts you for confirmation before executing any changing operations within the command.

    .PARAMETER InputObject
        SMO Server Objects (pipeline input from Connect-DbaInstance)

    .PARAMETER EnableException
        By default, when something goes wrong we try to catch it, interpret it and give you a friendly warning message.
        This avoids overwhelming you with "sea of red" exceptions, but is inconvenient because it basically disables advanced scripting.
        Using this switch turns this "nice by default" feature off and enables you to catch exceptions with your own try/catch.

    .NOTES
        Tags: Agent, Operator
        Author: Tracy Boggiano (@TracyBoggiano), databasesuperhero.com

        Website: https://dbatools.io
        Copyright: (c) 2021 by dbatools, licensed under MIT
        License: MIT https://opensource.org/licenses/MIT

    .LINK
        https://dbatools.io/Set-DbaAgentOperator

    .EXAMPLE
        PS:\> Set-DbaAgentOperator -SqlInstance sql01 -Operator DBA -EmailAddress operator@operator.com -PagerDay Everyday

        This sets the operator named DBA with the above email address with default values to alerts everyday for all hours of the day.

    .EXAMPLE
        PS:\> Set-DbaAgentOperator -SqlInstance sql01 -Operator DBA -EmailAddress operator@operator.com -NetSendAddress dbauser1 -PagerAddress dbauser1@pager.dbatools.io -PagerDay Everyday -SaturdayStartTime 070000 -SaturdayEndTime 180000 -SundayStartTime 080000 -SundayEndTime 170000 -WeekdayStartTime 060000 -WeekdayEndTime 190000

        Creates a new operator named DBA on the sql01 instance with email address operator@operator.com, net send address of dbauser1, pager address of dbauser1@pager.dbatools.io, page day as every day, Saturday start time of 7am, Saturday end time of 6pm, Sunday start time of 8am, Sunday end time of 5pm, Weekday start time of 6am, and Weekday end time of 7pm.
    #>
    [CmdletBinding(DefaultParameterSetName = "Default", SupportsShouldProcess, ConfirmImpact = "Medium")]
    param (
        [DbaInstanceParameter[]]$SqlInstance,
        [PSCredential]$SqlCredential,
        [string[]]$Operator,
        [string]$Name,
        [string]$EmailAddress,
        [string]$NetSendAddress,
        [string]$PagerAddress,
        [ValidateSet('EveryDay', 'Weekdays', 'Weekend', 'Sunday', 'Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday')]
        [string]$PagerDay,
        [string]$SaturdayStartTime,
        [string]$SaturdayEndTime,
        [string]$SundayStartTime,
        [string]$SundayEndTime,
        [string]$WeekdayStartTime,
        [string]$WeekdayEndTime,
        [switch]$IsFailsafeOperator,
        [ValidateSet('None', 'NotifyEmail', 'Pager', 'NetSend', 'NotifyAll')]
        [string[]]$FailsafeNotificationMethod = 'NotifyEmail',
        [parameter(ValueFromPipeline)]
        [Microsoft.SqlServer.Management.Smo.Agent.Operator[]]$InputObject,
        [switch]$EnableException
    )
    process {
        if (-not $PSBoundParameters.EmailAddress -and -not $PSBoundParameters.NetSendAddress -and -not $PSBoundParameters.PagerAddress) {
            Stop-Function -Message "You must specify either an EmailAddress, NetSendAddress, or a PagerAddress to be able to create an operator."
            return
        }

        if (-not $PSBoundParameters.InputObject -and -not $PSBoundParameters.Operator) {
            Stop-Function -Message "You must specify either operator or pipe in a list of operators"
            return
        }

        [int]$Interval = 0

        # Loop through the array
        foreach ($Item in $PagerDay) {
            switch ($Item) {
                "Sunday" { $Interval += 1 }
                "Monday" { $Interval += 2 }
                "Tuesday" { $Interval += 4 }
                "Wednesday" { $Interval += 8 }
                "Thursday" { $Interval += 16 }
                "Friday" { $Interval += 32 }
                "Saturday" { $Interval += 64 }
                "Weekdays" { $Interval = 62 }
                "Weekend" { $Interval = 65 }
                "EveryDay" { $Interval = 127 }
                1 { $Interval += 1 }
                2 { $Interval += 2 }
                4 { $Interval += 4 }
                8 { $Interval += 8 }
                16 { $Interval += 16 }
                32 { $Interval += 32 }
                64 { $Interval += 64 }
                62 { $Interval = 62 }
                65 { $Interval = 65 }
                127 { $Interval = 127 }
                default { $Interval = 0 }
            }
        }

        $RegexTime = '^(?:(?:([01]?\d|2[0-3]))?([0-5]?\d))?([0-5]?\d)$'

        if ($PagerDay -in ('Everyday', 'Saturday', 'Weekends')) {
            # Check the start time
            if (-not $SaturdayStartTime) {
                $SaturdayStartTime = '000000'
                Write-Message -Message "Saturday Start time was not set. Setting it to $SaturdayStartTime" -Level Verbose
            } elseif ($SaturdayStartTime -notmatch $RegexTime) {
                Stop-Function -Message "Start time $SaturdayStartTime needs to match between '000000' and '235959'"
                return
            }

            # Check the end time
            if (-not $SaturdayEndTime) {
                $SaturdayEndTime = '235959'
                Write-Message -Message "Saturday End time was not set. Setting it to $SaturdayEndTime" -Level Verbose
            } elseif ($SaturdayEndTime -notmatch $RegexTime) {
                Stop-Function -Message "End time $SaturdayEndTime needs to match between '000000' and '235959'"
                return
            }
        }

        if ($PagerDay -in ('Everyday', 'Sunday', 'Weekends')) {
            # Check the start time
            if (-not $SundayStartTime) {
                $SundayStartTime = '000000'
                Write-Message -Message "Sunday Start time was not set. Setting it to $SundayStartTime" -Level Verbose
            } elseif ($SundayStartTime -notmatch $RegexTime) {
                Stop-Function -Message "Start time $SundayStartTime needs to match between '000000' and '235959'"
                return
            }

            # Check the end time
            if (-not $SundayEndTime) {
                $SundayEndTime = '235959'
                Write-Message -Message "Sunday End time was not set. Setting it to $SundayEndTime" -Level Verbose
            } elseif ($SundayEndTime -notmatch $RegexTime) {
                Stop-Function -Message "Sunday End time $SundayEndTime needs to match between '000000' and '235959'"
                return
            }
        }

        if ($PagerDay -in ('Everyday', 'Weekdays', 'Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday')) {
            # Check the start time
            if (-not $WeekdayStartTime) {
                $WeekdayStartTime = '000000'
                Write-Message -Message "Weekday Start time was not set. Setting it to $WeekdayStartTime" -Level Verbose
            } elseif ($WeekdayStartTime -notmatch $RegexTime) {
                Stop-Function -Message "Weekday Start time $WeekdayStartTime needs to match between '000000' and '235959'"
                return
            }

            # Check the end time
            if (-not $WeekdayEndTime) {
                $WeekdayEndTime = '235959'
                Write-Message -Message "Weekday End time was not set. Setting it to $WeekdayEndTime" -Level Verbose
            } elseif ($WeekdayEndTime -notmatch $RegexTime) {
                Stop-Function -Message "Weekday End time $WeekdayEndTime needs to match between '000000' and '235959'"
                return
            }
        }

        if ($IsFailsafeOperator -and ($FailsafeNotificationMethod.Count -gt 1 -and ($FailsafeNotificationMethod.Contains('None') -or $FailsafeNotificationMethod.Contains('NotifyAll')))) {
            Stop-Function -Message "The failsafe operator notification methods 'None' and 'NotifyAll' cannot be specified in conjunction with any other notification method."
            return
        } else {

            [int]$failsafeNotificationMethodEnumerated = 0

            if ($FailsafeNotificationMethod.Contains('NotifyAll')) {
                $failsafeNotificationMethodEnumerated += 7
            } else {

                if ($FailsafeNotificationMethod.Contains('NotifyEmail')) {
                    $failsafeNotificationMethodEnumerated += 1
                }

                if ($FailsafeNotificationMethod.Contains('Pager')) {
                    $failsafeNotificationMethodEnumerated += 2
                }

                if ($FailsafeNotificationMethod.Contains('NetSend')) {
                    $failsafeNotificationMethodEnumerated += 4
                }
            }

        }

        #Format times
        if ($SaturdayStartTime) {
            $SaturdayStartTime = $SaturdayStartTime.Insert(4, ':').Insert(2, ':')
        }
        if ($SaturdayEndTime) {
            $SaturdayEndTime = $SaturdayEndTime.Insert(4, ':').Insert(2, ':')
        }

        if ($SundayStartTime) {
            $SundayStartTime = $SundayStartTime.Insert(4, ':').Insert(2, ':')
        }
        if ($SundayEndTime) {
            $SundayEndTime = $SundayEndTime.Insert(4, ':').Insert(2, ':')
        }

        if ($WeekdayStartTime) {
            $WeekdayStartTime = $WeekdayStartTime.Insert(4, ':').Insert(2, ':')
        }
        if ($WeekdayEndTime) {
            $WeekdayEndTime = $WeekdayEndTime.Insert(4, ':').Insert(2, ':')
        }

        if ($SqlInstance) {
            try {
                $InputObject += Get-DbaAgentOperator -SqlInstance $SqlInstance -SqlCredential $SqlCredential -Operator $Operator -EnableException
            } catch {
                Stop-Function -Message "Failed" -Category ConnectionError -ErrorRecord $_ -Target $instance -Continue
            }
        }

        foreach ($op in $InputObject) {
            $server = $op | Get-ConnectionParent
            try {
                if ($Name) {
                    if ($Pscmdlet.ShouldProcess($server, "Updating Operator $($op.Name) Name to $Name")) {
                        # instead of using .Rename(), we will execute a sql script to avoid enumeration problems when piping
                        $sql = "EXEC msdb.dbo.sp_update_operator @name=N'$($op.Name)', @new_name=N'$Name'"
                        try {
                            Invoke-DbaQuery -SqlInstance $server -Query "$sql" -EnableException
                        } catch {
                            Stop-Function -Message "Failed on $($server.name)" -ErrorRecord $_ -Target $server -Continue
                        }
                        $server.JobServer.Operators.Refresh()
                        $op = Get-DbaAgentOperator -SqlInstance $server -Operator $Name
                    }
                }

                if ($EmailAddress) {
                    if ($Pscmdlet.ShouldProcess($server, "Updating Operator $($op.Name) EmailAddress to $EmailAddress")) {
                        $op.EmailAddress = $EmailAddress
                    }
                }

                if ($NetSendAddress) {
                    if ($Pscmdlet.ShouldProcess($server, "Updating Operator $($op.Name) NetSendAddress to $NetSendAddress")) {
                        $op.NetSendAddress = $NetSendAddress
                    }
                }

                if ($PagerAddress) {
                    if ($Pscmdlet.ShouldProcess($server, "Updating Operator $($op.Name) PagerAddress to $PagerAddress")) {
                        $op.PagerAddress = $PagerAddress
                    }
                }

                if ($Interval) {
                    if ($Pscmdlet.ShouldProcess($server, "Updating Operator $($op.Name) PagerDays to $Interval")) {
                        $op.PagerDays = $Interval
                    }
                }

                if ($SaturdayStartTime) {
                    if ($Pscmdlet.ShouldProcess($server, "Updating Operator $($op.Name) SaturdayPagerStartTime to $SaturdayStartTime")) {
                        $op.SaturdayPagerStartTime = $SaturdayStartTime
                    }
                }

                if ($SaturdayEndTime) {
                    if ($Pscmdlet.ShouldProcess($server, "Updating Operator $($op.Name) SaturdayPagerEndTime to $SaturdayEndTime")) {
                        $op.SaturdayPagerEndTime = $SaturdayEndTime
                    }
                }

                if ($SundayStartTime) {
                    if ($Pscmdlet.ShouldProcess($server, "Updating Operator $($op.Name) SundayPagerStartTime to $SundayStartTime")) {
                        $op.SundayPagerStartTime = $SundayStartTime
                    }
                }

                if ($SundayEndTime) {
                    if ($Pscmdlet.ShouldProcess($server, "Updating Operator $($op.Name) SundayPagerEndTime to $SundayEndTime")) {
                        $op.SundayPagerEndTime = $SundayEndTime
                    }
                }

                if ($WeekdayStartTime) {
                    if ($Pscmdlet.ShouldProcess($server, "Updating Operator $($op.Name) WeekdayPagerStartTime to $WeekdayStartTime")) {
                        $op.WeekdayPagerStartTime = $WeekdayStartTime
                    }
                }

                if ($WeekdayEndTime) {
                    if ($Pscmdlet.ShouldProcess($server, "Updating Operator $($op.Name) WeekdayPagerEndTime to $WeekdayEndTime")) {
                        $op.WeekdayPagerEndTime = $WeekdayEndTime
                    }
                }

                if ($IsFailsafeOperator) {
                    if ($Pscmdlet.ShouldProcess($server, "Updating FailSafe Operator to $operator")) {
                        $server.JobServer.AlertSystem.FailSafeOperator = $Operator
                        $server.JobServer.AlertSystem.NotificationMethod = $failsafeNotificationMethodEnumerated
                        $server.JobServer.AlertSystem.Alter()
                    }
                }

                if ($Pscmdlet.ShouldProcess($server, "Committing changes for Operator $($op.Name)")) {
                    $op.Alter()
                    $op
                }
            } catch {
                Stop-Function -Message "Issue creating operator." -Category InvalidOperation -ErrorRecord $_ -Target $server
            }
        }
    }
}
# SIG # Begin signature block
# MIIjYAYJKoZIhvcNAQcCoIIjUTCCI00CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCDyUVwZCTOuzXSs
# 2iU7KdrGv6j8rbQav/BmMyXUlJ6qiKCCHVkwggUaMIIEAqADAgECAhADBbuGIbCh
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
# BgorBgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCD8646mZEOk/S/Fk6h76NMWyxPM
# ZT7lZjrUJakrWRkM9TANBgkqhkiG9w0BAQEFAASCAQAogVoaNcuEH4dFMvf7WwCM
# K+fEVgWpiMtBWHNLonjoA11JgV4I2j/t3RrVHYaN5WqMJckopjtGzkomP771jPI/
# kN1TGeYtF/VzFq4S+Kw4SQM3xs6daH8Du9bgvkve6VHLBw/R7QmpJLljT6+m8/jq
# SfDMyo9E6sCdPmC3XRxbBEhREra6nTSH7DLW4ibLo3URFKOCXcI9wpEsACrC9Qix
# tz1qgk5PbsxaFPsX/hKhBKto9gHgMUex027UdQI+MxgsjL+2GfpqXyMy465Qfdac
# 9xmffIJbu2A/In2VvRT8fz1ZUewI/CNYAdHYxy8bnQPeUbGpBOzPv5vZtZjRmel7
# oYIDIDCCAxwGCSqGSIb3DQEJBjGCAw0wggMJAgEBMHcwYzELMAkGA1UEBhMCVVMx
# FzAVBgNVBAoTDkRpZ2lDZXJ0LCBJbmMuMTswOQYDVQQDEzJEaWdpQ2VydCBUcnVz
# dGVkIEc0IFJTQTQwOTYgU0hBMjU2IFRpbWVTdGFtcGluZyBDQQIQDE1pckuU+jwq
# Sj0pB4A9WjANBglghkgBZQMEAgEFAKBpMBgGCSqGSIb3DQEJAzELBgkqhkiG9w0B
# BwEwHAYJKoZIhvcNAQkFMQ8XDTIyMTExNzA4NTcyOFowLwYJKoZIhvcNAQkEMSIE
# IGdRq45vYRoOFtX80GloUm9uvQqQkGuhC2ZutWNfHxUZMA0GCSqGSIb3DQEBAQUA
# BIICAB9yROAg4f31uIf4JUreyA9p+GeRRkDVrOPEWusF2IlHEqOIw37c1XD3hVBQ
# aYcHP2rS3CJ1LEoqNjfcm8Wm6/a4aWN/3k8IzRzzGC9fJMZdy+qiLus96UG/+yrC
# r3l9sJ+NOxdYmjYKbhDgFKU5KyMhNf/TEz09f3qaui4DWP5xtAxAuZ/w6rDgdudk
# 549RG6OGzX7ohEdmFal1w159DTO9O/pTJAcy9e004sIrPiBKrduhBFeGJikHQOgf
# Z747eHxLAjhEvHr23m6hgCkDvVMASNqsiMxAUcWZ+dHQd5OTAXYeyiuM96EPwjvl
# ltI7HmADt5Fm8KLl/HuCMeL/xSBYQSzc+DK3DqLo5ft070lIVhhyleuB9kRUQGka
# D/mDTjGyKnadIhDl/QvL8r5UUzLB/sxPNgSJPUyz4IOzIE/LbIGUAFASwSaal7ah
# DgPPUWVDb2eXgNSjd8iVzvbnMTrf2RVrzC6mnqT/ePdtbiRah5KBtaGp7La5IQOn
# MvE1Su3zwARn1C1Ort8l0q1EFrPtOGMIsZnrOvARr99+P8+Lc3ghDf2AFXmM2aE4
# bKuYyDQYHaZ+uMA5dKM2LDpkk5u6+yYo195OpuJwgFcDcN3JSmZ7EKw+S0AoYatN
# 5ifJF2XN2owpgCvY/dVgW83VfuTWuli62jlZXoIpbnR0WfFL
# SIG # End signature block
