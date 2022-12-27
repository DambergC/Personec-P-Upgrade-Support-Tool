function Set-DbaAgentServer {
    <#
    .SYNOPSIS
        Set-DbaAgentServer updates properties of a SQL Agent Server.

    .DESCRIPTION
        Set-DbaAgentServer updates properties in the SQL Server Server with parameters supplied.

    .PARAMETER SqlInstance
        The target SQL Server instance or instances. You must have sysadmin access and server version must be SQL Server version 2000 or greater.

    .PARAMETER SqlCredential
        Login to the target instance using alternative credentials. Accepts PowerShell credentials (Get-Credential).

        Windows Authentication, SQL Server Authentication, Active Directory - Password, and Active Directory - Integrated are all supported.

        For MFA support, please use Connect-DbaInstance.

    .PARAMETER InputObject
        Enables piping agent server objects

    .PARAMETER AgentLogLevel
        Specifies the agent log level.
        Allowed values 1, "Errors", 2, "Warnings", 3, "Errors, Warnings", 4, "Informational", 5, "Errors, Informational", 6, "Warnings, Informational", 7, "All"
        The text value can either be lowercase, uppercase or something in between as long as the text is correct.

    .PARAMETER AgentMailType
        Specifies the agent mail type.
        Allowed values 0, "SqlAgentMail", 1, "DatabaseMail"
        The text value can either be lowercase, uppercase or something in between as long as the text is correct.

    .PARAMETER AgentShutdownWaitTime
        The Agent Shutdown Wait Time value of the server agent. The accepted value range is between 5 and 600.

    .PARAMETER DatabaseMailProfile
        The Database Mail Profile to be used. Must exists on database mail profiles.

    .PARAMETER ErrorLogFile
        Error log file location

    .PARAMETER IdleCpuDuration
        Idle CPU Duration value to be used. The accepted value range is between 20 and 86400.

    .PARAMETER IdleCpuPercentage
        Idle CPU Percentage value to be used. The accepted value range is between 10 and 100.

    .PARAMETER CpuPolling
        Enable or Disable the Polling.
        Allowed values Enabled, Disabled

    .PARAMETER LocalHostAlias
        The value for Local Host Alias configuration

    .PARAMETER LoginTimeout
        The value for Login Timeout configuration. The accepted value range is between 5 and 45.

    .PARAMETER MaximumHistoryRows
        Indicates the Maximum job history log size (in rows). The acceptable value range is between 2 and 999999. To turn off the job history limitations use the value -1 and specify 0 for MaximumJobHistoryRows. See the example listed below.

    .PARAMETER MaximumJobHistoryRows
        Indicates the Maximum job history rows per job. The acceptable value range is between 2 and 999999. To turn off the job history limitations use the value 0 and specify -1 for MaximumHistoryRows. See the example listed below.

    .PARAMETER NetSendRecipient
        The Net send recipient value

    .PARAMETER ReplaceAlertTokens
        Enable or Disable the Token replacement property.
        Allowed values Enabled, Disabled

    .PARAMETER SaveInSentFolder
        Enable or Disable the copy of the sent messages is save in the Sent Items folder.
        Allowed values Enabled, Disabled

    .PARAMETER SqlAgentAutoStart
        Enable or Disable the SQL Agent Auto Start.
        Allowed values Enabled, Disabled

    .PARAMETER SqlAgentMailProfile
        The SQL Server Agent Mail Profile to be used. Must exists on database mail profiles.

    .PARAMETER SqlAgentRestart
        Enable or Disable the SQL Agent Restart.
        Allowed values Enabled, Disabled

    .PARAMETER SqlServerRestart
        Enable or Disable the SQL Server Restart.
        Allowed values Enabled, Disabled

    .PARAMETER WriteOemErrorLog
        Enable or Disable the Write OEM Error Log.
        Allowed values Enabled, Disabled

    .PARAMETER WhatIf
        Shows what would happen if the command were to run. No actions are actually performed.

    .PARAMETER Confirm
        Prompts you for confirmation before executing any changing operations within the command.

    .PARAMETER EnableException
        By default, when something goes wrong we try to catch it, interpret it and give you a friendly warning message.
        This avoids overwhelming you with "sea of red" exceptions, but is inconvenient because it basically disables advanced scripting.
        Using this switch turns this "nice by default" feature off and enables you to catch exceptions with your own try/catch.

    .NOTES
        Tags: Agent, Server
        Author: Claudio Silva (@claudioessilva), claudioessilva.com

        Website: https://dbatools.io
        Copyright: (c) 2018 by dbatools, licensed under MIT
        License: MIT https://opensource.org/licenses/MIT

    .LINK
        https://dbatools.io/Set-DbaAgentServer

    .EXAMPLE
        PS C:\> Set-DbaAgentServer -SqlInstance sql1 -MaximumHistoryRows 10000 -MaximumJobHistoryRows 100

        Changes the job history retention to 10000 rows with an maximum of 100 rows per job.

    .EXAMPLE
        PS C:\> Set-DbaAgentServer -SqlInstance sql1 -CpuPolling Enabled

        Enable the CPU Polling configurations.

    .EXAMPLE
        PS C:\> Set-DbaAgentServer -SqlInstance sql1, sql2, sql3 -AgentLogLevel 'Errors, Warnings'

        Set the agent log level to Errors and Warnings on multiple servers.

    .EXAMPLE
        PS C:\> Set-DbaAgentServer -SqlInstance sql1 -CpuPolling Disabled

        Disable the CPU Polling configurations.

    .EXAMPLE
        PS C:\> Set-DbaAgentServer -SqlInstance sql1 -MaximumJobHistoryRows 1000 -MaximumHistoryRows 10000

        Set the max history limitations. This is the equivalent to calling:  EXEC msdb.dbo.sp_set_sqlagent_properties @jobhistory_max_rows=10000, @jobhistory_max_rows_per_job=1000

    .EXAMPLE
        PS C:\> Set-DbaAgentServer -SqlInstance sql1 -MaximumJobHistoryRows 0 -MaximumHistoryRows -1

        Disable the max history limitations. This is the equivalent to calling:  EXEC msdb.dbo.sp_set_sqlagent_properties @jobhistory_max_rows=-1, @jobhistory_max_rows_per_job=0

    #>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = "Low")]
    param (
        [DbaInstanceParameter[]]$SqlInstance,
        [PSCredential]$SqlCredential,
        [parameter(ValueFromPipeline)]
        [Microsoft.SqlServer.Management.Smo.Agent.JobServer[]]$InputObject,
        [ValidateSet(1, "Errors", 2, "Warnings", 3, "Errors, Warnings", 4, "Informational", 5, "Errors, Informational", 6, "Warnings, Informational", 7, "All")]
        [object]$AgentLogLevel,
        [ValidateSet(0, "SqlAgentMail", 1, "DatabaseMail")]
        [object]$AgentMailType,
        [ValidateRange(5, 600)][int]$AgentShutdownWaitTime,
        [string]$DatabaseMailProfile,
        [string]$ErrorLogFile,
        [ValidateRange(20, 86400)][int]$IdleCpuDuration,
        [ValidateRange(10, 100)][int]$IdleCpuPercentage,
        [ValidateSet("Enabled", "Disabled")]
        [string]$CpuPolling,
        [string]$LocalHostAlias,
        [ValidateRange(5, 45)][int]$LoginTimeout,
        [int]$MaximumHistoryRows, # validated in the begin block
        [int]$MaximumJobHistoryRows, # validated in the begin block
        [string]$NetSendRecipient,
        [ValidateSet("Enabled", "Disabled")]
        [string]$ReplaceAlertTokens,
        [ValidateSet("Enabled", "Disabled")]
        [string]$SaveInSentFolder,
        [ValidateSet("Enabled", "Disabled")]
        [string]$SqlAgentAutoStart,
        [string]$SqlAgentMailProfile,
        [ValidateSet("Enabled", "Disabled")]
        [string]$SqlAgentRestart,
        [ValidateSet("Enabled", "Disabled")]
        [string]$SqlServerRestart,
        [ValidateSet("Enabled", "Disabled")]
        [string]$WriteOemErrorLog,
        [switch]$EnableException
    )

    begin {
        # Check of the agent mail type is of type string and set the integer value
        if (($AgentMailType -notin 0, 1) -and ($null -ne $AgentMailType)) {
            $AgentMailType = switch ($AgentMailType) { "SqlAgentMail" { 0 } "DatabaseMail" { 1 } }
        }

        # Check of the agent log level is of type string and set the integer value
        if (($AgentLogLevel -notin 0, 1) -and ($null -ne $AgentLogLevel)) {
            $AgentLogLevel = switch ($AgentLogLevel) { "Errors" { 1 } "Warnings" { 2 } "Errors, Warnings" { 3 } "Informational" { 4 } "Errors, Informational" { 5 } "Warnings, Informational" { 6 } "All" { 7 } }
        }

        if ($PSBoundParameters.ContainsKey("MaximumHistoryRows") -and ($MaximumHistoryRows -ne -1 -and $MaximumHistoryRows -notin 2..999999)) {
            Stop-Function -Message "You must specify a MaximumHistoryRows value of -1 (i.e. turn off max history) or a value between 2 and 999999. See the command description for examples."
            return
        }

        if ($PSBoundParameters.ContainsKey("MaximumJobHistoryRows") -and ($MaximumJobHistoryRows -ne 0 -and $MaximumJobHistoryRows -notin 2..999999)) {
            Stop-Function -Message "You must specify a MaximumJobHistoryRows value of 0 (i.e. turn off max history) or a value between 2 and 999999. See the command description for examples."
            return
        }
    }
    process {

        if (Test-FunctionInterrupt) { return }

        if ((-not $InputObject) -and (-not $SqlInstance)) {
            Stop-Function -Message "You must specify an Instance or pipe in results from another command" -Target $SqlInstance
            return
        }

        foreach ($instance in $SqlInstance) {
            try {
                $server = Connect-DbaInstance -SqlInstance $instance -SqlCredential $SqlCredential
            } catch {
                Stop-Function -Message "Failure" -Category ConnectionError -ErrorRecord $_ -Target $instance -Continue
            }

            $server.JobServer.Refresh()
            $InputObject += $server.JobServer
        }

        foreach ($jobServer in $InputObject) {
            $server = $jobServer.Parent

            #region job server options
            # Settings the options for the job server
            if ($AgentLogLevel) {
                Write-Message -Message "Setting Agent log level to $AgentLogLevel" -Level Verbose
                $jobServer.AgentLogLevel = $AgentLogLevel
            }

            if ($AgentMailType) {
                Write-Message -Message "Setting Agent Mail Type to $AgentMailType" -Level Verbose
                $jobServer.AgentMailType = $AgentMailType
            }

            if ($AgentShutdownWaitTime) {
                Write-Message -Message "Setting Agent Shutdown Wait Time to $AgentShutdownWaitTime" -Level Verbose
                $jobServer.AgentShutdownWaitTime = $AgentShutdownWaitTime
            }

            if ($DatabaseMailProfile) {
                if ($DatabaseMailProfile -in (Get-DbaDbMail -SqlInstance $server).Profiles.Name) {
                    Write-Message -Message "Setting Database Mail Profile to $DatabaseMailProfile" -Level Verbose
                    $jobServer.DatabaseMailProfile = $DatabaseMailProfile
                } else {
                    Write-Message -Message "Database mail profile not found on $server" -Level Warning
                }
            }

            if ($ErrorLogFile) {
                Write-Message -Message "Setting agent server ErrorLogFile to $ErrorLogFile" -Level Verbose
                $jobServer.ErrorLogFile = $ErrorLogFile
            }

            if ($IdleCpuDuration) {
                Write-Message -Message "Setting agent server IdleCpuDuration to $IdleCpuDuration" -Level Verbose
                $jobServer.IdleCpuDuration = $IdleCpuDuration
            }

            if ($IdleCpuPercentage) {
                Write-Message -Message "Setting agent server IdleCpuPercentage to $IdleCpuPercentage" -Level Verbose
                $jobServer.IdleCpuPercentage = $IdleCpuPercentage
            }

            if ($CpuPolling) {
                Write-Message -Message "Setting agent server IsCpuPollingEnabled to $IsCpuPollingEnabled" -Level Verbose
                $jobServer.IsCpuPollingEnabled = if ($CpuPolling -eq "Enabled") { $true } else { $false }
            }

            if ($LocalHostAlias) {
                Write-Message -Message "Setting agent server LocalHostAlias to $LocalHostAlias" -Level Verbose
                $jobServer.LocalHostAlias = $LocalHostAlias
            }

            if ($LoginTimeout) {
                Write-Message -Message "Setting agent server LoginTimeout to $LoginTimeout" -Level Verbose
                $jobServer.LoginTimeout = $LoginTimeout
            }

            if ($MaximumHistoryRows) {
                Write-Message -Message "Setting agent server MaximumHistoryRows to $MaximumHistoryRows" -Level Verbose
                $jobServer.MaximumHistoryRows = $MaximumHistoryRows
            }

            if ($PSBoundParameters.ContainsKey("MaximumJobHistoryRows")) {
                Write-Message -Message "Setting agent server MaximumJobHistoryRows to $MaximumJobHistoryRows" -Level Verbose
                $jobServer.MaximumJobHistoryRows = $MaximumJobHistoryRows
            }

            if ($NetSendRecipient) {
                Write-Message -Message "Setting agent server NetSendRecipient to $NetSendRecipient" -Level Verbose
                $jobServer.NetSendRecipient = $NetSendRecipient
            }

            if ($ReplaceAlertTokens) {
                Write-Message -Message "Setting agent server ReplaceAlertTokensEnabled to $ReplaceAlertTokens" -Level Verbose
                $jobServer.ReplaceAlertTokensEnabled = if ($ReplaceAlertTokens -eq "Enabled") { $true } else { $false }
            }

            if ($SaveInSentFolder) {
                Write-Message -Message "Setting agent server SaveInSentFolder to $SaveInSentFolder" -Level Verbose
                $jobServer.SaveInSentFolder = if ($SaveInSentFolder -eq "Enabled") { $true } else { $false }
            }

            if ($SqlAgentAutoStart) {
                Write-Message -Message "Setting agent server SqlAgentAutoStart to $SqlAgentAutoStart" -Level Verbose
                $jobServer.SqlAgentAutoStart = if ($SqlAgentAutoStart -eq "Enabled") { $true } else { $false }
            }

            if ($SqlAgentMailProfile) {
                Write-Message -Message "Setting agent server SqlAgentMailProfile to $SqlAgentMailProfile" -Level Verbose
                $jobServer.SqlAgentMailProfile = $SqlAgentMailProfile
            }

            if ($SqlAgentRestart) {
                Write-Message -Message "Setting agent server SqlAgentRestart to $SqlAgentRestart" -Level Verbose
                $jobServer.SqlAgentRestart = if ($SqlAgentRestart -eq "Enabled") { $true } else { $false }
            }

            if ($SqlServerRestart) {
                Write-Message -Message "Setting agent server SqlServerRestart to $SqlServerRestart" -Level Verbose
                $jobServer.SqlServerRestart = if ($SqlServerRestart -eq "Enabled") { $true } else { $false }
            }

            if ($WriteOemErrorLog) {
                Write-Message -Message "Setting agent server WriteOemErrorLog to $WriteOemErrorLog" -Level Verbose
                $jobServer.WriteOemErrorLog = if ($WriteOemErrorLog -eq "Enabled") { $true } else { $false }
            }

            #endregion server agent options

            # Execute
            if ($PSCmdlet.ShouldProcess($SqlInstance, "Changing the agent server")) {
                try {
                    Write-Message -Message "Changing the agent server" -Level Verbose

                    # Change the agent server
                    $jobServer.Alter()
                } catch {
                    Stop-Function -Message "Something went wrong changing the agent server" -ErrorRecord $_ -Target $instance -Continue
                }

                Get-DbaAgentServer -SqlInstance $server | Where-Object Name -eq $jobServer.name
            }
        }
    }
    end {
        Write-Message -Message "Finished changing agent server(s)" -Level Verbose
    }
}
# SIG # Begin signature block
# MIIjYAYJKoZIhvcNAQcCoIIjUTCCI00CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCD6R5fIkGZqAfll
# +aE8m3PW3OohaZXQ9rG2V5ppoB8+6qCCHVkwggUaMIIEAqADAgECAhADBbuGIbCh
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
# BgorBgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCCRtvj9+u9RjFbemfONFBmoNGFX
# gDh5z2+W8BRSOGutMzANBgkqhkiG9w0BAQEFAASCAQBhzzdFffqdPCcRqBu/ggjC
# 3bEoGrjjEeKdjg/k7cScRIlD7wJ1V2QUyfC1GZAeNDJxfgB67lL7xNnXzSFfpioV
# Y7nKexJl9ifyS0GvrmgIbQGDVogD8/C/1OtU0Q0sdn0ZbEfZgMoArd2JnWiwBL1X
# PBfZwjxo7rHkOeiX+ELbjjNdZo0p895guSdG1rwP+MuAToOwiIOOJVQm0QkzCVpI
# auoUk3V2JwzCDLaimQWPFx/0JOp54KR62zMV7/ZH+649y8E1dw5c1MulKRLmGZOo
# ZEIEaG7WGWo9uHPHqMU9n6D6uLjMoWgVW8dglGGKOuJF0y+77KUsfbAbp6R+DoFR
# oYIDIDCCAxwGCSqGSIb3DQEJBjGCAw0wggMJAgEBMHcwYzELMAkGA1UEBhMCVVMx
# FzAVBgNVBAoTDkRpZ2lDZXJ0LCBJbmMuMTswOQYDVQQDEzJEaWdpQ2VydCBUcnVz
# dGVkIEc0IFJTQTQwOTYgU0hBMjU2IFRpbWVTdGFtcGluZyBDQQIQDE1pckuU+jwq
# Sj0pB4A9WjANBglghkgBZQMEAgEFAKBpMBgGCSqGSIb3DQEJAzELBgkqhkiG9w0B
# BwEwHAYJKoZIhvcNAQkFMQ8XDTIyMTExNzA4NTcyOFowLwYJKoZIhvcNAQkEMSIE
# IJvmORkhQJVe1R7uSk/L/2qAc/KZqYtYvRnoHftalwlhMA0GCSqGSIb3DQEBAQUA
# BIICAAjf0KbgRuxJAXORUO1k/3peB/Uz01EyE5giyMx014V6lOg7mHuajObnZ57E
# WPA9vLK8dqtheq7xyn27Co9aELsdYTjGXU8w2P7a2oazNWnTKV3+hpuobM4HawKU
# g/YKzSE6cnSETOntKjHyyHBjHIiXpUzt8JNKK8d+4AunTgck5wgY5i/V//cjJxh6
# GI31I6HpMRbXHg3KwNFDMc0r9nQSwSOYoCuGB2vY6C9hcB9r0r5JTJi6jkcpXGfz
# V/qh8Bu31FrYQebWE6jNVjYZ/KsmEj1D2CbtImlLD9UyuAXV9LjKuMYfpVNKzw+m
# h7YeZ/6PDe223oQWrfIAzvEaSzz6hWVJ14+fSSg2z3NmDy0clbBbGQ7cFxAf8mo1
# j4lTOFMTV6ojQzQUsQ61CZ3HICaSApOzSDDP9ONNRHbk2+fmJ/JYZ4G1zSjwCJc3
# pH77DtlJ87X+mp1WKTU9DjP9NsDOcYSykLEvu//jyAOuPvQzEVNlKCwA5YiVew4b
# wB4yDJz8Ayis+mPCIczzRO0Tr4Irb/yIptIEkPW+mGmPrPfGMUguZHkqk/EBR6ez
# Pa3vRkHRvlZBUhy0LlfgoSDwOPHmRzCItccwd2gOffMyYMVFwfAW6Ddv6HvdsKZf
# ShzPKXV+WuHeYyJP+JFGnHeV7tG4Lcj6CUHfvXzyQ1sth7ba
# SIG # End signature block
