function New-DbaAgentJob {
    <#
    .SYNOPSIS
        New-DbaAgentJob creates a new job

    .DESCRIPTION
        New-DbaAgentJob makes is possible to create a job in the SQL Server Agent.
        It returns an array of the job(s) created

    .PARAMETER SqlInstance
        The target SQL Server instance or instances. You must have sysadmin access and server version must be SQL Server version 2000 or greater.

    .PARAMETER SqlCredential
        Login to the target instance using alternative credentials. Accepts PowerShell credentials (Get-Credential).

        Windows Authentication, SQL Server Authentication, Active Directory - Password, and Active Directory - Integrated are all supported.

        For MFA support, please use Connect-DbaInstance.

    .PARAMETER Job
        The name of the job. The name must be unique and cannot contain the percent (%) character.

    .PARAMETER Schedule
        Schedule to attach to job. This can be more than one schedule.

    .PARAMETER ScheduleId
        Schedule ID to attach to job. This can be more than one schedule ID.

    .PARAMETER Disabled
        Sets the status of the job to disabled. By default a job is enabled.

    .PARAMETER Description
        The description of the job.

    .PARAMETER StartStepId
        The identification number of the first step to execute for the job.

    .PARAMETER Category
        The category of the job.

    .PARAMETER OwnerLogin
        The name of the login that owns the job.

    .PARAMETER EventLogLevel
        Specifies when to place an entry in the Microsoft Windows application log for this job.
        Allowed values 0, "Never", 1, "OnSuccess", 2, "OnFailure", 3, "Always"
        The text value can either be lowercase, uppercase or something in between as long as the text is correct.

    .PARAMETER EmailLevel
        Specifies when to send an e-mail upon the completion of this job.
        Allowed values 0, "Never", 1, "OnSuccess", 2, "OnFailure", 3, "Always"
        The text value can either be lowercase, uppercase or something in between as long as the text is correct.

    .PARAMETER NetsendLevel
        Specifies when to send a network message upon the completion of this job.
        Allowed values 0, "Never", 1, "OnSuccess", 2, "OnFailure", 3, "Always"
        The text value can either be lowercase, uppercase or something in between as long as the text is correct.

    .PARAMETER PageLevel
        Specifies when to send a page upon the completion of this job.
        Allowed values 0, "Never", 1, "OnSuccess", 2, "OnFailure", 3, "Always"
        The text value can either be lowercase, uppercase or something in between as long as the text is correct.

    .PARAMETER EmailOperator
        The e-mail name of the operator to whom the e-mail is sent when EmailLevel is reached.

    .PARAMETER NetsendOperator
        The name of the operator to whom the network message is sent.

    .PARAMETER PageOperator
        The name of the operator to whom a page is sent.

    .PARAMETER DeleteLevel
        Specifies when to delete the job.
        Allowed values 0, "Never", 1, "OnSuccess", 2, "OnFailure", 3, "Always"
        The text value can either be lowercase, uppercase or something in between as long as the text is correct.

    .PARAMETER Force
        The force parameter will ignore some errors in the parameters and assume defaults.

    .PARAMETER WhatIf
        Shows what would happen if the command were to run. No actions are actually performed.

    .PARAMETER Confirm
        Prompts you for confirmation before executing any changing operations within the command.

    .PARAMETER EnableException
        By default, when something goes wrong we try to catch it, interpret it and give you a friendly warning message.
        This avoids overwhelming you with "sea of red" exceptions, but is inconvenient because it basically disables advanced scripting.
        Using this switch turns this "nice by default" feature off and enables you to catch exceptions with your own try/catch.

    .NOTES
        Tags: Agent, Job, JobStep
        Author: Sander Stad (@sqlstad), sqlstad.nl

        Website: https://dbatools.io
        Copyright: (c) 2018 by dbatools, licensed under MIT
        License: MIT https://opensource.org/licenses/MIT

    .LINK
        https://dbatools.io/New-DbaAgentJob

    .EXAMPLE
        PS C:\> New-DbaAgentJob -SqlInstance sql1 -Job 'Job One' -Description 'Just another job'

        Creates a job with the name "Job1" and a small description

    .EXAMPLE
        PS C:\> New-DbaAgentJob -SqlInstance sql1 -Job 'Job One' -Disabled

        Creates the job but sets it to disabled

    .EXAMPLE
        PS C:\> New-DbaAgentJob -SqlInstance sql1 -Job 'Job One' -EventLogLevel OnSuccess

        Creates the job and sets the notification to write to the Windows Application event log on success

    .EXAMPLE
        PS C:\> New-DbaAgentJob -SqlInstance SSTAD-PC -Job 'Job One' -EmailLevel OnFailure -EmailOperator dba

        Creates the job and sets the notification to send an e-mail to the e-mail operator

    .EXAMPLE
        PS C:\> New-DbaAgentJob -SqlInstance sql1 -Job 'Job One' -Description 'Just another job' -Whatif

        Doesn't create the job but shows what would happen.

    .EXAMPLE
        PS C:\> New-DbaAgentJob -SqlInstance sql1, sql2, sql3 -Job 'Job One'

        Creates a job with the name "Job One" on multiple servers

    .EXAMPLE
        PS C:\> "sql1", "sql2", "sql3" | New-DbaAgentJob -Job 'Job One'

        Creates a job with the name "Job One" on multiple servers using the pipe line

    #>

    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = "Low")]
    param (
        [parameter(Mandatory, ValueFromPipeline)]
        [DbaInstanceParameter[]]$SqlInstance,
        [PSCredential]$SqlCredential,
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Job,
        [object[]]$Schedule,
        [int[]]$ScheduleId,
        [switch]$Disabled,
        [string]$Description,
        [int]$StartStepId,
        [string]$Category,
        [string]$OwnerLogin,
        [ValidateSet(0, "Never", 1, "OnSuccess", 2, "OnFailure", 3, "Always")]
        [object]$EventLogLevel,
        [ValidateSet(0, "Never", 1, "OnSuccess", 2, "OnFailure", 3, "Always")]
        [object]$EmailLevel,
        [ValidateSet(0, "Never", 1, "OnSuccess", 2, "OnFailure", 3, "Always")]
        [Parameter()]
        [ValidateSet(0, "Never", 1, "OnSuccess", 2, "OnFailure", 3, "Always")]
        [object]$PageLevel,
        [string]$EmailOperator,
        [string]$NetsendOperator,
        [string]$PageOperator,
        [ValidateSet(0, "Never", 1, "OnSuccess", 2, "OnFailure", 3, "Always")]
        [object]$DeleteLevel,
        [switch]$Force,
        [switch]$EnableException
    )

    begin {
        if ($Force) { $ConfirmPreference = 'none' }

        # Check of the event log level is of type string and set the integer value
        if ($EventLogLevel -notin 1, 2, 3) {
            $EventLogLevel = switch ($EventLogLevel) {
                "Never" { 0 } "OnSuccess" { 1 } "OnFailure" { 2 } "Always" { 3 }
                default { 0 }
            }
        }

        # Check of the email level is of type string and set the integer value
        if ($EmailLevel -notin 1, 2, 3) {
            $EmailLevel = switch ($EmailLevel) {
                "Never" { 0 } "OnSuccess" { 1 } "OnFailure" { 2 } "Always" { 3 }
                default { 0 }
            }
        }

        # Check of the net send level is of type string and set the integer value
        if ($NetsendLevel -notin 1, 2, 3) {
            $NetsendLevel = switch ($NetsendLevel) {
                "Never" { 0 } "OnSuccess" { 1 } "OnFailure" { 2 } "Always" { 3 }
                default { 0 }
            }
        }

        # Check of the page level is of type string and set the integer value
        if ($PageLevel -notin 1, 2, 3) {
            $PageLevel = switch ($PageLevel) {
                "Never" { 0 } "OnSuccess" { 1 } "OnFailure" { 2 } "Always" { 3 }
                default { 0 }
            }
        }

        # Check of the delete level is of type string and set the integer value
        if ($DeleteLevel -notin 1, 2, 3) {
            $DeleteLevel = switch ($DeleteLevel) {
                "Never" { 0 } "OnSuccess" { 1 } "OnFailure" { 2 } "Always" { 3 }
                default { 0 }
            }
        }

        # Check the e-mail operator name
        if (($EmailLevel -ge 1) -and (-not $EmailOperator)) {
            Stop-Function -Message "Please set the e-mail operator when the e-mail level parameter is set." -Target $SqlInstance
            return
        }

        # Check the e-mail operator name
        if (($NetsendLevel -ge 1) -and (-not $NetsendOperator)) {
            Stop-Function -Message "Please set the netsend operator when the netsend level parameter is set." -Target $SqlInstance
            return
        }

        # Check the e-mail operator name
        if (($PageLevel -ge 1) -and (-not $PageOperator)) {
            Stop-Function -Message "Please set the page operator when the page level parameter is set." -Target $SqlInstance
            return
        }
    }

    process {

        if (Test-FunctionInterrupt) { return }

        foreach ($instance in $SqlInstance) {
            try {
                $server = Connect-DbaInstance -SqlInstance $instance -SqlCredential $SqlCredential
            } catch {
                Stop-Function -Message "Failure" -Category ConnectionError -ErrorRecord $_ -Target $instance -Continue
            }

            # Check if the job already exists
            if (-not $Force -and ($server.JobServer.Jobs.Name -contains $Job)) {
                Stop-Function -Message "Job $Job already exists on $instance" -Target $instance -Continue
            } elseif ($Force -and ($server.JobServer.Jobs.Name -contains $Job)) {
                Write-Message -Message "Job $Job already exists on $instance. Removing.." -Level Verbose

                if ($PSCmdlet.ShouldProcess($instance, "Removing the job $Job on $instance")) {
                    try {
                        Remove-DbaAgentJob -SqlInstance $server -Job $Job -EnableException -Confirm:$false
                        $server.JobServer.Refresh()
                    } catch {
                        Stop-Function -Message "Couldn't remove job $Job from $instance" -Target $instance -Continue -ErrorRecord $_
                    }
                }

            }

            if ($PSCmdlet.ShouldProcess($instance, "Creating the job on $instance")) {
                # Create the job object
                try {
                    $currentjob = New-Object Microsoft.SqlServer.Management.Smo.Agent.Job($server.JobServer, $Job)
                } catch {
                    Stop-Function -Message "Something went wrong creating the job. `n" -Target $Job -Continue -ErrorRecord $_
                }

                #region job options
                # Settings the options for the job
                if ($Disabled) {
                    Write-Message -Message "Setting job to disabled" -Level Verbose
                    $currentjob.IsEnabled = $false
                } else {
                    Write-Message -Message "Setting job to enabled" -Level Verbose
                    $currentjob.IsEnabled = $true
                }

                if ($Description.Length -ge 1) {
                    Write-Message -Message "Setting job description" -Level Verbose
                    $currentjob.Description = $Description
                }

                if ($StartStepId -ge 1) {
                    Write-Message -Message "Setting job start step id" -Level Verbose
                    $currentjob.StartStepID = $StartStepId
                }

                if ($Category.Length -ge 1) {
                    # Check if the job category exists
                    if ($Category -notin $server.JobServer.JobCategories.Name) {
                        if ($Force) {
                            if ($PSCmdlet.ShouldProcess($instance, "Creating job category on $instance")) {
                                try {
                                    # Create the category
                                    $server.JobServer.Refresh()
                                    New-DbaAgentJobCategory -SqlInstance $server -Category $Category
                                } catch {
                                    Stop-Function -Message "Couldn't create job category $Category from $instance" -Target $instance -Continue -ErrorRecord $_
                                }
                            }
                        } else {
                            Stop-Function -Message "Job category $Category doesn't exist on $instance. Use -Force to create it." -Target $instance
                            return
                        }
                    } else {
                        Write-Message -Message "Setting job category" -Level Verbose
                        $currentjob.Category = $Category
                    }
                }

                if ($OwnerLogin.Length -ge 1) {
                    # Check if the login name is present on the instance
                    if ($server.Logins.Name -contains $OwnerLogin) {
                        Write-Message -Message "Setting job owner login name to $OwnerLogin" -Level Verbose
                        $currentjob.OwnerLoginName = $OwnerLogin
                    } else {
                        Stop-Function -Message "The owner $OwnerLogin does not exist on instance $instance" -Target $Job -Continue
                    }
                }

                if ($EventLogLevel -ge 0) {
                    Write-Message -Message "Setting job event log level" -Level Verbose
                    $currentjob.EventLogLevel = $EventLogLevel
                }

                if ($EmailOperator) {
                    if ($EmailLevel -ge 1) {
                        # Check if the operator name is present
                        if ($server.JobServer.Operators.Name -contains $EmailOperator) {
                            Write-Message -Message "Setting job e-mail level" -Level Verbose
                            $currentjob.EmailLevel = $EmailLevel

                            Write-Message -Message "Setting job e-mail operator" -Level Verbose
                            $currentjob.OperatorToEmail = $EmailOperator
                        } else {
                            Stop-Function -Message "The e-mail operator name $EmailOperator does not exist on instance $instance. Exiting.." -Target $Job -Continue
                        }
                    } else {
                        Stop-Function -Message "Invalid combination of e-mail operator name $EmailOperator and email level $EmailLevel. Not setting the notification." -Target $Job -Continue
                    }
                }

                if ($NetsendOperator) {
                    if ($NetsendLevel -ge 1) {
                        # Check if the operator name is present
                        if ($server.JobServer.Operators.Name -contains $NetsendOperator) {
                            Write-Message -Message "Setting job netsend level" -Level Verbose
                            $currentjob.NetSendLevel = $NetsendLevel

                            Write-Message -Message "Setting job netsend operator" -Level Verbose
                            $currentjob.OperatorToNetSend = $NetsendOperator
                        } else {
                            Stop-Function -Message "The netsend operator name $NetsendOperator does not exist on instance $instance. Exiting.." -Target $Job -Continue
                        }
                    } else {
                        Write-Message -Message "Invalid combination of netsend operator name $NetsendOperator and netsend level $NetsendLevel. Not setting the notification."
                    }
                }

                if ($PageOperator) {
                    if ($PageLevel -ge 1) {
                        # Check if the operator name is present
                        if ($server.JobServer.Operators.Name -contains $PageOperator) {
                            Write-Message -Message "Setting job pager level" -Level Verbose
                            $currentjob.PageLevel = $PageLevel

                            Write-Message -Message "Setting job pager operator" -Level Verbose
                            $currentjob.OperatorToPage = $PageOperator
                        } else {
                            Stop-Function -Message "The page operator name $PageOperator does not exist on instance $instance. Exiting.." -Target $Job -Continue
                        }
                    } else {
                        Write-Message -Message "Invalid combination of page operator name $PageOperator and page level $PageLevel. Not setting the notification." -Level Warning
                    }
                }

                if ($DeleteLevel -ge 0) {
                    Write-Message -Message "Setting job delete level" -Level Verbose
                    $currentjob.DeleteLevel = $DeleteLevel
                }
                #endregion job options

                try {
                    Write-Message -Message "Creating the job" -Level Verbose

                    # Create the job
                    $currentjob.Create()

                    Write-Message -Message "Job created with UID $($currentjob.JobID)" -Level Verbose

                    # Make sure the target is set for the job
                    Write-Message -Message "Applying the target (local) to job $Job" -Level Verbose
                    $currentjob.ApplyToTargetServer("(local)")

                    # Refresh the SMO - another bug in SMO? As this should not be needed...
                    $currentjob.Refresh()

                    # If a schedule needs to be attached
                    if ($Schedule) {
                        $null = Set-DbaAgentJob -SqlInstance $server -Job $currentjob -Schedule $Schedule
                    }

                    if ($ScheduleId) {
                        $null = Set-DbaAgentJob -SqlInstance $server -Job $currentjob -ScheduleId $ScheduleId
                    }
                } catch {
                    Stop-Function -Message "Something went wrong creating the job" -Target $currentjob -ErrorRecord $_ -Continue
                }
            }

            Add-TeppCacheItem -SqlInstance $server -Type job -Name $Job

            Get-DbaAgentJob -SqlInstance $server -Job $Job
        }
    }

    end {
        if (Test-FunctionInterrupt) { return }
        Write-Message -Message "Finished creating job(s)." -Level Verbose
    }

}

# SIG # Begin signature block
# MIIjYAYJKoZIhvcNAQcCoIIjUTCCI00CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCBs3OK8OwpbeVpo
# FmvggyNco5QiXeq3TZ7xjcltD0JJT6CCHVkwggUaMIIEAqADAgECAhADBbuGIbCh
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
# BgorBgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCDceuPI1OQMBDkA5FhVs+h8Gxts
# N9X7KyRuSNGeys9ClTANBgkqhkiG9w0BAQEFAASCAQBnGCfDG6SSUWNvn9PvTESP
# gqhWraZZKtViQteqT5pPhWVSKNq6l6BTkWEJj9tKxqym4wnOCTVCfS8t0ZVuKk5p
# jq4cQICk0+9T3st7BmDhC2YthuOVO/AUSMpB8T7nI2i+h8V2P+nBPh3tRwLUD5u5
# 0rzt5KpDVcARIT6b1XYuxn//saEGVefQvgJ0SmkG7XMxOFHPO+0gnwjWQ/e1nKGl
# X+F1p4DLsjFZjsZePSJMFOFwTnws5Uv59Bc4ctphMzUsGTpgWQLBUwKrEQbPQVwP
# sN9HKKj+rt+Q27Cu7m1glAgvA6gdCo9ho6ngKxnpX5GeE6+Z1FKdqgIM2BIVNk1A
# oYIDIDCCAxwGCSqGSIb3DQEJBjGCAw0wggMJAgEBMHcwYzELMAkGA1UEBhMCVVMx
# FzAVBgNVBAoTDkRpZ2lDZXJ0LCBJbmMuMTswOQYDVQQDEzJEaWdpQ2VydCBUcnVz
# dGVkIEc0IFJTQTQwOTYgU0hBMjU2IFRpbWVTdGFtcGluZyBDQQIQDE1pckuU+jwq
# Sj0pB4A9WjANBglghkgBZQMEAgEFAKBpMBgGCSqGSIb3DQEJAzELBgkqhkiG9w0B
# BwEwHAYJKoZIhvcNAQkFMQ8XDTIyMTExNzA4NTY0OVowLwYJKoZIhvcNAQkEMSIE
# INn9KpyX5Aa1UfHDU6wy3QZtjLR6wUJ76urPr4DDwrGYMA0GCSqGSIb3DQEBAQUA
# BIICAHBnddoaPWtBaJwR5aI82cVqduNnbD68AKccCG5E2UsFYlZIFGzbSkBw5tx5
# nAhSbSfbKwFk28JNvB3j7gpv9Rq9FbSgNXfgUXasYG96TGGJHBDjdD09Da+92+lc
# UYqfidVDACCjryHCWjPx8yRldtgPYpkshQcAbnq3mq7DEW0yHuYJZ5UpzazyKsv5
# 3R3GdSUPaciP53ps2KN+AhOmIdv6r95BA0fEaWUP5QF8J3MzvSEBip3zbQ8EOsSS
# GLXxwyLFj7+DtOM+nhXlFtOJoo0/2u6EUlrsYLI7yYvMqSprURbGlBEm37wUS9P+
# cXcK/pgNjfSgraczv6eBZIYwUw0ztlkV//mo7IFVh9rfp/mVaWSnmmEMVLRxwd7B
# DU/uj0iG7okArsrXO78f1VuYORGCyQ43yhTxvEOGbaB8PYvRH4cB+dWes5Z2rY1F
# 6G81Wi4RnAm4hUakgjJkKQqN6l05EFpHb6D7F15p42+ArcrXqgJkkt6Jqbj8w078
# ucoUK676n15cJynyelFpgqMoISszNyffyNx0EoeeCg1xCVK9ZTDoJxZ8vQQyX2id
# Uv5Kbj/AbSXlIU1deSwxy3irhWpt3+FATJR2fyORvzo2Snj0sJ2ob0iOJlmSecb6
# 6+c3lBej73tUru/JL3J2F9KY+JpUKEjURc0zE6yogWXUqbnC
# SIG # End signature block
