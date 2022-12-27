function New-DbaAgentJobStep {
    <#
    .SYNOPSIS
        New-DbaAgentJobStep creates a new job step for a job

    .DESCRIPTION
        New-DbaAgentJobStep creates a new job in the SQL Server Agent for a specific job

    .PARAMETER SqlInstance
        The target SQL Server instance or instances. You must have sysadmin access and server version must be SQL Server version 2000 or greater.

    .PARAMETER SqlCredential
        Login to the target instance using alternative credentials. Accepts PowerShell credentials (Get-Credential).

        Windows Authentication, SQL Server Authentication, Active Directory - Password, and Active Directory - Integrated are all supported.

        For MFA support, please use Connect-DbaInstance.

    .PARAMETER Job
        The name of the job to which to add the step.

    .PARAMETER StepId
        The sequence identification number for the job step. Step identification numbers start at 1 and increment without gaps.

    .PARAMETER StepName
        The name of the step.

    .PARAMETER SubSystem
        The subsystem used by the SQL Server Agent service to execute command.
        Allowed values 'ActiveScripting','AnalysisCommand','AnalysisQuery','CmdExec','Distribution','LogReader','Merge','PowerShell','QueueReader','Snapshot','Ssis','TransactSql'
        The default is 'TransactSql'

    .PARAMETER SubSystemServer
        The subsystems AnalysisScripting, AnalysisCommand, AnalysisQuery ned the server property to be able to apply

    .PARAMETER Command
        The commands to be executed by SQLServerAgent service through subsystem.

    .PARAMETER CmdExecSuccessCode
        The value returned by a CmdExec subsystem command to indicate that command executed successfully.

    .PARAMETER OnSuccessAction
        The action to perform if the step succeeds.
        Allowed values  "QuitWithSuccess" (default), "QuitWithFailure", "GoToNextStep", "GoToStep".
        The text value van either be lowercase, uppercase or something in between as long as the text is correct.

    .PARAMETER OnSuccessStepId
        The ID of the step in this job to execute if the step succeeds and OnSuccessAction is "GoToStep".

    .PARAMETER OnFailAction
        The action to perform if the step fails.
        Allowed values  "QuitWithSuccess" (default), "QuitWithFailure", "GoToNextStep", "GoToStep".
        The text value van either be lowercase, uppercase or something in between as long as the text is correct.

    .PARAMETER OnFailStepId
        The ID of the step in this job to execute if the step fails and OnFailAction is "GoToStep".

    .PARAMETER Database
        The name of the database in which to execute a Transact-SQL step. The default is 'master'.

    .PARAMETER DatabaseUser
        The name of the user account to use when executing a Transact-SQL step.

    .PARAMETER RetryAttempts
        The number of retry attempts to use if this step fails. The default is 0.

    .PARAMETER RetryInterval
        The amount of time in minutes between retry attempts. The default is 0.

    .PARAMETER OutputFileName
        The name of the file in which the output of this step is saved.

    .PARAMETER Insert
        This switch indicates the new step is inserted at the specified stepid.
        All following steps will have their IDs incremented by, and success/failure next steps incremented accordingly

    .PARAMETER Flag
        Sets the flag(s) for the job step.

        Flag                                    Description
        ----------------------------------------------------------------------------
        AppendAllCmdExecOutputToJobHistory      Job history, including command output, is appended to the job history file.
        AppendToJobHistory                      Job history is appended to the job history file.
        AppendToLogFile                         Job history is appended to the SQL Server log file.
        AppendToTableLog                        Job history is appended to a log table.
        LogToTableWithOverwrite                 Job history is written to a log table, overwriting previous contents.
        None                                    Job history is not appended to a file.
        ProvideStopProcessEvent                 Job processing is stopped.

    .PARAMETER ProxyName
        The name of the proxy that the job step runs as.

    .PARAMETER WhatIf
        Shows what would happen if the command were to run. No actions are actually performed.

    .PARAMETER Confirm
        Prompts you for confirmation before executing any changing operations within the command.

    .PARAMETER Force
        The force parameter will ignore some errors in the parameters and assume defaults.

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
        https://dbatools.io/New-DbaAgentJobStep

    .EXAMPLE
        PS C:\> New-DbaAgentJobStep -SqlInstance sql1 -Job Job1 -StepName Step1

        Create a step in "Job1" with the name Step1 with the default subsystem TransactSql.

    .EXAMPLE
        PS C:\> New-DbaAgentJobStep -SqlInstance sql1 -Job Job1 -StepName Step1 -Database msdb

        Create a step in "Job1" with the name Step1 where the database will the msdb

    .EXAMPLE
        PS C:\> New-DbaAgentJobStep -SqlInstance sql1, sql2, sql3 -Job Job1 -StepName Step1 -Database msdb

        Create a step in "Job1" with the name Step1 where the database will the "msdb" for multiple servers

    .EXAMPLE
        PS C:\> New-DbaAgentJobStep -SqlInstance sql1, sql2, sql3 -Job Job1, Job2, 'Job Three' -StepName Step1 -Database msdb

        Create a step in "Job1" with the name Step1 where the database will the "msdb" for multiple servers for multiple jobs

    .EXAMPLE
        PS C:\> sql1, sql2, sql3 | New-DbaAgentJobStep -Job Job1 -StepName Step1 -Database msdb

        Create a step in "Job1" with the name Step1 where the database will the "msdb" for multiple servers using pipeline

    .EXAMPLE
        PS C:\> New-DbaAgentJobStep -SqlInstance sq1 -Job Job1 -StepName StepA -Database msdb -StepId 2 -Insert

        Assuming Job1 already has steps Step1 and Step2, will create a new step Step A and set the step order as Step1, StepA, Step2
        Internal StepIds will be updated, and any specific OnSuccess/OnFailure step references will also be updated

    #>

    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = "Low")]
    param (
        [parameter(Mandatory, ValueFromPipeline)]
        [DbaInstanceParameter[]]$SqlInstance,
        [PSCredential]$SqlCredential,
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [object[]]$Job,
        [int]$StepId,
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$StepName,
        [ValidateSet('ActiveScripting', 'AnalysisCommand', 'AnalysisQuery', 'CmdExec', 'Distribution', 'LogReader', 'Merge', 'PowerShell', 'QueueReader', 'Snapshot', 'Ssis', 'TransactSql')]
        [string]$Subsystem = 'TransactSql',
        [string]$SubsystemServer,
        [string]$Command,
        [int]$CmdExecSuccessCode,
        [ValidateSet('QuitWithSuccess', 'QuitWithFailure', 'GoToNextStep', 'GoToStep')]
        [string]$OnSuccessAction = 'QuitWithSuccess',
        [int]$OnSuccessStepId = 0,
        [ValidateSet('QuitWithSuccess', 'QuitWithFailure', 'GoToNextStep', 'GoToStep')]
        [string]$OnFailAction = 'QuitWithFailure',
        [int]$OnFailStepId = 0,
        [object]$Database,
        [string]$DatabaseUser,
        [int]$RetryAttempts,
        [int]$RetryInterval,
        [string]$OutputFileName,
        [switch]$Insert,
        [ValidateSet('AppendAllCmdExecOutputToJobHistory', 'AppendToJobHistory', 'AppendToLogFile', 'AppendToTableLog', 'LogToTableWithOverwrite', 'None', 'ProvideStopProcessEvent')]
        [string[]]$Flag,
        [string]$ProxyName,
        [switch]$Force,
        [switch]$EnableException
    )

    begin {
        if ($Force) { $ConfirmPreference = 'none' }

        # Check the parameter on success step id
        if (($OnSuccessAction -ne 'GoToStep') -and ($OnSuccessStepId -ge 1)) {
            Stop-Function -Message "Parameter OnSuccessStepId can only be used with OnSuccessAction 'GoToStep'." -Target $SqlInstance
            return
        }

        # Check the parameter on fail step id
        if (($OnFailAction -ne 'GoToStep') -and ($OnFailStepId -ge 1)) {
            Stop-Function -Message "Parameter OnFailStepId can only be used with OnFailAction 'GoToStep'." -Target $SqlInstance
            return
        }

        if ($Subsystem -in 'AnalysisScripting', 'AnalysisCommand', 'AnalysisQuery') {
            if (-not $SubsystemServer) {
                Stop-Function -Message "Please enter the server value using -SubSystemServer for subsystem $Subsystem." -Target $Subsystem
                return
            }
        }
    }

    process {

        if (Test-FunctionInterrupt) { return }

        foreach ($instance in $SqlInstance) {
            try {
                $Server = Connect-DbaInstance -SqlInstance $instance -SqlCredential $SqlCredential
            } catch {
                Stop-Function -Message "Failure" -Category ConnectionError -ErrorRecord $_ -Target $instance -Continue
            }

            foreach ($j in $Job) {

                # Check if the job exists
                if ($Server.JobServer.Jobs.Name -notcontains $j) {
                    Write-Message -Message "Job $j doesn't exist on $instance" -Level Warning
                } else {
                    # Create the job step object
                    try {
                        # Get the job from the server again since fields on the job object may have changed
                        $currentJob = $Server.JobServer.Jobs[$j]

                        # Create the job step
                        $jobStep = New-Object Microsoft.SqlServer.Management.Smo.Agent.JobStep

                        # Set the job where the job steps belongs to
                        $jobStep.Parent = $currentJob
                    } catch {
                        Stop-Function -Message "Something went wrong creating the job step" -Target $instance -ErrorRecord $_ -Continue
                    }

                    #region job step options
                    # Setting the options for the job step
                    if ($StepName) {
                        # Check if the step already exists
                        if ($currentJob.JobSteps.Name -notcontains $StepName) {
                            $jobStep.Name = $StepName
                        } elseif (($currentJob.JobSteps.Name -contains $StepName) -and $Force) {
                            Write-Message -Message "Step $StepName already exists for job. Force is used. Removing existing step" -Level Verbose

                            # Remove the job step based on the name
                            Remove-DbaAgentJobStep -SqlInstance $instance -Job $currentJob -StepName $StepName -SqlCredential $SqlCredential -Confirm:$false

                            # Set the name job step object
                            $jobStep.Name = $StepName
                        } else {
                            Stop-Function -Message "The step name $StepName already exists for job $currentJob" -Target $instance -Continue
                        }
                    }

                    # If the step id need to be set
                    if ($StepId) {
                        # Check if the used step id is already in place
                        if ($currentJob.JobSteps.ID -notcontains $StepId) {
                            Write-Message -Message "Setting job step step id to $StepId" -Level Verbose
                            $jobStep.ID = $StepId
                        } elseif (($currentJob.JobSteps.ID -contains $StepID) -and $Insert) {
                            Write-Message -Message "Inserting step as step $StepID" -Level Verbose
                            foreach ($tStep in $currentJob.JobSteps) {
                                if ($tStep.Id -ge $Stepid) {
                                    $tStep.Id = ($tStep.ID) + 1
                                }
                                if ($tStep.OnFailureStepID -ge $StepId -and $tStep.OnFailureStepId -ne 0) {
                                    $tStep.OnFailureStepID = ($tStep.OnFailureStepID) + 1
                                }
                            }
                            $jobStep.ID = $StepId
                        } elseif (($currentJob.JobSteps.ID -contains $StepId) -and $Force) {
                            Write-Message -Message "Step ID $StepId already exists for job. Force is used. Removing existing step" -Level Verbose

                            # Remove the existing job step
                            $StepName = ($currentJob.JobSteps | Where-Object { $_.ID -eq 1 }).Name
                            Remove-DbaAgentJobStep -SqlInstance $instance -Job $currentJob -StepName $StepName -SqlCredential $SqlCredential -Confirm:$false

                            # Set the ID job step object
                            $jobStep.ID = $StepId
                        } else {
                            Stop-Function -Message "The step id $StepId already exists for job $currentJob" -Target $instance -Continue
                        }
                    } else {
                        # Get the job step count
                        $jobStep.ID = $currentJob.JobSteps.Count + 1
                    }

                    if ($Subsystem) {
                        Write-Message -Message "Setting job step subsystem to $Subsystem" -Level Verbose
                        $jobStep.Subsystem = $Subsystem
                    }

                    if ($SubsystemServer) {
                        Write-Message -Message "Setting job step subsystem server to $SubsystemServer" -Level Verbose
                        $jobStep.Server = $SubsystemServer
                    }

                    if ($Command) {
                        Write-Message -Message "Setting job step command to $Command" -Level Verbose
                        $jobStep.Command = $Command
                    }

                    if ($CmdExecSuccessCode) {
                        Write-Message -Message "Setting job step command exec success code to $CmdExecSuccessCode" -Level Verbose
                        $jobStep.CommandExecutionSuccessCode = $CmdExecSuccessCode
                    }

                    if ($OnSuccessAction) {
                        Write-Message -Message "Setting job step success action to $OnSuccessAction" -Level Verbose
                        $jobStep.OnSuccessAction = $OnSuccessAction
                    }

                    if ($OnSuccessStepId) {
                        Write-Message -Message "Setting job step success step id to $OnSuccessStepId" -Level Verbose
                        $jobStep.OnSuccessStep = $OnSuccessStepId
                    }

                    if ($OnFailAction) {
                        Write-Message -Message "Setting job step fail action to $OnFailAction" -Level Verbose
                        $jobStep.OnFailAction = $OnFailAction
                    }

                    if ($OnFailStepId) {
                        Write-Message -Message "Setting job step fail step id to $OnFailStepId" -Level Verbose
                        $jobStep.OnFailStep = $OnFailStepId
                    }

                    if ($Database) {
                        # Check if the database is present on the server
                        if ($Server.Databases.Name -contains $Database) {
                            Write-Message -Message "Setting job step database name to $Database" -Level Verbose
                            $jobStep.DatabaseName = $Database
                        } else {
                            Stop-Function -Message "The database is not present on instance $instance." -Target $instance -Continue
                        }
                    }

                    if ($DatabaseUser -and $DatabaseName) {
                        # Check if the username is present in the database
                        if ($Server.Databases[$DatabaseName].Users.Name -contains $DatabaseUser) {

                            Write-Message -Message "Setting job step database username to $DatabaseUser" -Level Verbose
                            $jobStep.DatabaseUserName = $DatabaseUser
                        } else {
                            Stop-Function -Message "The database user is not present in the database $DatabaseName on instance $instance." -Target $instance -Continue
                        }
                    }

                    if ($RetryAttempts) {
                        Write-Message -Message "Setting job step retry attempts to $RetryAttempts" -Level Verbose
                        $jobStep.RetryAttempts = $RetryAttempts
                    }

                    if ($RetryInterval) {
                        Write-Message -Message "Setting job step retry interval to $RetryInterval" -Level Verbose
                        $jobStep.RetryInterval = $RetryInterval
                    }

                    if ($OutputFileName) {
                        Write-Message -Message "Setting job step output file name to $OutputFileName" -Level Verbose
                        $jobStep.OutputFileName = $OutputFileName
                    }

                    if ($ProxyName) {
                        # Check if the proxy exists
                        if ($Server.JobServer.ProxyAccounts.Name -contains $ProxyName) {
                            Write-Message -Message "Setting job step proxy name to $ProxyName" -Level Verbose
                            $jobStep.ProxyName = $ProxyName
                        } else {
                            Stop-Function -Message "The proxy name $ProxyName doesn't exist on instance $instance." -Target $instance -Continue
                        }
                    }

                    if ($Flag.Count -ge 1) {
                        Write-Message -Message "Setting job step flag(s) to $($Flags -join ',')" -Level Verbose
                        $jobStep.JobStepFlags = $Flag
                    }
                    #endregion job step options

                    # Execute
                    if ($PSCmdlet.ShouldProcess($instance, "Creating the job step $StepName")) {
                        try {
                            Write-Message -Message "Creating the job step" -Level Verbose

                            # Create the job step
                            $jobStep.Create()
                            $currentJob.Alter()
                        } catch {
                            Stop-Function -Message "Something went wrong creating the job step" -Target $instance -ErrorRecord $_ -Continue
                        }

                        # Return the job step
                        $jobStep
                    }
                }
            } # foreach object job
        } # foreach object instance
    } # process

    end {
        if (Test-FunctionInterrupt) { return }
        Write-Message -Message "Finished creating job step(s)" -Level Verbose
    }
}
# SIG # Begin signature block
# MIIjYAYJKoZIhvcNAQcCoIIjUTCCI00CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCC07q773992dgzX
# dDBCuW6mGmBYZWbfoIXMuhOSCTsUV6CCHVkwggUaMIIEAqADAgECAhADBbuGIbCh
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
# BgorBgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCCoLYHyGsrpiaTG2FYkBLKG96I5
# 7nGgRydF/79zguVE+jANBgkqhkiG9w0BAQEFAASCAQAJhKjhQpR1wBUWLVTf5CFb
# 9Wgtcrx5mFkli97oY4b4yBAw+YlCklcSmvKuulL6eol+7LLcFoxK7aEOKl+xGtxQ
# xmpTHrRLdpMV4C9sjbDO5+xDR44WqrqdvL6xxZo0gAFkZDsEeBGIUlgMq0ucmg/c
# /J+fG2DsMyMBygOVPbOG4A4+r9OIktl/HskA18U1DmAgDHcOv8SYyiUa7vLAkB+t
# eTDel/mTni3ncrsLtS9zu41GJjB47SOP5ppk4XU4K4st43DcU4ZMHHW9KLI6OIM6
# Qlbc0VhgD2FUzr8Y3zIyk26olItCa1jiBBJyTsGseDqkWHC8q6iQLcAlKAwzyc9F
# oYIDIDCCAxwGCSqGSIb3DQEJBjGCAw0wggMJAgEBMHcwYzELMAkGA1UEBhMCVVMx
# FzAVBgNVBAoTDkRpZ2lDZXJ0LCBJbmMuMTswOQYDVQQDEzJEaWdpQ2VydCBUcnVz
# dGVkIEc0IFJTQTQwOTYgU0hBMjU2IFRpbWVTdGFtcGluZyBDQQIQDE1pckuU+jwq
# Sj0pB4A9WjANBglghkgBZQMEAgEFAKBpMBgGCSqGSIb3DQEJAzELBgkqhkiG9w0B
# BwEwHAYJKoZIhvcNAQkFMQ8XDTIyMTExNzA4NTY1MFowLwYJKoZIhvcNAQkEMSIE
# ILQrF4Qb3/26NeRKBgbWWl8yWXa29h79dxBSfYOuLk6tMA0GCSqGSIb3DQEBAQUA
# BIICAFukH/3Ut6Zb/yyKUWRc0n3WYsXf8vL0MKuFVeQh+2VQ3/Dy/4fW6t0x9n/M
# KGS9TQATKsegk2LhfIahfpA/XC5KPb/dSnR17tW7zeAUdjRO/GqKQAdhzMCdEXkP
# koFBEXlSHOORgO26bgED0LiFOWFnX4IZB5vnmKPKTSWrUm2/B995sDwP0O+0AKVv
# sUWqcaRD991jBpZe+lIqF/i5hpIPzWfHpLduO1+mj0Qzw4SaSrS7jAa2GIwhMGrW
# /iiXizXOhQYxLP+D8KxEYJttYff1MS5SbsDaKiKBD36qRzzjhX5RrGr8sZbmU6/N
# y5crI3/QTxMgr52zVmdQWM5r69BbcIFmSvyK3pBPuCRlPRrk9G2zZRWs2l3w3epA
# moKlkkHRYMYPYaXmLfzysMeEYALxC32lgSPWgfda4xCuurHNenBJ+N3qPY+02w98
# i5UfvrWNC7RQHzdYe+THa04R/u+78LqX0TQrh8h1Kf2/njK3BcqBWlhDnF5MXAFD
# rKTsWop5zyyKWkqL07Si1nFrDIuSk4KFfN3DkhyaiD+4B4q7AlJ7GOfciwz+Nry6
# RUa/T/NSdwVHusdZKAG6ykORhDbad7A1yEfchxzqAx6AtSM7DVoTzZ/sDHIcuRHY
# GHHXd5+Jzhrj95oES3KSodGxGU1UWwP7pJIw+F6ideSbZnW7
# SIG # End signature block
