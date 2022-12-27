function Get-DbaAgentJobHistory {
    <#
    .SYNOPSIS
        Gets execution history of SQL Agent Job on instance(s) of SQL Server.

    .DESCRIPTION
        Get-DbaAgentJobHistory returns all information on the executions still available on each instance(s) of SQL Server submitted.
        The cleanup of SQL Agent history determines how many records are kept.

        https://msdn.microsoft.com/en-us/library/ms201680.aspx
        https://msdn.microsoft.com/en-us/library/microsoft.sqlserver.management.smo.agent.jobhistoryfilter(v=sql.120).aspx

    .PARAMETER SqlInstance
        The target SQL Server instance or instances. This can be a collection and receive pipeline input to allow the function to be executed against multiple SQL Server instances.

    .PARAMETER SqlCredential
        Login to the target instance using alternative credentials. Accepts PowerShell credentials (Get-Credential).

        Windows Authentication, SQL Server Authentication, Active Directory - Password, and Active Directory - Integrated are all supported.

        For MFA support, please use Connect-DbaInstance.

    .PARAMETER Job
        The name of the job from which the history is wanted. If unspecified, all jobs will be processed.

    .PARAMETER ExcludeJob
        The job(s) to exclude - this list is auto-populated from the server

    .PARAMETER StartDate
        The DateTime starting from which the history is wanted. If unspecified, all available records will be processed.

    .PARAMETER EndDate
        The DateTime before which the history is wanted. If unspecified, all available records will be processed.

    .PARAMETER OutcomeType
        The CompletionResult to filter the history for. Valid values are: Failed, Succeeded, Retry, Cancelled, InProgress, Unknown

    .PARAMETER ExcludeJobSteps
        Use this switch to discard all job steps, and return only the job totals

    .PARAMETER WithOutputFile
        Use this switch to retrieve the output file (only if you want step details). Bonus points, we handle the quirks
        of SQL Agent tokens to the best of our knowledge (https://technet.microsoft.com/it-it/library/ms175575(v=sql.110).aspx)

    .PARAMETER JobCollection
        An array of SMO jobs

    .PARAMETER EnableException
        By default, when something goes wrong we try to catch it, interpret it and give you a friendly warning message.
        This avoids overwhelming you with "sea of red" exceptions, but is inconvenient because it basically disables advanced scripting.
        Using this switch turns this "nice by default" feature off and enables you to catch exceptions with your own try/catch.

    .NOTES
        Tags: Agent, Job
        Author: Klaas Vandenberghe (@PowerDbaKlaas) | Simone Bizzotto (@niphold)

        Website: https://dbatools.io
        Copyright: (c) 2018 by dbatools, licensed under MIT
        License: MIT https://opensource.org/licenses/MIT

    .LINK
        https://dbatools.io/Get-DbaAgentJobHistory

    .EXAMPLE
        PS C:\> Get-DbaAgentJobHistory -SqlInstance localhost

        Returns all SQL Agent Job execution results on the local default SQL Server instance.

    .EXAMPLE
        PS C:\> Get-DbaAgentJobHistory -SqlInstance localhost, sql2016

        Returns all SQL Agent Job execution results for the local and sql2016 SQL Server instances.

    .EXAMPLE
        PS C:\> 'sql1','sql2\Inst2K17' | Get-DbaAgentJobHistory

        Returns all SQL Agent Job execution results for sql1 and sql2\Inst2K17.

    .EXAMPLE
        PS C:\> Get-DbaAgentJobHistory -SqlInstance sql2\Inst2K17 | Select-Object *

        Returns all properties for all SQl Agent Job execution results on sql2\Inst2K17.

    .EXAMPLE
        PS C:\> Get-DbaAgentJobHistory -SqlInstance sql2\Inst2K17 -Job 'Output File Cleanup'

        Returns all properties for all SQl Agent Job execution results of the 'Output File Cleanup' job on sql2\Inst2K17.

    .EXAMPLE
        PS C:\> Get-DbaAgentJobHistory -SqlInstance sql2\Inst2K17 -Job 'Output File Cleanup' -WithOutputFile

        Returns all properties for all SQl Agent Job execution results of the 'Output File Cleanup' job on sql2\Inst2K17,
        with additional properties that show the output filename path

    .EXAMPLE
        PS C:\> Get-DbaAgentJobHistory -SqlInstance sql2\Inst2K17 -ExcludeJobSteps

        Returns the SQL Agent Job execution results for the whole jobs on sql2\Inst2K17, leaving out job step execution results.

    .EXAMPLE
        PS C:\> Get-DbaAgentJobHistory -SqlInstance sql2\Inst2K17 -StartDate '2017-05-22' -EndDate '2017-05-23 12:30:00'

        Returns the SQL Agent Job execution results between 2017/05/22 00:00:00 and 2017/05/23 12:30:00 on sql2\Inst2K17.

    .EXAMPLE
        PS C:\> Get-DbaAgentJob -SqlInstance sql2016 | Where-Object Name -Match backup | Get-DbaAgentJobHistory

        Gets all jobs with the name that match the regex pattern "backup" and then gets the job history from those. You can also use -Like *backup* in this example.

    .EXAMPLE
        PS C:\> Get-DbaAgentJobHistory -SqlInstance sql2016 -OutcomeType Failed

        Returns only the failed SQL Agent Job execution results for the sql2016 SQL Server instance.

    #>
    [CmdletBinding(DefaultParameterSetName = "Default")]
    param (
        [parameter(Mandatory, ValueFromPipeline, ParameterSetName = "Server")]
        [DbaInstanceParameter[]]$SqlInstance,
        [PSCredential]
        $SqlCredential,
        [object[]]$Job,
        [object[]]$ExcludeJob,
        [DateTime]$StartDate = "1900-01-01",
        [DateTime]$EndDate = $(Get-Date),
        [ValidateSet('Failed', 'Succeeded', 'Retry', 'Cancelled', 'InProgress', 'Unknown')]
        [Microsoft.SqlServer.Management.Smo.Agent.CompletionResult]$OutcomeType,
        [switch]$ExcludeJobSteps,
        [switch]$WithOutputFile,
        [parameter(Mandatory, ValueFromPipeline, ParameterSetName = "Collection")]
        [Microsoft.SqlServer.Management.Smo.Agent.Job]$JobCollection,
        [switch]$EnableException
    )

    begin {
        $filter = New-Object Microsoft.SqlServer.Management.Smo.Agent.JobHistoryFilter
        $filter.StartRunDate = $StartDate
        $filter.EndRunDate = $EndDate

        if (Test-Bound OutcomeType) {
            $filter.OutcomeTypes = $OutcomeType
        }

        if ($ExcludeJobSteps -and $WithOutputFile) {
            Stop-Function -Message "You can't use -ExcludeJobSteps and -WithOutputFile together"
        }

        function Get-JobHistory {
            [CmdletBinding()]
            param (
                $Server,
                $Job,
                [switch]$WithOutputFile
            )
            $tokenrex = [regex]'\$\((?<method>[^()]+)\((?<tok>[^)]+)\)\)|\$\((?<tok>[^)]+)\)'
            $propmap = @{
                'INST'      = $Server.ServiceName
                'MACH'      = $Server.ComputerName
                'SQLDIR'    = $Server.InstallDataDirectory
                'SQLLOGDIR' = $Server.ErrorLogPath
                #'STEPCT' loop number ?
                'SRVR'      = $Server.DomainInstanceName
                # WMI( property ) impossible
            }


            $squote_rex = [regex]"(?<!')'(?!')"
            $dquote_rex = [regex]'(?<!")"(?!")'
            $rbrack_rex = [regex]'(?<!])](?!])'

            function Resolve-TokenEscape($method, $value) {
                if (!$method) {
                    return $value
                }
                $value = switch ($method) {
                    'ESCAPE_SQUOTE' { $squote_rex.Replace($value, "''") }
                    'ESCAPE_DQUOTE' { $dquote_rex.Replace($value, '""') }
                    'ESCAPE_RBRACKET' { $rbrack_rex.Replace($value, ']]') }
                    'ESCAPE_NONE' { $value }
                    default { $value }
                }
                return $value
            }

            #'STEPID' =  stepid
            #'STRTTM' job begin time
            #'STRTDT' job begin date
            #'JOBID' = JobId
            function Resolve-JobToken($exec, $outfile, $outcome) {
                $n = $tokenrex.Matches($outfile)
                foreach ($x in $n) {
                    $tok = $x.Groups['tok'].Value
                    $EscMethod = $x.Groups['method'].Value
                    if ($propmap.containskey($tok)) {
                        $repl = Resolve-TokenEscape -method $EscMethod -value $propmap[$tok]
                        $outfile = $outfile.Replace($x.Value, $repl)
                    } elseif ($tok -eq 'STEPID') {
                        $repl = Resolve-TokenEscape -method $EscMethod -value $exec.StepID
                        $outfile = $outfile.Replace($x.Value, $repl)
                    } elseif ($tok -eq 'JOBID') {
                        # convert(binary(16), ?)
                        $repl = @('0x') + @($exec.JobID.ToByteArray() | ForEach-Object -Process { $_.ToString('X2') }) -join ''
                        $repl = Resolve-TokenEscape -method $EscMethod -value $repl
                        $outfile = $outfile.Replace($x.Value, $repl)
                    } elseif ($tok -eq 'STRTDT') {
                        $repl = Resolve-TokenEscape -method $EscMethod -value $outcome.RunDate.toString('yyyyMMdd')
                        $outfile = $outfile.Replace($x.Value, $repl)
                    } elseif ($tok -eq 'STRTTM') {
                        $repl = Resolve-TokenEscape -method $EscMethod -value ([int]$outcome.RunDate.toString('HHmmss')).toString()
                        $outfile = $outfile.Replace($x.Value, $repl)
                    } elseif ($tok -eq 'DATE') {
                        $repl = Resolve-TokenEscape -method $EscMethod -value $exec.RunDate.toString('yyyyMMdd')
                        $outfile = $outfile.Replace($x.Value, $repl)
                    } elseif ($tok -eq 'TIME') {
                        $repl = Resolve-TokenEscape -method $EscMethod -value ([int]$exec.RunDate.toString('HHmmss')).toString()
                        $outfile = $outfile.Replace($x.Value, $repl)
                    }
                }
                return $outfile
            }
            try {
                Write-Message -Message "Attempting to get job history from $instance" -Level Verbose
                if ($Job) {
                    foreach ($currentjob in $Job) {
                        $filter.JobName = $currentjob
                        $executions += $server.JobServer.EnumJobHistory($filter)
                    }
                } else {
                    $executions = $server.JobServer.EnumJobHistory($filter)
                }
                if ($ExcludeJobSteps) {
                    $executions = $executions | Where-Object { $_.StepID -eq 0 }
                }

                if ($WithOutputFile) {
                    $outmap = @{ }
                    $outfiles = Get-DbaAgentJobOutputFile -SqlInstance $Server -SqlCredential $SqlCredential -Job $Job

                    foreach ($out in $outfiles) {
                        if (!$outmap.ContainsKey($out.Job)) {
                            $outmap[$out.Job] = @{ }
                        }
                        $outmap[$out.Job][$out.StepId] = $out.OutputFileName
                    }
                }
                $outcome = [pscustomobject]@{ }
                foreach ($execution in $executions) {
                    $status = switch ($execution.RunStatus) {
                        0 { "Failed" }
                        1 { "Succeeded" }
                        2 { "Retry" }
                        3 { "Canceled" }
                    }

                    Add-Member -Force -InputObject $execution -MemberType NoteProperty -Name ComputerName -value $server.ComputerName
                    Add-Member -Force -InputObject $execution -MemberType NoteProperty -Name InstanceName -value $server.ServiceName
                    Add-Member -Force -InputObject $execution -MemberType NoteProperty -Name SqlInstance -value $server.DomainInstanceName
                    $DurationInSeconds = ($execution.RunDuration % 100) + [math]::floor( ($execution.RunDuration % 10000 ) / 100 ) * 60 + [math]::floor( ($execution.RunDuration % 1000000 ) / 10000 ) * 60 * 60
                    Add-Member -Force -InputObject $execution -MemberType NoteProperty -Name StartDate -value ([dbadatetime]$execution.RunDate)
                    Add-Member -Force -InputObject $execution -MemberType NoteProperty -Name EndDate -value ([dbadatetime]$execution.RunDate.AddSeconds($DurationInSeconds))
                    Add-Member -Force -InputObject $execution -MemberType NoteProperty -Name Duration -value ([prettytimespan](New-TimeSpan -Seconds $DurationInSeconds))
                    Add-Member -Force -InputObject $execution -MemberType NoteProperty -Name Status -value $status
                    if ($WithOutputFile) {
                        if ($execution.StepID -eq 0) {
                            $outcome = $execution
                        }
                        try {
                            $outname = $outmap[$execution.JobName][$execution.StepID]
                            $outname = Resolve-JobToken -exec $execution -outcome $outcome -outfile $outname
                            $outremote = Join-AdminUNC $Server.ComputerName $outname
                        } catch {
                            $outname = ''
                            $outremote = ''
                        }
                        Add-Member -Force -InputObject $execution -MemberType NoteProperty -Name OutputFileName -value $outname
                        Add-Member -Force -InputObject $execution -MemberType NoteProperty -Name RemoteOutputFileName -value $outremote
                        # Add this in for easier ConvertTo-DbaTimeline Support
                        Add-Member -Force -InputObject $execution -MemberType NoteProperty -Name TypeName -value AgentJobHistory
                        Select-DefaultView -InputObject $execution -Property ComputerName, InstanceName, SqlInstance, 'JobName as Job', StepName, RunDate, StartDate, EndDate, Duration, Status, OperatorEmailed, Message, OutputFileName, RemoteOutputFileName -TypeName AgentJobHistory
                    } else {
                        Add-Member -Force -InputObject $execution -MemberType NoteProperty -Name TypeName -value AgentJobHistory
                        Select-DefaultView -InputObject $execution -Property ComputerName, InstanceName, SqlInstance, 'JobName as Job', StepName, RunDate, StartDate, EndDate, Duration, Status, OperatorEmailed, Message -TypeName AgentJobHistory
                    }

                }
            } catch {
                Stop-Function -Message "Could not get Agent Job History from $instance" -Target $instance -Continue
            }
        }
    }

    process {

        if (Test-FunctionInterrupt) { return }

        if ($JobCollection) {
            foreach ($currentjob in $JobCollection) {
                Get-JobHistory -Server $currentjob.Parent.Parent -Job $currentjob.Name -WithOutputFile:$WithOutputFile
            }
        }

        foreach ($instance in $SqlInstance) {
            try {
                $server = Connect-DbaInstance -SqlInstance $instance -SqlCredential $SqlCredential
            } catch {
                Stop-Function -Message "Failure" -Category ConnectionError -ErrorRecord $_ -Target $instance -Continue
            }

            if ($ExcludeJob) {
                $jobs = $server.JobServer.Jobs.Name | Where-Object { $_ -notin $ExcludeJob }
                foreach ($currentjob in $jobs) {
                    Get-JobHistory -Server $server -Job $currentjob -WithOutputFile:$WithOutputFile
                }
            } else {
                Get-JobHistory -Server $server -Job $Job -WithOutputFile:$WithOutputFile
            }
        }
    }
}
# SIG # Begin signature block
# MIIjYAYJKoZIhvcNAQcCoIIjUTCCI00CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCBRcgHoPcmJ44ZU
# mJ3Y4veEToWcTAGKlOaWPBCIyIYvSqCCHVkwggUaMIIEAqADAgECAhADBbuGIbCh
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
# BgorBgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCDCksRg13SXJ6zHJpS1Yf6QDrgP
# RLubeh2C4vgeXQpPfDANBgkqhkiG9w0BAQEFAASCAQAkfb+3S9qUfJsB8fmhxQP7
# dy56LG5EPw70KMD6T8Le8qLYLlGGjn8nHOEA8Q9H2zBhKxs9SmTLd8Dv0HpNhZda
# noAG52QV2QvxrZKK2PSLZ5LGBjpB2Z1vmOOylF62Z8H2/7FcV5HWP9q2iCQbxNvo
# ut8S7Z4Y4CJp7Wom+1fnkJwZ1ilLMi7DqdnDsBJlBGU6n1lYB2KmdUpmhJplWvtt
# Vi9NQ6JFo2YfQEMilG/fwtlzkFsgI5Oe/fM/cN+eMBSE8+AOMR3WOJDfIRW/zRIM
# ViGqpJ+NNcwL7HPZPbDd/Tbk9YsNDIzXZKiGbm9qZC2ndNrsk6+PLANCDJ1CcxLE
# oYIDIDCCAxwGCSqGSIb3DQEJBjGCAw0wggMJAgEBMHcwYzELMAkGA1UEBhMCVVMx
# FzAVBgNVBAoTDkRpZ2lDZXJ0LCBJbmMuMTswOQYDVQQDEzJEaWdpQ2VydCBUcnVz
# dGVkIEc0IFJTQTQwOTYgU0hBMjU2IFRpbWVTdGFtcGluZyBDQQIQDE1pckuU+jwq
# Sj0pB4A9WjANBglghkgBZQMEAgEFAKBpMBgGCSqGSIb3DQEJAzELBgkqhkiG9w0B
# BwEwHAYJKoZIhvcNAQkFMQ8XDTIyMTExNzA4NTUzOFowLwYJKoZIhvcNAQkEMSIE
# IGujyg0Xta5h9cVxsLqqkqj6qRp4HWol5qBkaG8Qe1m/MA0GCSqGSIb3DQEBAQUA
# BIICAMyccn8w8vKj2Jk1YYUdd1ca0ar7b/7lbEo65cAgT3X7nTJrgXRkgBtIZz47
# 6NXG3cCvZNkMxjNNaSjx+7BVqLNY6V2H+kIZ3EtRPI8z/hzlsverOuB4uroaEin3
# FGk1rkpTiWnvySI9wULnTaJdDrYBPz41Yl7q4yeJwuXjhJjRfH2tkWFtUES5lzGq
# hzzISl4wNxilZPQFUHJO2YFI+y4uaVzj7YzxYOWyfx5tGGjitx1RxB5FOpGitrw4
# TnWc/P25VNuUMqxVWkBlbqd2ZUNPOU+/G7IOdtb8YsOs7R7jfo+0ZXpjvs0FGaPr
# NqVxaX2C4LO01GxY2qs9bwr5YdpJsX+KL6M/d8pnJvTCooJ65NajKhO/AYBt6IOM
# 5yXsSoAEtKn84aeFUz93li24vUFxAguf1fl+sXviX+Y+hLmkCAo1rWMPRgyDAmxr
# mTAgeU6Ul1DBT2/sf6WlRV7h0U1vIMnkrj1hHfUzS168QNYpynSxuMvLlKAMShRo
# GeddV4GwcjUWpBhWQ1xfvd0iKQWjeX4loW7PMp0ldO5/C/yJnq8JB9sB7D+1ieT8
# CHw/GcELrvvuo2GM5xpxqvaOcElf+LUGGO7Ic9C+vmCm08x9GC7DkykavJxq4MXM
# O25KxKQBfi2leyut1nEYm84OUF+jFzisZx/Kj5IzvrNgighA
# SIG # End signature block
