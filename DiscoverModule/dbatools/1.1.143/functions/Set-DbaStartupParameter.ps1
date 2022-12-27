function Set-DbaStartupParameter {
    <#
    .SYNOPSIS
        Sets the Startup Parameters for a SQL Server instance

    .DESCRIPTION
        Modifies the startup parameters for a specified SQL Server Instance

        For full details of what each parameter does, please refer to this MSDN article - https://msdn.microsoft.com/en-us/library/ms190737(v=sql.105).aspx

    .PARAMETER SqlInstance
        The SQL Server instance to be modified

        If the Sql Instance is offline path parameters will be ignored as we cannot test the instance's access to the path. If you want to force this to work then please use the Force switch

    .PARAMETER SqlCredential
        Login to the target instance using alternative credentials. Accepts PowerShell credentials (Get-Credential).

        Windows Authentication, SQL Server Authentication, Active Directory - Password, and Active Directory - Integrated are all supported.

        For MFA support, please use Connect-DbaInstance.

    .PARAMETER Credential
        Windows Credential with permission to log on to the server running the SQL instance

    .PARAMETER MasterData
        Path to the data file for the Master database

        Will be ignored if SqlInstance is offline or the Offline switch is set. To override this behaviour use the Force switch. This is to ensure you understand the risk as we cannot validate the path if the instance is offline

    .PARAMETER MasterLog
        Path to the log file for the Master database

        Will be ignored if SqlInstance is offline or the Offline switch is set. To override this behaviour use the Force switch. This is to ensure you understand the risk as we cannot validate the path if the instance is offline

    .PARAMETER ErrorLog
        Path to the SQL Server error log file

        Will be ignored if SqlInstance is offline or the Offline switch is set. To override this behaviour use the Force switch. This is to ensure you understand the risk as we cannot validate the path if the instance is offline

    .PARAMETER TraceFlag
        A comma separated list of TraceFlags to be applied at SQL Server startup
        By default these will be appended to any existing trace flags set

    .PARAMETER CommandPromptStart
        Shortens startup time when starting SQL Server from the command prompt. Typically, the SQL Server Database Engine starts as a service by calling the Service Control Manager.
        Because the SQL Server Database Engine does not start as a service when starting from the command prompt

    .PARAMETER MinimalStart
        Starts an instance of SQL Server with minimal configuration. This is useful if the setting of a configuration value (for example, over-committing memory) has
        prevented the server from starting. Starting SQL Server in minimal configuration mode places SQL Server in single-user mode

    .PARAMETER MemoryToReserve
        Specifies an integer number of megabytes (MB) of memory that SQL Server will leave available for memory allocations within the SQL Server process,
        but outside the SQL Server memory pool. The memory outside of the memory pool is the area used by SQL Server for loading items such as extended procedure .dll files,
        the OLE DB providers referenced by distributed queries, and automation objects referenced in Transact-SQL statements. The default is 256 MB.

    .PARAMETER SingleUser
        Start Sql Server in single user mode

    .PARAMETER NoLoggingToWinEvents
        Don't use Windows Application events log

    .PARAMETER StartAsNamedInstance
        Allows you to start a named instance of SQL Server

    .PARAMETER DisableMonitoring
        Disables the following monitoring features:

        SQL Server performance monitor counters
        Keeping CPU time and cache-hit ratio statistics
        Collecting information for the DBCC SQLPERF command
        Collecting information for some dynamic management views
        Many extended-events event points

        ** Warning *\* When you use the -x startup option, the information that is available for you to diagnose performance and functional problems with SQL Server is greatly reduced.

    .PARAMETER SingleUserDetails
        The username for single user

    .PARAMETER IncreasedExtents
        Increases the number of extents that are allocated for each file in a file group.

    .PARAMETER TraceFlagOverride
        Overrides the default behaviour and replaces any existing trace flags. If not trace flags specified will just remove existing ones

    .PARAMETER StartupConfig
        Pass in a previously saved SQL Instance startup config
        using this parameter will set TraceFlagOverride to true, so existing Trace Flags will be overridden

    .PARAMETER Offline
        Setting this switch will try perform the requested actions without connect to the SQL Server Instance, this will speed things up if you know the Instance is offline.

        When working offline, path inputs (MasterData, MasterLog and ErrorLog) will be ignored, unless Force is specified

    .PARAMETER Force
        By default we test the values passed in via MasterData, MasterLog, ErrorLog

    .PARAMETER WhatIf
        Shows what would happen if the command were to run. No actions are actually performed.

    .PARAMETER Confirm
        Prompts you for confirmation before executing any changing operations within the command.

    .PARAMETER EnableException
        By default, when something goes wrong we try to catch it, interpret it and give you a friendly warning message.
        This avoids overwhelming you with "sea of red" exceptions, but is inconvenient because it basically disables advanced scripting.
        Using this switch turns this "nice by default" feature off and enables you to catch exceptions with your own try/catch.

    .NOTES
        Tags: Startup, Parameter, Configure
        Author: Stuart Moore (@napalmgram), stuart-moore.com

        Website: https://dbatools.io
        Copyright: (c) 2018 by dbatools, licensed under MIT
        License: MIT https://opensource.org/licenses/MIT

    .LINK
        https://dbatools.io/Set-DbaStartupParameter

    .EXAMPLE
        PS C:\> Set-DbaStartupParameter -SqlInstance server1\instance1 -SingleUser

        Will configure the SQL Instance server1\instance1 to startup up in Single User mode at next startup

    .EXAMPLE
        PS C:\> Set-DbaStartupParameter -SqlInstance sql2016 -IncreasedExtents

        Will configure the SQL Instance sql2016 to IncreasedExtents = True (-E)

    .EXAMPLE
        PS C:\> Set-DbaStartupParameter -SqlInstance sql2016  -IncreasedExtents:$false -WhatIf

        Shows what would happen if you attempted to configure the SQL Instance sql2016 to IncreasedExtents = False (no -E)

    .EXAMPLE
        PS C:\> Set-DbaStartupParameter -SqlInstance server1\instance1 -TraceFlag 8032,8048

        This will append Trace Flags 8032 and 8048 to the startup parameters

    .EXAMPLE
        PS C:\> Set-DbaStartupParameter -SqlInstance sql2016 -SingleUser:$false -TraceFlagOverride

        This will remove all trace flags and set SingleUser to false

    .EXAMPLE
        PS C:\> Set-DbaStartupParameter -SqlInstance server1\instance1 -SingleUser -TraceFlag 8032,8048 -TraceFlagOverride

        This will set Trace Flags 8032 and 8048 to the startup parameters, removing any existing Trace Flags

    .EXAMPLE
        PS C:\> Set-DbaStartupParameter -SqlInstance sql2016 -SingleUser:$false -TraceFlagOverride -Offline

        This will remove all trace flags and set SingleUser to false from an offline instance

    .EXAMPLE
        PS C:\> Set-DbaStartupParameter -SqlInstance sql2016 -ErrorLog c:\Sql\ -Offline

        This will attempt to change the ErrorLog path to c:\sql\. However, with the offline switch this will not happen. To force it, use the -Force switch like so:

        Set-DbaStartupParameter -SqlInstance sql2016 -ErrorLog c:\Sql\ -Offline -Force

    .EXAMPLE
        PS C:\> $StartupConfig = Get-DbaStartupParameter -SqlInstance server1\instance1
        PS C:\> Set-DbaStartupParameter -SqlInstance server1\instance1 -SingleUser -NoLoggingToWinEvents
        PS C:\> #Restart your SQL instance with the tool of choice
        PS C:\> #Do Some work
        PS C:\> Set-DbaStartupParameter -SqlInstance server1\instance1 -StartupConfig $StartupConfig
        PS C:\> #Restart your SQL instance with the tool of choice and you're back to normal

        In this example we take a copy of the existing startup configuration of server1\instance1

        We then change the startup parameters ahead of some work

        After the work has been completed, we can push the original startup parameters back to server1\instance1 and resume normal operation
#>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = "High")]
    param ([parameter(Mandatory)]
        [DbaInstanceParameter[]]$SqlInstance,
        [PSCredential]$SqlCredential,
        [PSCredential]$Credential,
        [string]$MasterData,
        [string]$MasterLog,
        [string]$ErrorLog,
        [string[]]$TraceFlag,
        [switch]$CommandPromptStart,
        [switch]$MinimalStart,
        [int]$MemoryToReserve,
        [switch]$SingleUser,
        [string]$SingleUserDetails,
        [switch]$NoLoggingToWinEvents,
        [switch]$StartAsNamedInstance,
        [switch]$DisableMonitoring,
        [switch]$IncreasedExtents,
        [switch]$TraceFlagOverride,
        [object]$StartupConfig,
        [switch]$Offline,
        [switch]$Force,
        [switch]$EnableException
    )
    begin {
        if ($Force) { $ConfirmPreference = 'none' }
        $null = Test-ElevationRequirement -ComputerName $SqlInstance[0]
    }
    process {
        if (Test-FunctionInterrupt) { return }

        foreach ($instance in $SqlInstance) {
            if (-not $Offline) {
                try {
                    $server = Connect-DbaInstance -SqlInstance $instance -SqlCredential $SqlCredential
                } catch {
                    Write-Message -Level Warning -Message "Failed to connect to $instance, will try to work with just WMI. Path options will be ignored unless Force was indicated"
                    $server = $instance
                    $Offline = $true
                }
            } else {
                Write-Message -Level Verbose -Message "Offline switch set, proceeding with just WMI"
                $server = $instance
            }

            # Get Current parameters (uses WMI) -- requires elevated session
            try {
                $currentStartup = Get-DbaStartupParameter -SqlInstance $instance -Credential $Credential -EnableException
            } catch {
                Stop-Function -Message "Unable to gather current startup parameters" -Target $instance -ErrorRecord $_
                return
            }
            $originalParamString = $currentStartup.ParameterString
            $parameterString = $null

            Write-Message -Level Verbose -Message "Original startup parameter string: $originalParamString"

            if ('StartupConfig' -in $PSBoundParameters.Keys) {
                Write-Message -Level VeryVerbose -Message "startupObject passed in"
                $newStartup = $StartupConfig
                $TraceFlagOverride = $true
            } else {
                Write-Message -Level VeryVerbose -Message "Parameters passed in"
                $newStartup = $currentStartup.PSObject.Copy()
                foreach ($param in ($PSBoundParameters.Keys | Where-Object { $_ -in ($newStartup.PSObject.Properties.Name) })) {
                    if ($PSBoundParameters.Item($param) -ne $newStartup.$param) {
                        $newStartup.$param = $PSBoundParameters.Item($param)
                    }
                }
            }

            if (!($currentStartup.SingleUser)) {

                if ($newStartup.MasterData.Length -gt 0) {
                    if ($Offline -and -not $Force) {
                        Write-Message -Level Warning -Message "Working offline, skipping untested MasterData path"
                        $parameterString += "-d$($currentStartup.MasterData);"

                    } else {
                        if ($Force) {
                            $parameterString += "-d$($newStartup.MasterData);"
                        } elseif (Test-DbaPath -SqlInstance $server -SqlCredential $SqlCredential -Path (Split-Path $newStartup.MasterData -Parent)) {
                            $parameterString += "-d$($newStartup.MasterData);"
                        } else {
                            Stop-Function -Message "Specified folder for MasterData file is not reachable by instance $instance"
                            return
                        }
                    }
                } else {
                    Stop-Function -Message "MasterData value must be provided"
                    return
                }

                if ($newStartup.ErrorLog.Length -gt 0) {
                    if ($Offline -and -not $Force) {
                        Write-Message -Level Warning -Message "Working offline, skipping untested ErrorLog path"
                        $parameterString += "-e$($currentStartup.ErrorLog);"
                    } else {
                        if ($Force) {
                            $parameterString += "-e$($newStartup.ErrorLog);"
                        } elseif (Test-DbaPath -SqlInstance $server -SqlCredential $SqlCredential -Path (Split-Path $newStartup.ErrorLog -Parent)) {
                            $parameterString += "-e$($newStartup.ErrorLog);"
                        } else {
                            Stop-Function -Message "Specified folder for ErrorLog  file is not reachable by $instance"
                            return
                        }
                    }
                } else {
                    Stop-Function -Message "ErrorLog value must be provided"
                    return
                }

                if ($newStartup.MasterLog.Length -gt 0) {
                    if ($Offline -and -not $Force) {
                        Write-Message -Level Warning -Message "Working offline, skipping untested MasterLog path"
                        $parameterString += "-l$($currentStartup.MasterLog);"
                    } else {
                        if ($Force) {
                            $parameterString += "-l$($newStartup.MasterLog);"
                        } elseif (Test-DbaPath -SqlInstance $server -SqlCredential $SqlCredential -Path (Split-Path $newStartup.MasterLog -Parent)) {
                            $parameterString += "-l$($newStartup.MasterLog);"
                        } else {
                            Stop-Function -Message "Specified folder for MasterLog  file is not reachable by $instance"
                            return
                        }
                    }
                } else {
                    Stop-Function -Message "MasterLog value must be provided."
                    return
                }
            } else {

                Write-Message -Level Verbose -Message "Instance is presently configured for single user, skipping path validation"
                if ($newStartup.MasterData.Length -gt 0) {
                    $parameterString += "-d$($newStartup.MasterData);"
                } else {
                    Stop-Function -Message "Must have a value for MasterData"
                    return
                }
                if ($newStartup.ErrorLog.Length -gt 0) {
                    $parameterString += "-e$($newStartup.ErrorLog);"
                } else {
                    Stop-Function -Message "Must have a value for Errorlog"
                    return
                }
                if ($newStartup.MasterLog.Length -gt 0) {
                    $parameterString += "-l$($newStartup.MasterLog);"
                } else {
                    Stop-Function -Message "Must have a value for MasterLog"
                    return
                }
            }

            if ($newStartup.CommandPromptStart) {
                $parameterString += "-c;"
            }
            if ($newStartup.MinimalStart) {
                $parameterString += "-f;"
            }
            if ($newStartup.MemoryToReserve -notin ($null, 0)) {
                $parameterString += "-g$($newStartup.MemoryToReserve)"
            }
            if ($newStartup.SingleUser) {
                if ($SingleUserDetails.Length -gt 0) {
                    if ($SingleUserDetails -match ' ') {
                        $SingleUserDetails = """$SingleUserDetails"""
                    }
                    $parameterString += "-m$SingleUserDetails;"
                } else {
                    $parameterString += "-m;"
                }
            }
            if ($newStartup.NoLoggingToWinEvents) {
                $parameterString += "-n;"
            }
            If ($newStartup.StartAsNamedInstance) {
                $parameterString += "-s;"
            }
            if ($newStartup.DisableMonitoring) {
                $parameterString += "-x;"
            }
            if ($newStartup.IncreasedExtents) {
                $parameterString += "-E;"
            }
            if ($newStartup.TraceFlags -eq 'None') {
                $newStartup.TraceFlags = ''
            }
            if ($TraceFlagOverride -and 'TraceFlag' -in $PSBoundParameters.Keys) {
                if ($null -ne $TraceFlag -and '' -ne $TraceFlag) {
                    $newStartup.TraceFlags = $TraceFlag -join ','
                    $parameterString += (($TraceFlag.Split(',') | ForEach-Object { "-T$_" }) -join ';') + ";"
                }
            } else {
                if ('TraceFlag' -in $PSBoundParameters.Keys) {
                    if ($null -eq $TraceFlag) { $TraceFlag = '' }
                    $oldFlags = @($currentStartup.TraceFlags) -split ',' | Where-Object { $_ -ne 'None' }
                    $newFlags = $TraceFlag
                    $newStartup.TraceFlags = (@($oldFlags) + @($newFlags) | Sort-Object -Unique) -join ','
                } elseif ($TraceFlagOverride) {
                    $newStartup.TraceFlags = ''
                } else {
                    $newStartup.TraceFlags = if ($currentStartup.TraceFlags -eq 'None') { }
                    else { $currentStartup.TraceFlags -join ',' }
                }
                If ($newStartup.TraceFlags.Length -ne 0) {
                    $parameterString += (($newStartup.TraceFlags.Split(',') | ForEach-Object { "-T$_" }) -join ';') + ";"
                }
            }

            $instanceName = $instance.InstanceName
            $displayName = "SQL Server ($instanceName)"

            $scriptBlock = {
                #Variable marked as unused by PSScriptAnalyzer
                #$instance = $args[0]
                $displayName = $args[1]
                $parameterString = $args[2]

                $wmiSvc = $wmi.Services | Where-Object { $_.DisplayName -eq $displayName }
                $wmiSvc.StartupParameters = $parameterString
                $wmiSvc.Alter()
                $wmiSvc.Refresh()
                if ($wmiSvc.StartupParameters -eq $parameterString) {
                    $true
                } else {
                    $false
                }
            }
            if ($PSCmdlet.ShouldProcess("Setting startup parameters on $instance to $parameterString")) {
                try {
                    if ($Credential) {
                        $null = Invoke-ManagedComputerCommand -ComputerName $server.ComputerName -Credential $Credential -ScriptBlock $scriptBlock -ArgumentList $server.ComputerName, $displayName, $parameterString -EnableException

                        $output = Get-DbaStartupParameter -SqlInstance $server -Credential $Credential -EnableException
                        Add-Member -Force -InputObject $output -MemberType NoteProperty -Name OriginalStartupParameters -Value $originalParamString
                    } else {
                        $null = Invoke-ManagedComputerCommand -ComputerName $server.ComputerName -scriptBlock $scriptBlock -ArgumentList $server.ComputerName, $displayName, $parameterString -EnableException

                        $output = Get-DbaStartupParameter -SqlInstance $server -EnableException
                        Add-Member -Force -InputObject $output -MemberType NoteProperty -Name OriginalStartupParameters -Value $originalParamString
                        Add-Member -Force -InputObject $output -MemberType NoteProperty -Name Notes -Value "Startup parameters changed on $instance. You must restart SQL Server for changes to take effect."
                    }
                    $output
                } catch {
                    Stop-Function -Message "Startup parameter update failed on $instance. " -Target $instance -ErrorRecord $_
                    return
                }
            }
        }
    }
}
# SIG # Begin signature block
# MIIjYAYJKoZIhvcNAQcCoIIjUTCCI00CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCAWkXPXzHOcA2kp
# ywsXzPRvs0OIdIw8IEOb7IptQpY9vqCCHVkwggUaMIIEAqADAgECAhADBbuGIbCh
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
# BgorBgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCAvW9lnkFr6sdIWg8vbnDGuJ/Xn
# mvcptUBkhusFZbGmYTANBgkqhkiG9w0BAQEFAASCAQClCHXtqwDseQRax8w/YhCn
# kI1M2b9+hjai2Bwegwb64OAhQwHuUHuwvB1FgMZyAmanBz27R7/IFYrIjRtAG6AP
# +4zaiWSWorsaSC/6QlCwCw7P0M2Nj0HghShj9gr+JCRLnNY3dm85MiDeIGSzL88+
# ocURlzZ3PbMacmi65oCbR9mGVTq1Zj9gBc2D2HIEFIC3O1huJ6Foj5unbuo1jYUC
# mdGRG/jiG4+uu3tpONGFfvdm7FaJjLtEbbRqW94AUXwPyLOuDrS3zwkYvUc9VuyJ
# jd+v0x2CgVYASIF5lcy96D9LbeR7W2v8r2dVJNW0FDy4nmRuNcCp/JPoUqFJL/i9
# oYIDIDCCAxwGCSqGSIb3DQEJBjGCAw0wggMJAgEBMHcwYzELMAkGA1UEBhMCVVMx
# FzAVBgNVBAoTDkRpZ2lDZXJ0LCBJbmMuMTswOQYDVQQDEzJEaWdpQ2VydCBUcnVz
# dGVkIEc0IFJTQTQwOTYgU0hBMjU2IFRpbWVTdGFtcGluZyBDQQIQDE1pckuU+jwq
# Sj0pB4A9WjANBglghkgBZQMEAgEFAKBpMBgGCSqGSIb3DQEJAzELBgkqhkiG9w0B
# BwEwHAYJKoZIhvcNAQkFMQ8XDTIyMTExNzA4NTczN1owLwYJKoZIhvcNAQkEMSIE
# IN3xs+eKj8SPdlItuwvDEbMf3JE3COd4dco9vZghS41mMA0GCSqGSIb3DQEBAQUA
# BIICACgZDIEX6oruClV0oEOqcITr1a8B7zcbL5s9l0lbBPaIBCT8bTA946qdCSWW
# oUCA/Adka6139a9I7Fuv8kL7oqqybAn2R/QFleDY7+m4f8OqTPVn8qj6/O05NEMC
# nw2z9dmhxT9Ay8vT+o7MBmnIJymxPGWrGSPKc8x1EVRRVDxf0qH6lXuXvZ+TOBDp
# rtdAWhm+IVCTWXXmsRXMkHaSS5wGaUjj3s/oR48KZVIRTTNu3ZnlJXf3LfzlwJzY
# 5KYxMT7GeR0rfdMayKR8BqS6tDiAmtKJnftLgkQSWioSXpwDVROQ4VvPrGrAiWCV
# yZ7OBoN6BMMa0KMcQDB7vzJw03Dr+Bl1VfvxXn+g3RW7ovlHn3+IwVXKFxT6+dsU
# 47kqWTOkQt0DvyUHXejtdmTGu6GYXK3i/AYwibXxge+DxQxIjvVcOk/tjU4R8UF1
# rZE42VPghxp0QgqfOhJo5WBpyLUFNpb6HLt982jjJ1MsP0fTZ/Lr1J6huyw4vR/x
# VoUl+RaZnExnYpAAQ9ULf/uE3EhienWUQIgsnGzek6k4pUAX+FF7Kshg51wGchtW
# m0v82UvLOuJEllcgJxKlpT8gtiGyHsyXZ3I42QCjA002hzEbwffJ35+/SG6mCor2
# NE4M3n1NszfToD9/Km0Ee1U4Q5QloZHnIjDv2inEiKhbwKjw
# SIG # End signature block
