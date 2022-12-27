function Invoke-DbaPfRelog {
    <#
    .SYNOPSIS
        Pipeline-compatible wrapper for the relog command which is available on modern Windows platforms.

    .DESCRIPTION
        Pipeline-compatible wrapper for the relog command. Relog is useful for converting Windows Perfmon.

        Extracts performance counters from performance counter logs into other formats,
        such as text-TSV (for tab-delimited text), text-CSV (for comma-delimited text), binary-BIN, or SQL.

        `relog "C:\PerfLogs\Admin\System Correlation\WORKSTATIONX_20180112-000001\DataCollector01.blg" -o C:\temp\foo.csv -f tsv`

        If you find any input hangs, please send us the output so we can accommodate for it then use -Raw for an immediate solution.

    .PARAMETER Path
        Specifies the pathname of an existing performance counter log or performance counter path. You can specify multiple input files.

    .PARAMETER Destination
        Specifies the pathname of the output file or SQL database where the counters will be written. Defaults to the same directory as the source.

    .PARAMETER Type
        The output format. Defaults to tsv. Options include tsv, csv, bin, and sql.

        For a SQL database, the output file specifies the DSN!counter_log. You can specify the database location by using the ODBC manager to configure the DSN (Database System Name).

        For more information, read here: https://technet.microsoft.com/en-us/library/bb490958.aspx

    .PARAMETER Append
        If this switch is enabled, output will be appended to the specified file instead of overwriting. This option does not apply to SQL format where the default is always to append.

    .PARAMETER AllowClobber
        If this switch is enabled, the destination file will be overwritten if it exists.

    .PARAMETER PerformanceCounter
        Specifies the performance counter path to log.

    .PARAMETER PerformanceCounterPath
        Specifies the pathname of the text file that lists the performance counters to be included in a relog file. Use this option to list counter paths in an input file, one per line. Default setting is all counters in the original log file are relogged.

    .PARAMETER Interval
        Specifies sample intervals in "n" records. Includes every nth data point in the relog file. Default is every data point.

    .PARAMETER BeginTime
        This is is Get-Date object and we format it for you.

    .PARAMETER EndTime
        Specifies end time for copying last record from the input file. This is is Get-Date object and we format it for you.

    .PARAMETER ConfigPath
        Specifies the pathname of the settings file that contains command-line parameters.

    .PARAMETER Summary
        If this switch is enabled, the performance counters and time ranges of log files specified in the input file will be displayed.

    .PARAMETER Multithread
        If this switch is enabled, processing will be done in parallel. This may speed up large batches or large files.

    .PARAMETER AllTime
        If this switch is enabled and a datacollector or datacollectorset is passed in via the pipeline, collects all logs, not just the latest.

    .PARAMETER Raw
        If this switch is enabled, the results of the DOS command instead of Get-ChildItem will be displayed. This does not run in parallel.

    .PARAMETER InputObject
        Accepts the output of Get-DbaPfDataCollector and Get-DbaPfDataCollectorSet as input via the pipeline.

    .PARAMETER EnableException
        By default, when something goes wrong we try to catch it, interpret it and give you a friendly warning message.
        This avoids overwhelming you with "sea of red" exceptions, but is inconvenient because it basically disables advanced scripting.
        Using this switch turns this "nice by default" feature off and enables you to catch exceptions with your own try/catch.

    .NOTES
        Tags: Performance, DataCollector, PerfCounter, Relog
        Author: Chrissy LeMaire (@cl), netnerds.net

        Website: https://dbatools.io
        Copyright: (c) 2018 by dbatools, licensed under MIT
        License: MIT https://opensource.org/licenses/MIT

    .LINK
        https://dbatools.io/Invoke-DbaPfRelog

    .EXAMPLE
        PS C:\> Invoke-DbaPfRelog -Path C:\temp\perfmon.blg

        Creates C:\temp\perfmon.tsv from C:\temp\perfmon.blg.

    .EXAMPLE
        PS C:\> Invoke-DbaPfRelog -Path C:\temp\perfmon.blg -Destination C:\temp\a\b\c

        Creates the temp, a, and b directories if needed, then generates c.tsv (tab separated) from C:\temp\perfmon.blg.

        Returns the newly created file as a file object.

    .EXAMPLE
        PS C:\> Get-DbaPfDataCollectorSet -ComputerName sql2016 | Get-DbaPfDataCollector | Invoke-DbaPfRelog -Destination C:\temp\perf

        Creates C:\temp\perf if needed, then generates computername-datacollectorname.tsv (tab separated) from the latest logs of all data collector sets on sql2016. This destination format was chosen to avoid naming conflicts with piped input.

    .EXAMPLE
        PS C:\> Invoke-DbaPfRelog -Path C:\temp\perfmon.blg -Destination C:\temp\a\b\c -Raw
        >> [Invoke-DbaPfRelog][21:21:35] relog "C:\temp\perfmon.blg" -f csv -o C:\temp\a\b\c
        >> Input
        >> ----------------
        >> File(s):
        >> C:\temp\perfmon.blg (Binary)
        >> Begin:    1/13/2018 5:13:23
        >> End:      1/13/2018 14:29:55
        >> Samples:  2227
        >> 100.00%
        >> Output
        >> ----------------
        >> File:     C:\temp\a\b\c.csv
        >> Begin:    1/13/2018 5:13:23
        >> End:      1/13/2018 14:29:55
        >> Samples:  2227
        >> The command completed successfully.

        Creates the temp, a, and b directories if needed, then generates c.tsv (tab separated) from C:\temp\perfmon.blg then outputs the raw results of the relog command.

    .EXAMPLE
        PS C:\> Invoke-DbaPfRelog -Path 'C:\temp\perflog with spaces.blg' -Destination C:\temp\a\b\c -Type csv -BeginTime ((Get-Date).AddDays(-30)) -EndTime ((Get-Date).AddDays(-1))

        Creates the temp, a, and b directories if needed, then generates c.csv (comma separated) from C:\temp\perflog with spaces.blg', starts 30 days ago and ends one day ago.

    .EXAMPLE
        PS C:\> $servers | Get-DbaPfDataCollectorSet | Get-DbaPfDataCollector | Invoke-DbaPfRelog -Multithread -AllowClobber

        Relogs latest data files from all collectors within the servers listed in $servers.

    .EXAMPLE
        PS C:\> Get-DbaPfDataCollector -Collector DataCollector01 | Invoke-DbaPfRelog -AllowClobber -AllTime

        Relogs all the log files from the DataCollector01 on the local computer and allows overwrite.

    #>
    [CmdletBinding()]
    param (
        [parameter(ValueFromPipelineByPropertyName)]
        [Alias("FullName")]
        [string[]]$Path,
        [string]$Destination,
        [ValidateSet("tsv", "csv", "bin", "sql")]
        [string]$Type = "tsv",
        [switch]$Append,
        [switch]$AllowClobber,
        [string[]]$PerformanceCounter,
        [string]$PerformanceCounterPath,
        [int]$Interval,
        [datetime]$BeginTime,
        [datetime]$EndTime,
        [string]$ConfigPath,
        [switch]$Summary,
        [parameter(ValueFromPipeline)]
        [object[]]$InputObject,
        [switch]$Multithread,
        [switch]$AllTime,
        [switch]$Raw,
        [switch]$EnableException
    )
    begin {


        if (Test-Bound -ParameterName BeginTime) {
            $script:beginstring = ($BeginTime -f 'M/d/yyyy hh:mm:ss' | Out-String).Trim()
        }
        if (Test-Bound -ParameterName EndTime) {
            $script:endstring = ($EndTime -f 'M/d/yyyy hh:mm:ss' | Out-String).Trim()
        }

        $allpaths = @()
        $allpaths += $Path

        # to support multithreading
        if (Test-Bound -ParameterName Destination) {
            $script:destinationset = $true
            $originaldestination = $Destination
        } else {
            $script:destinationset = $false
        }
    }
    process {
        if ($Append -and $Type -ne "bin") {
            Stop-Function -Message "Append can only be used with -Type bin." -Target $Path
            return
        }

        if ($InputObject) {
            foreach ($object in $InputObject) {
                # DataCollectorSet
                if ($object.OutputLocation -and $object.RemoteOutputLocation) {
                    $instance = [dbainstance]$object.ComputerName

                    if (-not $AllTime) {
                        if ($instance.IsLocalHost) {
                            $allpaths += (Get-ChildItem -Recurse -Path $object.LatestOutputLocation -Include *.blg -ErrorAction SilentlyContinue).FullName
                        } else {
                            $allpaths += (Get-ChildItem -Recurse -Path $object.RemoteLatestOutputLocation -Include *.blg -ErrorAction SilentlyContinue).FullName
                        }
                    } else {
                        if ($instance.IsLocalHost) {
                            $allpaths += (Get-ChildItem -Recurse -Path $object.OutputLocation -Include *.blg -ErrorAction SilentlyContinue).FullName
                        } else {
                            $allpaths += (Get-ChildItem -Recurse -Path $object.RemoteOutputLocation -Include *.blg -ErrorAction SilentlyContinue).FullName
                        }
                    }


                    $script:perfmonobject = $true
                }
                # DataCollector
                if ($object.LatestOutputLocation -and $object.RemoteLatestOutputLocation) {
                    $instance = [dbainstance]$object.ComputerName

                    if (-not $AllTime) {
                        if ($instance.IsLocalHost) {
                            $allpaths += (Get-ChildItem -Recurse -Path $object.LatestOutputLocation -Include *.blg -ErrorAction SilentlyContinue).FullName
                        } else {
                            $allpaths += (Get-ChildItem -Recurse -Path $object.RemoteLatestOutputLocation -Include *.blg -ErrorAction SilentlyContinue).FullName
                        }
                    } else {
                        if ($instance.IsLocalHost) {
                            $allpaths += (Get-ChildItem -Recurse -Path (Split-Path $object.LatestOutputLocation) -Include *.blg -ErrorAction SilentlyContinue).FullName
                        } else {
                            $allpaths += (Get-ChildItem -Recurse -Path (Split-Path $object.RemoteLatestOutputLocation) -Include *.blg -ErrorAction SilentlyContinue).FullName
                        }
                    }
                    $script:perfmonobject = $true
                }
            }
        }
    }

    # Gotta collect all the paths first then process them otherwise there may be duplicates
    end {
        $allpaths = $allpaths | Where-Object { $_ -match '.blg' } | Select-Object -Unique

        if (-not $allpaths) {
            Stop-Function -Message "Could not find matching .blg files" -Target $file -Continue
            return
        }

        $scriptBlock = {
            if ($args) {
                $file = $args
            } else {
                $file = $psitem
            }
            $item = Get-ChildItem -Path $file -ErrorAction SilentlyContinue

            if ($null -eq $item) {
                Stop-Function -Message "$file does not exist." -Target $file -Continue
                return
            }

            if (-not $script:destinationset -and $file -match "C\:\\.*Admin.*") {
                $null = Test-ElevationRequirement -ComputerName $env:COMPUTERNAME -Continue
            }

            if ($script:destinationset -eq $false -and -not $Append) {
                $Destination = Join-Path (Split-Path $file) $item.BaseName
            }

            if ($Destination -and $Destination -notmatch "\." -and -not $Append -and $script:perfmonobject) {
                # if destination is set, then it needs a different name
                if ($script:destinationset -eq $true) {
                    if ($file -match "\:") {
                        $computer = $env:COMPUTERNAME
                    } else {
                        $computer = $file.Split("\")[2]
                    }
                    # Avoid naming conflicts
                    $timestamp = Get-Date -format yyyyMMddHHmmfff
                    $Destination = Join-Path $originaldestination "$computer - $($item.BaseName) - $timestamp"
                }
            }

            $params = @("`"$file`"")

            if ($Append) {
                $params += "-a"
            }

            if ($PerformanceCounter) {
                $parsedcounters = $PerformanceCounter -join " "
                $params += "-c `"$parsedcounters`""
            }

            if ($PerformanceCounterPath) {
                $params += "-cf `"$PerformanceCounterPath`""
            }

            $params += "-f $Type"

            if ($Interval) {
                $params += "-t $Interval"
            }

            if ($Destination) {
                $params += "-o `"$Destination`""
            }

            if ($script:beginstring) {
                $params += "-b $script:beginstring"
            }

            if ($script:endstring) {
                $params += "-e $script:endstring"
            }

            if ($ConfigPath) {
                $params += "-config $ConfigPath"
            }

            if ($Summary) {
                $params += "-q"
            }


            if (-not ($Destination.StartsWith("DSN"))) {
                $outputisfile = $true
            } else {
                $outputisfile = $false
            }

            if ($outputisfile) {
                if ($Destination) {
                    $dir = Split-Path $Destination
                    if (-not (Test-Path -Path $dir)) {
                        try {
                            $null = New-Item -ItemType Directory -Path $dir -ErrorAction Stop
                        } catch {
                            Stop-Function -Message "Failure" -ErrorRecord $_ -Target $Destination -Continue
                        }
                    }

                    if ((Test-Path $Destination) -and -not $Append -and ((Get-Item $Destination) -isnot [System.IO.DirectoryInfo])) {
                        if ($AllowClobber) {
                            try {
                                Remove-Item -Path "$Destination" -ErrorAction Stop
                            } catch {
                                Stop-Function -Message "Failure" -ErrorRecord $_ -Continue
                            }
                        } else {
                            if ($Type -eq "bin") {
                                Stop-Function -Message "$Destination exists. Use -AllowClobber to overwrite or -Append to append." -Continue
                            } else {
                                Stop-Function -Message "$Destination exists. Use -AllowClobber to overwrite." -Continue
                            }
                        }
                    }

                    if ((Test-Path "$Destination.$type") -and -not $Append) {
                        if ($AllowClobber) {
                            try {
                                Remove-Item -Path "$Destination.$type" -ErrorAction Stop
                            } catch {
                                Stop-Function -Message "Failure" -ErrorRecord $_ -Continue
                            }
                        } else {
                            if ($Type -eq "bin") {
                                Stop-Function -Message "$("$Destination.$type") exists. Use -AllowClobber to overwrite or -Append to append." -Continue
                            } else {
                                Stop-Function -Message "$("$Destination.$type") exists. Use -AllowClobber to overwrite." -Continue
                            }
                        }
                    }
                }
            }

            $arguments = ($params -join " ")

            try {
                if ($Raw) {
                    Write-Message -Level Output -Message "relog $arguments"
                    cmd /c "relog $arguments"
                } else {
                    Write-Message -Level Verbose -Message "relog $arguments"
                    $scriptBlock = {
                        $output = (cmd /c "relog $arguments" | Out-String).Trim()

                        if ($output -notmatch "Success") {
                            Stop-Function -Continue -Message $output.Trim("Input")
                        } else {
                            Write-Message -Level Verbose -Message "$output"
                            $array = $output -Split [environment]::NewLine
                            $files = $array | Select-String "File:"

                            foreach ($rawfile in $files) {
                                $rawfile = $rawfile.ToString().Replace("File:", "").Trim()
                                $gcierror = $null
                                Get-ChildItem $rawfile -ErrorAction SilentlyContinue -ErrorVariable gcierror | Add-Member -MemberType NoteProperty -Name RelogFile -Value $true -PassThru -ErrorAction Ignore
                                if ($gcierror) {
                                    Write-Message -Level Verbose -Message "$gcierror"
                                }
                            }
                        }
                    }
                    Invoke-Command -ScriptBlock $scriptBlock
                }
            } catch {
                Stop-Function -Message "Failure" -ErrorRecord $_ -Target $path
            }
        }

        if ($Multithread) {
            $allpaths | Invoke-Parallel -ImportVariables -ImportModules -ScriptBlock $scriptBlock -ErrorAction SilentlyContinue -ErrorVariable parallelerror
            if ($parallelerror) {
                Write-Message -Level Verbose -Message "$parallelerror"
            }
        } else {
            foreach ($file in $allpaths) { Invoke-Command -ScriptBlock $scriptBlock -ArgumentList $file }
        }
    }
}
# SIG # Begin signature block
# MIIjYAYJKoZIhvcNAQcCoIIjUTCCI00CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCB2DrD/4n+/7EEr
# PnAiQlMn7gaAIuxnFH7m6+vnHY9J6qCCHVkwggUaMIIEAqADAgECAhADBbuGIbCh
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
# BgorBgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCBBMSBibot3/Adl/rXylXNE9fyi
# KX/cUZ1pZudVpVa8DTANBgkqhkiG9w0BAQEFAASCAQA4s2kTvoafUJOwxaGsmx7d
# 6/S9tvmjFHcXRPS32LOSpZ8s0PrCEFrfU+Gl6R8V7socyUsgIKxT88rDxQBJU98S
# RmvdBwRbNqeoMHcYlzNd7467MALM51ixV4q/OovXePZ5BFAW9Qv/RHFAi7GDiYIY
# d9G2emFHGfXAtdw5WHNyABvxVFz3dyp6nvTtTgHY1STYvPowMGTrAYrAmGG0zKes
# 6iknMPxl+qRGFI85ClPjm39+VInoOHz3KwHX9AKzK2a6fAIxth33xiU+qcmHZeMB
# lpPUxdDUxVxVpAu7lQHh9XqzWBLQYhfLn7Ej4y06gkGweVj0lW5w0Of/ID89RSPY
# oYIDIDCCAxwGCSqGSIb3DQEJBjGCAw0wggMJAgEBMHcwYzELMAkGA1UEBhMCVVMx
# FzAVBgNVBAoTDkRpZ2lDZXJ0LCBJbmMuMTswOQYDVQQDEzJEaWdpQ2VydCBUcnVz
# dGVkIEc0IFJTQTQwOTYgU0hBMjU2IFRpbWVTdGFtcGluZyBDQQIQDE1pckuU+jwq
# Sj0pB4A9WjANBglghkgBZQMEAgEFAKBpMBgGCSqGSIb3DQEJAzELBgkqhkiG9w0B
# BwEwHAYJKoZIhvcNAQkFMQ8XDTIyMTExNzA4NTY0NVowLwYJKoZIhvcNAQkEMSIE
# IE4+BTie9zNfaBeiLB2hgGr4ZIKqDs3CSAAElSwxZLYjMA0GCSqGSIb3DQEBAQUA
# BIICABRNOvdz6kgyUW/VTk1PwZwgqM2uIPTuUGxzRZ971hwhWfrfA68Xw6XBDTcH
# FB0DnryeysouW9KcAL46L3WYXeILxi69L1K2p0KjNsQ4UaIioholLnPNMTENsfDv
# iL6bC2/zlCd9F5QLGhDxSwJbc2jJIkfCFxizdSBoYXwo2TP0B4HXpNes/8/7l0AY
# 5glxBhObvXbjLXZjHlmwFSdcDVTBmEvF1BP7KMWqYAlG8CguQFjxn2ryrtZtzkYa
# TTYfVrQxO5CYbEJstPpb6oQWjBDXa4Bb73WhL2sQQa2CbG0Zm+0WcI9M2WCed1o2
# qQuPbH6tZ8kcxDl2mRhLxWYo8aQGycenTC0B9MmUdiQ3uUOVx4Qcv9a2qGyn0D8U
# FLZbz1aTlT/GnzCLKOftkxXKQ0m8cZ2W+nmMfFH+uAnhWygDg4wPZPMw/O6oryQo
# mWeHsc9iVYKgX8/qCfy7V1ItfkbEI9o3ojPK9dt9YNNibe1j9aa4KQ+gVRtHmJMZ
# K35cJUpJIOI3tIyHG51Nf3MrHrzjsQDwlxTK4kihE/NRLOv/7D5BYBA9A4KMpwMA
# j8/gss1lT1dw6laC/XKMumLtV3DkkInF2L5DAIejXd2tV+lBIaXGVFvJVYuAIpG3
# Ukg4Cm3i0PryBa0IStas6X8D/bf76VngI6Gw8sPfYeu8HTve
# SIG # End signature block
