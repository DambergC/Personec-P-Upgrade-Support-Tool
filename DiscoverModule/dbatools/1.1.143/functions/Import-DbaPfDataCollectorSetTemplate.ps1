function Import-DbaPfDataCollectorSetTemplate {
    <#
    .SYNOPSIS
        Imports a new Performance Monitor Data Collector Set Template either from the dbatools repository or a file you specify.

    .DESCRIPTION
        Imports a new Performance Monitor Data Collector Set Template either from the dbatools repository or a file you specify.
        When importing data collector sets from the local instance, Run As Admin is required.

        Note: The included counters will be added for all SQL instances on the machine by default.
        For specific instances in addition to the default, use -Instance.

        See https://msdn.microsoft.com/en-us/library/windows/desktop/aa371952 for more information

    .PARAMETER ComputerName
        The target computer. Defaults to localhost.

    .PARAMETER Credential
        Allows you to login to servers using alternative credentials. To use:

        $scred = Get-Credential, then pass $scred object to the -Credential parameter.

    .PARAMETER Path
        The path to the xml file or files.

    .PARAMETER Template
        From one or more of the templates from the dbatools repository. Press Tab to cycle through the available options.

    .PARAMETER RootPath
        Sets the base path where the subdirectories are created.

    .PARAMETER DisplayName
        Sets the display name of the data collector set.

    .PARAMETER SchedulesEnabled
        If this switch is enabled, sets a value that indicates whether the schedules are enabled.

    .PARAMETER Segment
        Sets a value that indicates whether PLA creates new logs if the maximum size or segment duration is reached before the data collector set is stopped.

    .PARAMETER SegmentMaxDuration
        Sets the duration that the data collector set can run before it begins writing to new log files.

    .PARAMETER SegmentMaxSize
        Sets the maximum size of any log file in the data collector set.

    .PARAMETER Subdirectory
        Sets a base subdirectory of the root path where the next instance of the data collector set will write its logs.

    .PARAMETER SubdirectoryFormat
        Sets flags that describe how to decorate the subdirectory name. PLA appends the decoration to the folder name. For example, if you specify plaMonthDayHour, PLA appends the current month, day, and hour values to the folder name. If the folder name is MyFile, the result could be MyFile110816.

    .PARAMETER SubdirectoryFormatPattern
        Sets a format pattern to use when decorating the folder name. Default is 'yyyyMMdd\-NNNNNN'.

    .PARAMETER Task
        Sets the name of a Task Scheduler job to start each time the data collector set stops, including between segments.

    .PARAMETER TaskRunAsSelf
        If this switch is enabled, sets a value that determines whether the task runs as the data collector set user or as the user specified in the task.

    .PARAMETER TaskArguments
        Sets the command-line arguments to pass to the Task Scheduler job specified in the IDataCollectorSet::Task property.
        See https://msdn.microsoft.com/en-us/library/windows/desktop/aa371992 for more information.

    .PARAMETER TaskUserTextArguments
        Sets the command-line arguments that are substituted for the {usertext} substitution variable in the IDataCollectorSet::TaskArguments property.
        See https://msdn.microsoft.com/en-us/library/windows/desktop/aa371993 for more information.

    .PARAMETER StopOnCompletion
        If this switch is enabled, sets a value that determines whether the data collector set stops when all the data collectors in the set are in a completed state.

    .PARAMETER Instance
        By default, the template will be applied to all instances. If you want to set specific ones in addition to the default, supply just the instance name.

    .PARAMETER WhatIf
        If this switch is enabled, no actions are performed but informational messages will be displayed that explain what would happen if the command were to run.

    .PARAMETER Confirm
        If this switch is enabled, you will be prompted for confirmation before executing any operations that change state.

    .PARAMETER EnableException
        By default, when something goes wrong we try to catch it, interpret it and give you a friendly warning message.
        This avoids overwhelming you with "sea of red" exceptions, but is inconvenient because it basically disables advanced scripting.
        Using this switch turns this "nice by default" feature off and enables you to catch exceptions with your own try/catch.

    .NOTES
        Tags: Performance, DataCollector, PerfCounter
        Author: Chrissy LeMaire (@cl), netnerds.net

        Website: https://dbatools.io
        Copyright: (c) 2018 by dbatools, licensed under MIT
        License: MIT https://opensource.org/licenses/MIT

    .LINK
        https://dbatools.io/Import-DbaPfDataCollectorSetTemplate

    .EXAMPLE
        PS C:\> Import-DbaPfDataCollectorSetTemplate -ComputerName sql2017 -Template 'Long Running Query'

        Creates a new data collector set named 'Long Running Query' from the dbatools repository on the SQL Server sql2017.

    .EXAMPLE
        PS C:\> Import-DbaPfDataCollectorSetTemplate -ComputerName sql2017 -Template 'Long Running Query' -DisplayName 'New Long running query' -Confirm

        Creates a new data collector set named "New Long Running Query" using the 'Long Running Query' template. Forces a confirmation if the template exists.

    .EXAMPLE
        PS C:\> Get-DbaPfDataCollectorSet -ComputerName sql2017 -Session db_ola_health | Remove-DbaPfDataCollectorSet
        Import-DbaPfDataCollectorSetTemplate -ComputerName sql2017 -Template db_ola_health | Start-DbaPfDataCollectorSet

        Imports a session if it exists, then recreates it using a template.

    .EXAMPLE
        PS C:\> Get-DbaPfDataCollectorSetTemplate | Out-GridView -PassThru | Import-DbaPfDataCollectorSetTemplate -ComputerName sql2017

        Allows you to select a Session template then import to an instance named sql2017.

    .EXAMPLE
        PS C:\> Import-DbaPfDataCollectorSetTemplate -ComputerName sql2017 -Template 'Long Running Query' -Instance SHAREPOINT

        Creates a new data collector set named 'Long Running Query' from the dbatools repository on the SQL Server sql2017 for both the default and the SHAREPOINT instance.

        If you'd like to remove counters for the default instance, use Remove-DbaPfDataCollectorCounter.

    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = "Low")]
    param (
        [parameter(ValueFromPipeline)]
        [DbaInstanceParameter[]]$ComputerName = $env:COMPUTERNAME,
        [PSCredential]$Credential,
        [string]$DisplayName,
        [switch]$SchedulesEnabled,
        [string]$RootPath,
        [switch]$Segment,
        [int]$SegmentMaxDuration,
        [int]$SegmentMaxSize,
        [string]$Subdirectory,
        [int]$SubdirectoryFormat = 3,
        [string]$SubdirectoryFormatPattern = 'yyyyMMdd\-NNNNNN',
        [string]$Task,
        [switch]$TaskRunAsSelf,
        [string]$TaskArguments,
        [string]$TaskUserTextArguments,
        [switch]$StopOnCompletion,
        [parameter(ValueFromPipelineByPropertyName)]
        [Alias("FullName")]
        [string[]]$Path,
        [string[]]$Template,
        [string[]]$Instance,
        [switch]$EnableException
    )
    begin {
        #Variable marked as unused by PSScriptAnalyzer
        #$metadata = Import-Clixml "$script:PSModuleRoot\bin\perfmontemplates\collectorsets.xml"

        $setscript = {
            $setname = $args[0]; $templatexml = $args[1]
            $collectorset = New-Object -ComObject Pla.DataCollectorSet
            $collectorset.SetXml($templatexml)
            $null = $collectorset.Commit($setname, $null, 0x0003) #add or modify.
            $null = $collectorset.Query($setname, $Null)
        }

        $instancescript = {
            $services = Get-Service -DisplayName *sql* | Select-Object -ExpandProperty DisplayName
            [regex]::matches($services, '(?<=\().+?(?=\))').Value | Where-Object { $PSItem -ne 'MSSQLSERVER' } | Select-Object -Unique
        }
    }
    process {


        if ((Test-Bound -ParameterName Path -Not) -and (Test-Bound -ParameterName Template -Not)) {
            Stop-Function -Message "You must specify Path or Template"
        }

        if (($Path.Count -gt 1 -or $Template.Count -gt 1) -and (Test-Bound -ParameterName Template)) {
            Stop-Function -Message "Name cannot be specified with multiple files or templates because the Session will already exist"
        }

        foreach ($computer in $ComputerName) {
            $null = Test-ElevationRequirement -ComputerName $computer -Continue

            foreach ($file in $template) {
                $templatepath = "$script:PSModuleRoot\bin\perfmontemplates\collectorsets\$file.xml"
                if ((Test-Path $templatepath)) {
                    $Path += $templatepath
                } else {
                    Stop-Function -Message "Invalid template ($templatepath does not exist)" -Continue
                }
            }

            foreach ($file in $Path) {

                if ((Test-Bound -ParameterName DisplayName -Not)) {
                    Set-Variable -Name DisplayName -Value (Get-ChildItem -Path $file).BaseName
                }

                $Name = $DisplayName

                Write-Message -Level Verbose -Message "Processing $file for $computer"

                if ((Test-Bound -ParameterName RootPath -Not)) {
                    Set-Variable -Name RootName -Value "%systemdrive%\PerfLogs\Admin\$Name"
                }

                # Perform replace
                $temp = ([System.IO.Path]::GetTempPath()).TrimEnd("").TrimEnd("\")
                $tempfile = "$temp\import-dbatools-perftemplate.xml"

                try {
                    # Get content
                    $contents = Get-Content $file -ErrorAction Stop

                    # Replace content
                    $replacements = 'RootPath', 'DisplayName', 'SchedulesEnabled', 'Segment', 'SegmentMaxDuration', 'SegmentMaxSize', 'SubdirectoryFormat', 'SubdirectoryFormatPattern', 'Task', 'TaskRunAsSelf', 'TaskArguments', 'TaskUserTextArguments', 'StopOnCompletion', 'DisplayNameUnresolved'

                    foreach ($replacement in $replacements) {
                        $phrase = "<$replacement></$replacement>"
                        $value = (Get-Variable -Name $replacement -ErrorAction SilentlyContinue).Value
                        if ($value -eq $false) {
                            $value = "0"
                        }
                        if ($value -eq $true) {
                            $value = "1"
                        }
                        $replacephrase = "<$replacement>$value</$replacement>"
                        $contents = $contents.Replace($phrase, $replacephrase)
                    }

                    # Set content
                    $null = Set-Content -Path $tempfile -Value $contents -Encoding Unicode
                    $xml = [xml](Get-Content $tempfile -ErrorAction Stop)
                    $plainxml = Get-Content $tempfile -ErrorAction Stop -Raw
                    $file = $tempfile
                } catch {
                    Stop-Function -Message "Failure" -ErrorRecord $_ -Target $file -Continue
                }
                if (-not $xml.DataCollectorSet) {
                    Stop-Function -Message "$file is not a valid Performance Monitor template document" -Continue
                }

                try {
                    Write-Message -Level Verbose -Message "Importing $file as $name "

                    if ($instance) {
                        $instances = $instance
                    } else {
                        $instances = Invoke-Command2 -ComputerName $computer -Credential $Credential -ScriptBlock $instancescript -ErrorAction Stop -Raw
                    }

                    $scriptBlock = {
                        try {
                            $results = Invoke-Command2 -ComputerName $computer -Credential $Credential -ScriptBlock $setscript -ArgumentList $Name, $plainxml -ErrorAction Stop
                            Write-Message -Level Verbose -Message " $results"
                        } catch {
                            Stop-Function -Message "Failure starting $setname on $computer" -ErrorRecord $_ -Target $computer -Continue
                        }
                    }

                    if ((Get-DbaPfDataCollectorSet -ComputerName $computer -CollectorSet $Name)) {
                        if ($Pscmdlet.ShouldProcess($computer, "CollectorSet $Name already exists. Modify?")) {
                            Invoke-Command -Scriptblock $scriptBlock
                            $output = Get-DbaPfDataCollectorSet -ComputerName $computer -CollectorSet $Name
                        }
                    } else {
                        if ($Pscmdlet.ShouldProcess($computer, "Importing collector set $Name")) {
                            Invoke-Command -Scriptblock $scriptBlock
                            $output = Get-DbaPfDataCollectorSet -ComputerName $computer -CollectorSet $Name
                        }
                    }

                    $newcollection = @()
                    foreach ($instance in $instances) {
                        $datacollector = Get-DbaPfDataCollectorSet -ComputerName $computer -CollectorSet $Name | Get-DbaPfDataCollector
                        $sqlcounters = $datacollector | Get-DbaPfDataCollectorCounter | Where-Object { $_.Name -match 'sql.*\:' -and $_.Name -notmatch 'sqlclient' } | Select-Object -ExpandProperty Name

                        foreach ($counter in $sqlcounters) {
                            $split = $counter.Split(":")
                            $firstpart = switch ($split[0]) {
                                'SQLServer' { 'MSSQL' }
                                '\SQLServer' { '\MSSQL' }
                                default { $split[0] }
                            }
                            $secondpart = $split[-1]
                            $finalcounter = "$firstpart`$$instance`:$secondpart"
                            $newcollection += $finalcounter
                        }
                    }

                    if ($newcollection.Count) {
                        if ($Pscmdlet.ShouldProcess($computer, "Adding $($newcollection.Count) additional counters")) {
                            $null = Add-DbaPfDataCollectorCounter -InputObject $datacollector -Counter $newcollection
                        }
                    }

                    Remove-Item $tempfile -ErrorAction SilentlyContinue
                    $output
                } catch {
                    Stop-Function -Message "Failure" -ErrorRecord $_ -Target $store -Continue
                }
            }
        }
    }
}
# SIG # Begin signature block
# MIIjYAYJKoZIhvcNAQcCoIIjUTCCI00CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCDaNSPD53Mi/pQl
# Z0Ht3JV++49MU1QjGWoGmDuXuXs/PaCCHVkwggUaMIIEAqADAgECAhADBbuGIbCh
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
# BgorBgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCA3BhKx98aAbLZAfDPHKFa1Vv1d
# HGNEk5F4mPMdKFaOTTANBgkqhkiG9w0BAQEFAASCAQB4wOt2R+bVkODDpFhgDYPA
# uoqwQrZ/jReutW+XWAP6Z4K4lQ3Gqpv3/WLRYgs1+ITSm6MbRr1issDqsO88Zwc+
# mkp/S4NfbmVWj4IXwyHLRp0QMPlsPk2iysdLGbe8iCsCdaz6QXpi7I+Ns6SWC+NK
# qNT2nbXQ/2ZIUrFd8D7dob7Egou9NpsyKV7LPzdZoGI6TCRGoGfCMiBveY9RZmM0
# Dz7YwCh/xtAXigJj+HB/gNtGGD8gs/0omauP/RsB0iFuDrsgmIxNn3ZO2rmdGcUq
# 5mIXLlUr8fGFrV/WAAsHFG23dOF1vWjoCehPu/4O8qqKrZBfFOrbo4vKYb5nQcir
# oYIDIDCCAxwGCSqGSIb3DQEJBjGCAw0wggMJAgEBMHcwYzELMAkGA1UEBhMCVVMx
# FzAVBgNVBAoTDkRpZ2lDZXJ0LCBJbmMuMTswOQYDVQQDEzJEaWdpQ2VydCBUcnVz
# dGVkIEc0IFJTQTQwOTYgU0hBMjU2IFRpbWVTdGFtcGluZyBDQQIQDE1pckuU+jwq
# Sj0pB4A9WjANBglghkgBZQMEAgEFAKBpMBgGCSqGSIb3DQEJAzELBgkqhkiG9w0B
# BwEwHAYJKoZIhvcNAQkFMQ8XDTIyMTExNzA4NTYzNlowLwYJKoZIhvcNAQkEMSIE
# IGr1IJIbwsqg9vIWqVQ96V/osrxwMkDmqvT6tmemgSPoMA0GCSqGSIb3DQEBAQUA
# BIICACXmtIQVtpYTkC2BBQuuUGdG/JxvGaoEEBhKrT/hbrOD0QX7Udf92zXDfbsK
# oShRVdEhi9DRl9VwPfnRFSZPIRWOseI2liKV48eQ2ZVkhYy0Iwoz+p+8hzE5Jnwk
# srzQ2R0AtFcay9PE5vrg/LNCX0GA9GUmgqtHrMFM+mCfTM7ckpdj/SHMG9lpwYOw
# cFpleeP3w1/KxghZEvKdt70e/esTlx8o8MCHVdV1uYIL2HMmB1D2719jDyGYXi9k
# 8tvLPsf+SkWUhSclfri6Ehy9KQK5cc88hBKFeW+oqFcO1hyieMcIFhFOmB4jmcPb
# tVyqRuF0dWFdCY9I7durkcapqQesLBheHmORI1dLfXpWcaUp5Z2FaZC8l6+Qktkq
# eXYohGgjRyPaG3ewtMuRlvGLq7u3cPiK4SxQri5byYEfk64m8xADtoh4WhaImZJc
# eTFyRU2BIc5+jjVwF7QqKGFvCsHsuiso8UEGoIK+mmoMw4aM985F/vZn5HmqZtV8
# L5kf52hwKYM+ZtQxaujkwAS+cfhsT2PPsdurL1VrnDFEnExpR9zftrfpTSvhIAP4
# 7gNAaKrfyJw0Nm0dh07v2boRvEe278O1m+3xZ044SezpvVEXtPujlZ2tkcTcY7MC
# Nk8qaZpvvrBQaBNV9JnL84t2PYMOU1SJLAk2naezyGidUvjU
# SIG # End signature block
