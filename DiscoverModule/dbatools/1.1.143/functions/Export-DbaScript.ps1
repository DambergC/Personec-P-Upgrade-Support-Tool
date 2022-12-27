function Export-DbaScript {
    <#
    .SYNOPSIS
        Exports scripts from SQL Management Objects (SMO)

    .DESCRIPTION
        Exports scripts from SQL Management Objects

    .PARAMETER InputObject
        A SQL Management Object such as the one returned from Get-DbaLogin

    .PARAMETER Path
        Specifies the directory where the file or files will be exported.
        Will default to Path.DbatoolsExport Configuration entry

    .PARAMETER FilePath
        Specifies the full file path of the output file.

    .PARAMETER Encoding
        Specifies the file encoding. The default is UTF8.

        Valid values are:
        -- ASCII: Uses the encoding for the ASCII (7-bit) character set.
        -- BigEndianUnicode: Encodes in UTF-16 format using the big-endian byte order.
        -- Byte: Encodes a set of characters into a sequence of bytes.
        -- String: Uses the encoding type for a string.
        -- Unicode: Encodes in UTF-16 format using the little-endian byte order.
        -- UTF7: Encodes in UTF-7 format.
        -- UTF8: Encodes in UTF-8 format.
        -- Unknown: The encoding type is unknown or invalid. The data can be treated as binary.

    .PARAMETER Passthru
        Output script to console

    .PARAMETER ScriptingOptionsObject
        An SMO Scripting Object that can be used to customize the output - see New-DbaScriptingOption
        Options set in the ScriptingOptionsObject may override other parameter values

    .PARAMETER BatchSeparator
        Specifies the Batch Separator to use. Uses the value from configuration Formatting.BatchSeparator by default. This is normally "GO"

    .PARAMETER NoPrefix
        Do not include a Prefix

    .PARAMETER WhatIf
        Shows what would happen if the command were to run. No actions are actually performed

    .PARAMETER NoClobber
        Do not overwrite file

    .PARAMETER Append
        Append to file

    .PARAMETER Confirm
        Prompts you for confirmation before executing any changing operations within the command

    .PARAMETER EnableException
        By default, when something goes wrong we try to catch it, interpret it and give you a friendly warning message.
        This avoids overwhelming you with "sea of red" exceptions, but is inconvenient because it basically disables advanced scripting.
        Using this switch turns this "nice by default" feature off and enables you to catch exceptions with your own try/catch.

    .NOTES
        Tags: Migration, Backup, Export
        Author: Chrissy LeMaire (@cl), netnerds.net

        Website: https://dbatools.io
        Copyright: (c) 2018 by dbatools, licensed under MIT
        License: MIT https://opensource.org/licenses/MIT

    .LINK
        https://dbatools.io/Export-DbaScript

    .EXAMPLE
        PS C:\> Get-DbaAgentJob -SqlInstance sql2016 | Export-DbaScript

        Exports all jobs on the SQL Server sql2016 instance using a trusted connection - automatically determines filename based on the Path.DbatoolsExport configuration setting, current time and server name.

    .EXAMPLE
        PS C:\> Get-DbaAgentJob -SqlInstance sql2016 | Export-DbaScript -FilePath C:\temp\export.sql -Append

        Exports all jobs on the SQL Server sql2016 instance using a trusted connection - Will append the output to the file C:\temp\export.sql if it already exists
        Inclusion of Batch Separator in script depends on the configuration s not include Batch Separator and will not compile

    .EXAMPLE
        PS C:\> Get-DbaDbTable -SqlInstance sql2016 -Database MyDatabase -Table 'dbo.Table1', 'dbo.Table2' -SqlCredential sqladmin | Export-DbaScript -FilePath C:\temp\export.sql

        Exports only script for 'dbo.Table1' and 'dbo.Table2' in MyDatabase to C:temp\export.sql and uses the SQL login "sqladmin" to login to sql2016

    .EXAMPLE
        PS C:\> Get-DbaAgentJob -SqlInstance sql2016 -Job syspolicy_purge_history, 'Hourly Log Backups' -SqlCredential sqladmin | Export-DbaScript -FilePath C:\temp\export.sql -NoPrefix

        Exports only syspolicy_purge_history and 'Hourly Log Backups' to C:temp\export.sql and uses the SQL login "sqladmin" to login to sql2016
        Suppress the output of a Prefix

    .EXAMPLE
        PS C:\> $options = New-DbaScriptingOption
        PS C:\> $options.ScriptSchema = $true
        PS C:\> $options.IncludeDatabaseContext  = $true
        PS C:\> $options.IncludeHeaders = $false
        PS C:\> $Options.NoCommandTerminator = $false
        PS C:\> $Options.ScriptBatchTerminator = $true
        PS C:\> $Options.AnsiFile = $true
        PS C:\> Get-DbaAgentJob -SqlInstance sql2016 -Job syspolicy_purge_history, 'Hourly Log Backups' -SqlCredential sqladmin | Export-DbaScript -FilePath C:\temp\export.sql -ScriptingOptionsObject $options

        Exports only syspolicy_purge_history and 'Hourly Log Backups' to C:temp\export.sql and uses the SQL login "sqladmin" to login to sql2016
        Uses Scripting options to ensure Batch Terminator is set

    .EXAMPLE
        PS C:\> Get-DbaAgentJob -SqlInstance sql2014 | Export-DbaScript -Passthru | ForEach-Object { $_.Replace('sql2014','sql2016') } | Set-Content -Path C:\temp\export.sql

        Exports jobs and replaces all instances of the servername "sql2014" with "sql2016" then writes to C:\temp\export.sql

    .EXAMPLE
        PS C:\> $options = New-DbaScriptingOption
        PS C:\> $options.ScriptSchema = $true
        PS C:\> $options.IncludeDatabaseContext  = $true
        PS C:\> $options.IncludeHeaders = $false
        PS C:\> $Options.NoCommandTerminator = $false
        PS C:\> $Options.ScriptBatchTerminator = $true
        PS C:\> $Options.AnsiFile = $true
        PS C:\> $Databases = Get-DbaDatabase -SqlInstance sql2016 -ExcludeDatabase master, model, msdb, tempdb
        PS C:\> foreach ($db in $Databases) {
        >>        Export-DbaScript -InputObject $db -FilePath C:\temp\export.sql -Append -Encoding UTF8 -ScriptingOptionsObject $options -NoPrefix
        >> }

        Exports Script for each database on sql2016 excluding system databases
        Uses Scripting options to ensure Batch Terminator is set
        Will append the output to the file C:\temp\export.sql if it already exists

    #>
    [CmdletBinding(SupportsShouldProcess)]
    param (
        [parameter(Mandatory, ValueFromPipeline)]
        [object[]]$InputObject,
        [Alias("ScriptingOptionObject")]
        [Microsoft.SqlServer.Management.Smo.ScriptingOptions]$ScriptingOptionsObject,
        [string]$Path = (Get-DbatoolsConfigValue -FullName 'Path.DbatoolsExport'),
        [Alias("OutFile", "FileName")]
        [string]$FilePath,
        [ValidateSet('ASCII', 'BigEndianUnicode', 'Byte', 'String', 'Unicode', 'UTF7', 'UTF8', 'Unknown')]
        [string]$Encoding = 'UTF8',
        [string]$BatchSeparator = (Get-DbatoolsConfigValue -FullName 'Formatting.BatchSeparator'),
        [switch]$NoPrefix,
        [switch]$Passthru,
        [switch]$NoClobber,
        [switch]$Append,
        [switch]$EnableException
    )
    begin {
        $null = Test-ExportDirectory -Path $Path
        if ($IsLinux -or $IsMacOs) {
            $executingUser = $env:USER
        } else {
            $executingUser = [Security.Principal.WindowsIdentity]::GetCurrent().Name
        }
        $commandName = $MyInvocation.MyCommand.Name
        $prefixArray = @()

        # If -Append or -Append:$true is passed in then set these variables. Otherwise, the caller has specified -Append:$false or not specified -Append and they want to overwrite the file if it already exists.
        $appendToScript = $false
        if ($Append) {
            $appendToScript = $true
        }

        if ($ScriptingOptionsObject) {
            # Check if BatchTerminator is consistent
            if (($($ScriptingOptionsObject.ScriptBatchTerminator)) -and ([string]::IsNullOrWhitespace($BatchSeparator))) {
                Write-Message -Level Warning -Message "Setting ScriptBatchTerminator to true and also having BatchSeperarator as an empty or null string may produce unintended results."
            }
            # Save those properties that will be changed in the process block so that they can be reset at the end
            $soAppendToFile = $ScriptingOptionsObject.AppendToFile
            $soToFileOnly = $ScriptingOptionsObject.ToFileOnly
            $soFileName = $ScriptingOptionsObject.FileName
        }

        $eol = [System.Environment]::NewLine
    }

    process {
        if (Test-FunctionInterrupt) { return }
        foreach ($object in $InputObject) {

            $typename = $object.GetType().ToString()

            if ($typename.StartsWith('Microsoft.SqlServer.')) {
                $shorttype = $typename.Split(".")[-1]
            } else {
                Stop-Function -Message "InputObject is of type $typename which is not a SQL Management Object. Only SMO objects are supported." -Category InvalidData -Target $object -Continue
            }

            if ($shorttype -in "LinkedServer", "Credential", "Login") {
                Write-Message -Level Warning -Message "Support for $shorttype is limited at this time. No passwords, hashed or otherwise, will be exported if they exist."
            }

            # Just gotta add the stuff that Nic Cain added to his script

            if ($shorttype -eq "Configuration") {
                Write-Message -Level Warning -Message "Support for $shorttype is limited at this time."
            }

            if ($shorttype -eq "AvailabilityGroup") {
                Write-Message -Level Verbose -Message "Invoking .Script() as a workaround for https://github.com/dataplat/dbatools/issues/5913."
                try {
                    $null = $InputObject.Script()
                } catch {
                    Write-Message -Level Verbose -Message "Invoking .Script() failed: $_"
                }
            }

            # Find the server object to pass on to the function
            $parent = $object.parent

            do {
                if ($parent.Urn.Type -ne "Server") {
                    $parent = $parent.Parent
                }
            }
            until (($parent.Urn.Type -eq "Server") -or (-not $parent))

            if (-not $parent -and -not (Get-Member -InputObject $object -Name ScriptCreate) ) {
                Stop-Function -Message "Failed to find valid SMO server object in input: $object." -Category InvalidData -Target $object -Continue
            }

            try {
                $server = $parent
                $serverName = $server.Name.Replace('\', '$')

                $scripter = New-Object Microsoft.SqlServer.Management.Smo.Scripter $server
                if ($ScriptingOptionsObject) {
                    $scripter.Options = $ScriptingOptionsObject
                    $scriptBatchTerminator = $ScriptingOptionsObject.ScriptBatchTerminator
                }

                if (-not $Passthru) {
                    $scriptPath = Get-ExportFilePath -Path $PSBoundParameters.Path -FilePath $PSBoundParameters.FilePath -Type sql -ServerName $serverName
                } else {
                    $scriptPath = 'Console'
                }

                if ($NoPrefix) {
                    $prefix = $null
                } else {
                    $prefix = "/*$eol`tCreated by $executingUser using dbatools $commandName for objects on $serverName at $(Get-Date)$eol`tSee https://dbatools.io/$commandName for more information$eol*/"
                }

                if ($Passthru) {
                    if ($null -ne $prefix) {
                        $prefix | Out-String
                    }
                } else {
                    if ($prefixArray -notcontains $scriptPath) {
                        if ((Test-Path -Path $scriptPath) -and $NoClobber) {
                            Stop-Function -Message "File already exists. If you want to overwrite it remove the -NoClobber parameter. If you want to append data, please Use -Append parameter." -Target $scriptPath -Continue
                        }
                        #Only at the first output we use the passed variables Append & NoClobber. For this execution the next ones need to use -Append
                        # Empty $prefix will clean file in case $appendToScript is not set.
                        Write-Message -Level Verbose -Message "Writing (maybe empty) prefix to file $scriptPath"
                        $prefix | Out-File -FilePath $scriptPath -Encoding $encoding -Append:$appendToScript -NoClobber:$NoClobber
                        $prefixArray += $scriptPath
                    }
                }

                if ($Pscmdlet.ShouldProcess($env:computername, "Exporting $object from $server to $scriptPath")) {
                    Write-Message -Level Verbose -Message "Exporting $object"

                    if ($Passthru) {
                        if ($ScriptingOptionsObject) {
                            $ScriptingOptionsObject.FileName = $null
                            foreach ($scriptpart in $scripter.EnumScript($object)) {
                                if ($scriptBatchTerminator) {
                                    $scriptpart = "$scriptpart$eol$BatchSeparator$eol"
                                }
                                $scriptpart | Out-String
                            }
                        } else {
                            foreach ($scriptpart in $scripter.EnumScript($object)) {
                                if ($BatchSeparator) {
                                    $scriptpart = "$scriptpart$eol$BatchSeparator$eol"
                                } else {
                                    $scriptpart = "$scriptpart$eol"
                                }
                                $scriptpart | Out-String
                            }
                        }
                    } else {
                        if ($ScriptingOptionsObject) {
                            if ($scriptBatchTerminator) {
                                # Option to script batch terminator via ScriptingOptionsObject needs to write to file only
                                $ScriptingOptionsObject.AppendToFile = $true
                                $ScriptingOptionsObject.ToFileOnly = $true
                                if (-not $ScriptingOptionsObject.FileName) {
                                    $ScriptingOptionsObject.FileName = $scriptPath
                                }
                                $null = $object.Script($ScriptingOptionsObject)
                            } else {
                                $ScriptingOptionsObject.FileName = $null
                                $scriptInFull = foreach ($scriptpart in $scripter.EnumScript($object)) {
                                    if ($BatchSeparator) {
                                        $scriptpart = "$scriptpart$eol$BatchSeparator$eol"
                                    } else {
                                        $scriptpart = "$scriptpart$eol"
                                    }
                                    $scriptpart
                                }
                                $scriptInFull | Out-File -FilePath $scriptPath -Encoding $encoding -Append
                            }
                        } else {
                            $scriptInFull = foreach ($scriptpart in $scripter.EnumScript($object)) {
                                if ($BatchSeparator) {
                                    $scriptpart = "$scriptpart$eol$BatchSeparator$eol"
                                } else {
                                    $scriptpart = "$scriptpart$eol"
                                }
                                $scriptpart
                            }
                            $scriptInFull | Out-File -FilePath $scriptPath -Encoding $encoding -Append
                        }
                    }

                    if (-not $Passthru) {
                        Write-Message -Level Verbose -Message "Exported $object on $($server.Name) to $scriptPath"
                        Get-ChildItem -Path $scriptPath
                    }
                }
            } catch {
                $message = $_.Exception.InnerException.InnerException.InnerException.Message
                if (-not $message) {
                    $message = $_.Exception
                }
                Stop-Function -Message "Failure on $($server.Name) | $message" -Target $server
            } finally {
                # Reset the changed values of the $ScriptingOptionsObject in case it is reused later
                if ($ScriptingOptionsObject) {
                    $ScriptingOptionsObject.AppendToFile = $soAppendToFile
                    $ScriptingOptionsObject.ToFileOnly = $soToFileOnly
                    $ScriptingOptionsObject.FileName = $soFileName
                }
            }
        }
    }
}
# SIG # Begin signature block
# MIIjYAYJKoZIhvcNAQcCoIIjUTCCI00CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCBc+8iNG3DU3OQx
# NfV8Uny0+hFEoxPyxwzQrDu1Q9Hm1qCCHVkwggUaMIIEAqADAgECAhADBbuGIbCh
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
# BgorBgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCBQGfeIQ7Dx/LlzaUzhlTnEeCO7
# 9G9NAcmvwH73K/8cjTANBgkqhkiG9w0BAQEFAASCAQAv2xF6nY+BpWeMGNrRqTp4
# BR6fv3EnUFrVANb0NsA+eCyotzPnhZFm17r9N3wS5WRdQrX+7x1Wts9B7HsCq09+
# 3msX/Dm2rkePhGjsJtrUBult/xZuVRtRK7doaHJK2QTIZAFZKfpLgF5aOcuMb9Jx
# BD/wdA48HipLq/GQF77tTUR80NCXkGGr03Y4ZIZ7aQWta06ikx8XHtK940zNZKIy
# VB/QJtTLv2rSjIM0nOLdT/QyQ5S0j7dc4/F4mTE+VG57Qtj3zYZWG7i0cHmxZcx2
# KhLpFUjIInncpjB0OBaQxbtvbrgojxrZ9EkjpjiDFf1eOqT2GupnEcjyAt+w0yqz
# oYIDIDCCAxwGCSqGSIb3DQEJBjGCAw0wggMJAgEBMHcwYzELMAkGA1UEBhMCVVMx
# FzAVBgNVBAoTDkRpZ2lDZXJ0LCBJbmMuMTswOQYDVQQDEzJEaWdpQ2VydCBUcnVz
# dGVkIEc0IFJTQTQwOTYgU0hBMjU2IFRpbWVTdGFtcGluZyBDQQIQDE1pckuU+jwq
# Sj0pB4A9WjANBglghkgBZQMEAgEFAKBpMBgGCSqGSIb3DQEJAzELBgkqhkiG9w0B
# BwEwHAYJKoZIhvcNAQkFMQ8XDTIyMTExNzA4NTUzMFowLwYJKoZIhvcNAQkEMSIE
# IO+MsN4lLA7TrA3nNlIhVqarys2s/tExHsxwZH1nzXA/MA0GCSqGSIb3DQEBAQUA
# BIICAALvB3r/JKKCaWpiOYD9P/rPEy2b9vPcXxaelcQHZyojcdlw6GR88BTWSX/C
# 7y8Fo6ajAAepTr3tFKQVpp38U/aSHKAozUZKghrCFyg2VJ4KXm0R989D04EO2zkE
# x1BD3qoF2TK0YfWHx0SJImPeyQN3Wl3wm0OioVMzMLf4+OX+1iXr4vtNgwo2gHML
# 7ENu24VBEW/suHeat+WC5bPa7vIcPMNRaGjawBRcWvLZNCrlQC8X3SaeRpgBoKwO
# B6+qC/bjyYge90BXwhHaxF30aHQ6f0AyCebMlLG+g5L5dGdTGCMvo7Vk6FveRzyl
# B1AnW4mlnqs8kPtlxrN5huSv1nFJ2VrX9ZWt1MTtL99/zY6VF6NnTSKnOCZQXz3e
# Skg8oLgaA+jDiDgOg1iXEuhA3H8FlzTNENnFTPpbgsl9sqEaBK0xECd2gjUkXwma
# jCMfZJqfMgZN6db/mGGvSoXIA2RtIWCdJi7rIHrQ+wSlAs1zlrrmPyVabTkWLei3
# 7kJODgYSRO0chkfueY+a8BfH97DyDRaS267sgCx3Q3R2GwJZ/icAjz8An+lf/b5v
# 5uyETOpEuMQKXHLWcApGHMUvdsCu5TjyPmqwDIFr+Fldfb3EQJT2J8/m0lzPLc1y
# 8uoHW5ZZrLXcROhZhqbqGupdgF9J4SOqx9VpKjT9gaqr4XVP
# SIG # End signature block
