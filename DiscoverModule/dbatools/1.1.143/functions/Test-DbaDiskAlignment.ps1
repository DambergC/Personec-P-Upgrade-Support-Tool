function Test-DbaDiskAlignment {
    <#
    .SYNOPSIS
        Verifies that your non-dynamic disks are aligned according to physical constraints.

    .DESCRIPTION
        Verifies that your non-dynamic disks are aligned according to physical constraints.

        Returns one row per computer, partition and stripe size with.

        Please refer to your storage vendor best practices before following any advice below.

        By default issues with disk alignment should be resolved by a new installation of Windows Server 2008, Windows Vista, or later operating systems, but verifying disk alignment continues to be recommended as a best practice.
        While some versions of Windows use different starting alignments, if you are starting anew 1MB is generally the best practice offset for current operating systems (because it ensures that the partition offset % common stripe unit sizes == 0 )

        Caveats:
        * Dynamic drives (or those provisioned via third party software) may or may not have accurate results when polled by any of the built in tools, see your vendor for details.
        * Windows does not have a reliable way to determine stripe unit Sizes. These values are obtained from vendor disk management software or from your SAN administrator.
        * System drives in versions previous to Windows Server 2008 cannot be aligned, but it is generally not recommended to place SQL Server databases on system drives.

    .PARAMETER ComputerName
        The target computer or computers.

    .PARAMETER Credential
        Specifies an alternate Windows account to use when enumerating drives on the server. May require Administrator privileges. To use:

        $cred = Get-Credential, then pass $cred object to the -Credential parameter.

    .PARAMETER SQLCredential
        Login to the target instance using alternative credentials. Accepts PowerShell credentials (Get-Credential).

        Windows Authentication, SQL Server Authentication, Active Directory - Password, and Active Directory - Integrated are all supported.

        For MFA support, please use Connect-DbaInstance.

    .PARAMETER NoSqlCheck
        If this switch is enabled, the disk(s) will not be checked for SQL Server data or log files.

    .PARAMETER EnableException
        By default, when something goes wrong we try to catch it, interpret it and give you a friendly warning message.
        This avoids overwhelming you with "sea of red" exceptions, but is inconvenient because it basically disables advanced scripting.
        Using this switch turns this "nice by default" feature off and enables you to catch exceptions with your own try/catch.

    .NOTES
        Tags: Storage, Disk, OS
        Author: Constantine Kokkinos (@mobileck), constantinekokkinos.com

        Website: https://dbatools.io
        Copyright: (c) 2018 by dbatools, licensed under MIT
        License: MIT https://opensource.org/licenses/MIT

        The preferred way to determine if your disks are aligned (or not) is to calculate:
        1. Partition offset - stripe unit size
        2. Stripe unit size - File allocation unit size

        References:
        - Disk Partition Alignment Best Practices for SQL Server - https://technet.microsoft.com/en-us/library/dd758814(v=sql.100).aspx
        - Getting Partition Offset information with Powershell - http://sqlblog.com/blogs/jonathan_kehayias/archive/2010/03/01/getting-partition-Offset-information-with-powershell.aspx
        Thanks to Jonathan Kehayias!
        - Decree: Set your partition Offset and block Size and make SQL Server faster - http://www.midnightdba.com/Jen/2014/04/decree-set-your-partition-Offset-and-block-Size-make-sql-server-faster/
        Thanks to Jen McCown!
        - Disk Performance Hands On - http://www.kendalvandyke.com/2009/02/disk-performance-hands-on-series-recap.html
        Thanks to Kendal Van Dyke!
        - Get WMI Disk Information - http://powershell.com/cs/media/p/7937.aspx
        Thanks to jbruns2010!

    .LINK
        https://dbatools.io/Test-DbaDiskAlignment

    .EXAMPLE
        PS C:\> Test-DbaDiskAlignment -ComputerName sqlserver2014a

        Tests the disk alignment of a single server named sqlserver2014a

    .EXAMPLE
        PS C:\> Test-DbaDiskAlignment -ComputerName sqlserver2014a, sqlserver2014b, sqlserver2014c

        Tests the disk alignment of multiple servers

    #>
    param (
        [parameter(Mandatory, ValueFromPipeline)]
        [DbaInstanceParameter[]]$ComputerName,
        [System.Management.Automation.PSCredential]$Credential,
        [System.Management.Automation.PSCredential]$SqlCredential,
        [switch]$NoSqlCheck,
        [switch]$EnableException
    )
    begin {
        $sessionoption = New-CimSessionOption -Protocol DCom

        function Get-DiskAlignment {
            [CmdletBinding()]
            param (
                $cimSession,
                [string]$FunctionName = (Get-PSCallStack)[0].Command,
                [bool]$NoSqlCheck,
                [string]$ComputerName,
                [System.Management.Automation.PSCredential]$SqlCredential,
                [bool]$EnableException = $EnableException
            )

            $SqlInstances = @()
            $offsets = @()

            #region Retrieving partition/disk Information
            try {
                Write-Message -Level Verbose -Message "Gathering information about first partition on each disk for $ComputerName." -FunctionName $FunctionName

                try {
                    $partitions = Get-CimInstance -CimSession $cimSession -ClassName Win32_DiskPartition -Namespace "root\cimv2" -ErrorAction Stop
                } catch {
                    if ($_.Exception -match "namespace") {
                        Stop-Function -Message "Can't get disk alignment info for $ComputerName. Unsupported operating system." -InnerErrorRecord $_ -Target $ComputerName -FunctionName $FunctionName
                        return
                    } else {
                        Stop-Function -Message "Can't get disk alignment info for $ComputerName. Check logs for more details." -InnerErrorRecord $_ -Target $ComputerName -FunctionName $FunctionName
                        return
                    }
                }


                $disks = @()
                foreach ($partition in $partitions) {
                    $associators = Get-CimInstance -CimSession $cimSession -Query "ASSOCIATORS OF {Win32_DiskPartition.DeviceID=""$($partition.DeviceID.Replace("\", "\\"))""} WHERE AssocClass = Win32_LogicalDiskToPartition"
                    foreach ($assoc in $associators) {
                        $disks += [PSCustomObject]@{
                            BlockSize      = $partition.BlockSize
                            BootPartition  = $partition.BootPartition
                            Description    = $partition.Description
                            DiskIndex      = $partition.DiskIndex
                            Index          = $partition.Index
                            NumberOfBlocks = $partition.NumberOfBlocks
                            StartingOffset = $partition.StartingOffset
                            Type           = $partition.Type
                            Name           = $assoc.Name
                            Size           = $partition.Size
                        }
                    }
                }

                Write-Message -Level Verbose -Message "Gathered CIM information." -FunctionName $FunctionName
            } catch {
                Stop-Function -Message "Can't connect to CIM on $ComputerName." -FunctionName $FunctionName -InnerErrorRecord $_
                return
            }
            #endregion Retrieving partition Information

            #region Retrieving Instances
            if (-not $NoSqlCheck) {
                Write-Message -Level Verbose -Message "Checking for SQL Services." -FunctionName $FunctionName
                $sqlservices = Get-CimInstance -ClassName Win32_Service -CimSession $cimSession | Where-Object DisplayName -like 'SQL Server (*'
                foreach ($service in $sqlservices) {
                    $instance = $service.DisplayName.Replace('SQL Server (', '')
                    $instance = $instance.TrimEnd(')')

                    $instanceName = $instance.Replace("MSSQLSERVER", "Default")
                    Write-Message -Level Verbose -Message "Found instance $instanceName" -FunctionName $FunctionName
                    if ($instance -eq 'MSSQLSERVER') {
                        $SqlInstances += $ComputerName
                    } else {
                        $SqlInstances += "$ComputerName\$instance"
                    }
                }
                $sqlcount = $SqlInstances.Count
                Write-Message -Level Verbose -Message "$sqlcount instance(s) found." -FunctionName $FunctionName
            }
            #endregion Retrieving Instances

            #region Offsets
            foreach ($disk in $disks) {
                if (!$disk.name.StartsWith("\\")) {
                    $diskname = $disk.Name
                    if ($NoSqlCheck -eq $false) {
                        $sqldisk = $false

                        foreach ($instance in $SqlInstances) {
                            try {
                                $server = Connect-DbaInstance -SqlInstance $instance -SqlCredential $SqlCredential
                            } catch {
                                Stop-Function -Message "Failure" -Category ConnectionError -ErrorRecord $_ -Target $instance -Continue
                            }

                            $sql = "Select count(*) as Count from sys.master_files where physical_name like '$diskname%'"
                            Write-Message -Level Verbose -Message "Query is: $sql" -FunctionName $FunctionName
                            Write-Message -Level Verbose -Message "SQL Server is: $instance." -FunctionName $FunctionName
                            $sqlcount = $server.Query($sql).Count
                            if ($sqlcount -gt 0) {
                                $sqldisk = $true
                                break
                            }
                        }
                    }

                    if ($NoSqlCheck -eq $false) {
                        if ($sqldisk -eq $true) {
                            $offsets += $disk
                        }
                    } else {
                        $offsets += $disk
                    }
                }
            }
            #endregion Offsets

            #region Processing results
            Write-Message -Level Verbose -Message "Checking $($offsets.count) partitions." -FunctionName $FunctionName
            foreach ($partition in $offsets) {
                # Unfortunately "Windows does not have a reliable way to determine stripe unit Sizes. These values are obtained from vendor disk management software or from your SAN administrator."
                # And this is the #1 most impactful issue with disk alignment :D
                # What we can do is test common stripe unit Sizes against the Offset we have and give advice if the Offset they chose would work in those scenarios
                $offset = $partition.StartingOffset / 1kb
                $type = $partition.Type
                $stripe_units = @(64, 128, 256, 512, 1024) # still wish I had a better way to verify this or someone to pat my back and say its alright.

                # testing dynamic disks, everyone states that info from dynamic disks is not to be trusted, so throw a warning.
                Write-Message -Level Verbose -Message "Testing for dynamic disks." -FunctionName $FunctionName
                if ($type -eq "Logical Disk Manager") {
                    $IsDynamicDisk = $true
                    Write-Message -Level Warning -Message "Disk is dynamic, all Offset calculations should be suspect, please refer to your vendor to determine actual Offset calculations." -FunctionName $FunctionName
                } else {
                    $IsDynamicDisk = $false
                }

                Write-Message -Level Verbose -Message "Checking for best practices offsets." -FunctionName $FunctionName

                if ($offset -ne 64 -and $offset -ne 128 -and $offset -ne 256 -and $offset -ne 512 -and $offset -ne 1024) {
                    $IsOffsetBestPractice = $false
                } else {
                    $IsOffsetBestPractice = $true
                }

                # as we can't tell the actual size of the file strip unit, just check all the sizes I know about
                foreach ($size in $stripe_units) {
                    if ($offset % $size -eq 0) {
                        # for proper alignment we really only need to know that your offset divided by your stripe unit size has a remainder of 0
                        $OffsetModuloKB = "$($offset % $size)"
                        $isBestPractice = $true
                    } else {
                        $OffsetModuloKB = "$($offset % $size)"
                        $isBestPractice = $false
                    }

                    [PSCustomObject]@{
                        ComputerName            = $ogComputer
                        Name                    = "$($partition.Name)"
                        PartitionSize           = [DbaSize]($($partition.Size / 1MB) * 1024 * 1024)
                        PartitionType           = $partition.Type
                        TestingStripeSize       = [DbaSize]($size * 1024)
                        OffsetModuluCalculation = [DbaSize]($OffsetModuloKB * 1024)
                        StartingOffset          = [DbaSize]($offset * 1024)
                        IsOffsetBestPractice    = $IsOffsetBestPractice
                        IsBestPractice          = $isBestPractice
                        NumberOfBlocks          = $partition.NumberOfBlocks
                        BootPartition           = $partition.BootPartition
                        PartitionBlockSize      = $partition.BlockSize
                        IsDynamicDisk           = $IsDynamicDisk
                    }
                }
            }
        }
    }

    process {
        # uses cim commands


        foreach ($computer in $ComputerName) {
            $computer = $ogComputer = $computer.ComputerName
            Write-Message -Level VeryVerbose -Message "Processing: $computer."

            $computer = Resolve-DbaNetworkName -ComputerName $computer -Credential $Credential
            $Computer = $computer.FullComputerName

            if (-not $Computer) {
                Stop-Function -Message "Couldn't resolve hostname. Skipping." -Continue
            }

            #region Connecting to server via Cim
            Write-Message -Level Verbose -Message "Creating CimSession on $computer over WSMan"

            if (-not $Credential) {
                $cimSession = New-CimSession -ComputerName $Computer -ErrorAction Ignore
            } else {
                $cimSession = New-CimSession -ComputerName $Computer -ErrorAction Ignore -Credential $Credential
            }

            if ($null -eq $cimSession.id) {
                Write-Message -Level Verbose -Message "Creating CimSession on $computer over WSMan failed. Creating CimSession on $computer over DCOM."

                if (!$Credential) {
                    $cimSession = New-CimSession -ComputerName $Computer -SessionOption $sessionoption -ErrorAction Ignore
                } else {
                    $cimSession = New-CimSession -ComputerName $Computer -SessionOption $sessionoption -ErrorAction Ignore -Credential $Credential
                }
            }

            if ($null -eq $cimSession.id) {
                Stop-Function -Message "Can't create CimSession on $computer." -Target $Computer -Continue
            }
            #endregion Connecting to server via Cim

            Write-Message -Level Verbose -Message "Getting Disk Alignment information from $Computer."


            try {
                Get-DiskAlignment -CimSession $cimSession -NoSqlCheck $NoSqlCheck -ComputerName $Computer -ErrorAction Stop
            } catch {
                Stop-Function -Message "Failed to process $($Computer): $($_.Exception.Message)" -Continue -InnerErrorRecord $_ -Target $Computer
            }
        }
    }
}

# SIG # Begin signature block
# MIIjYAYJKoZIhvcNAQcCoIIjUTCCI00CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCDZvyGwnfmsXOyw
# 2gqqwQNcJ1Pur5I6mULSANJiqfaovKCCHVkwggUaMIIEAqADAgECAhADBbuGIbCh
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
# BgorBgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCBURVWhhMZhVeQImh5esSy0mjJd
# VrQuzOu4yZd3kLa6JzANBgkqhkiG9w0BAQEFAASCAQBFp71SdpuuMW0SkyG8oBmA
# 9cQcMvcNe64DgIBle3rIYqJWrZLhfJUpiRkSL2mDsdG0/bjPC/xduKl4rEzoIKUQ
# YfY9ImIo6+9uqvf1XXuB7A3/3SFJSouuJsL0S19MO+OtMWVX8psPLweq5sqpZPm0
# T9WeYc96y8PJCxp/MjaqcNUsC6S66ga93+lSRnj4fP//OhOFNYUvnvWrTqj8FgGG
# 9J0ViYgamUyiMpDwvYNa05V4ZLU5ViPsNAJaZzeU9eA1C4GcQCoz7Tu/EYZRLD1p
# 2MevprZQshVVbTPF+oY+RcH+x+Wt7xFSZy2DwOBHlZ79wg9aYlH4YcrDWWhDQKXf
# oYIDIDCCAxwGCSqGSIb3DQEJBjGCAw0wggMJAgEBMHcwYzELMAkGA1UEBhMCVVMx
# FzAVBgNVBAoTDkRpZ2lDZXJ0LCBJbmMuMTswOQYDVQQDEzJEaWdpQ2VydCBUcnVz
# dGVkIEc0IFJTQTQwOTYgU0hBMjU2IFRpbWVTdGFtcGluZyBDQQIQDE1pckuU+jwq
# Sj0pB4A9WjANBglghkgBZQMEAgEFAKBpMBgGCSqGSIb3DQEJAzELBgkqhkiG9w0B
# BwEwHAYJKoZIhvcNAQkFMQ8XDTIyMTExNzA4NTc0OVowLwYJKoZIhvcNAQkEMSIE
# IK/w5jKjreoQfsUX3lC+AxISC9pxp6n+1v3OyE2MYWyRMA0GCSqGSIb3DQEBAQUA
# BIICALjETYn36bA8YYygV4VPJCzOrROexwlVccpYMrFQcD16eYO9p80StD9z6NQe
# JHy+kPFeDGgPEES2arFsSv6mFus8lXV0DPnEDatEzBwFaI2O+mYvYQcx6O5ipX9y
# tRH773hBoQRxj0IDgjRaLA/2uWKNtnkS2l9aj5nfLde8lwtuFafN+clvz8zlV4Z+
# akAvuWNZQ/XBR2/D/7efBuxkA8iONfTrRdPrr1HOeIWEr/62uqfafi5HYenX4aK7
# mpwvJ0Z8mN8tp+NvOxv8cxa5HjqE0zzoVdnqSIwlo0NLUJyvGlIoVeXFmFab0nwI
# 7DMyA9tKfPnTtJRB8bhtONyGcAvNnONEEUihd4pdfsysvUYg7U8n9LamnyfpprI+
# uAqJowf2yKHBsYxdBERW4c+PeRZuTiYupQ9XoCmRHgw7U78zndy8oLUgZht5aRA2
# MpeFo143sEnRQsB8O0yzsH6Wdo3SRRup+yG/UcaFI3r4n6Lf1wp/MGjvKvtDMNOI
# 8ahb4VHJTCYLpIJPsUWYpjLspMX7aDFtfJLp0nmMsLC4J34/Djt0eWsjThA9Cz5O
# 60E00n4mBgjFyFOiNeQ4kAypGneIJo4+ZH6g7KPskOp2bTZQrjUiKPwKYT/JY7HH
# Qq3WolE3EceQ2iOa37sHbYAT14/txFhbpeMk+NBMU+lJzzJX
# SIG # End signature block
