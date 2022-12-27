function Test-DbaBuild {
    <#
    .SYNOPSIS
        Returns SQL Server Build "compliance" level on a build.

    .DESCRIPTION
        Returns info about the specific build of a SQL instance, including the SP, the CU and the reference KB, End Of Support, wherever possible. It adds a Compliance property as true/false, and adds details about the "targeted compliance".
        The build data used can be found here: https://dbatools.io/builds

    .PARAMETER Build
        Instead of connecting to a real instance, pass a string identifying the build to get the info back.

    .PARAMETER MinimumBuild
        This is the build version to test "compliance" against. Anything below this is flagged as not compliant.

    .PARAMETER MaxBehind
        Instead of using a specific MinimumBuild here you can pass "how many service packs and cu back" is the targeted compliance level. You can use xxSP or xxCU or both, where xx is a number. See the Examples for more information.

    .PARAMETER Latest
        Shortcut for specifying the very most up-to-date build available.

    .PARAMETER SqlInstance
        Target any number of instances, in order to return their compliance state.

    .PARAMETER SqlCredential
        Login to the target instance using alternative credentials. Accepts PowerShell credentials (Get-Credential).

        Windows Authentication, SQL Server Authentication, Active Directory - Password, and Active Directory - Integrated are all supported.

        For MFA support, please use Connect-DbaInstance.

    .PARAMETER Update
        Looks online for the most up to date reference, replacing the local one.

    .PARAMETER Quiet
        Makes the function just return $true/$false. It's useful if you use Test-DbaBuild in your own scripts.

    .PARAMETER EnableException
        By default, when something goes wrong we try to catch it, interpret it and give you a friendly warning message.
        This avoids overwhelming you with "sea of red" exceptions, but is inconvenient because it basically disables advanced scripting.
        Using this switch turns this "nice by default" feature off and enables you to catch exceptions with your own try/catch.

    .NOTES
        Tags: SqlBuild, Version, Utility
        Author: Simone Bizzotto (@niphold) | Friedrich Weinmann (@FredWeinmann)

        dbatools PowerShell module (https://dbatools.io)
        Copyright: (c) 2018 by dbatools, licensed under MIT
        License: MIT https://opensource.org/licenses/MIT

    .LINK
        https://dbatools.io/Test-DbaBuild

    .EXAMPLE
        PS C:\> Test-DbaBuild -Build "12.0.5540" -MinimumBuild "12.0.5557"

        Returns information about a build identified by "12.0.5540" (which is SQL 2014 with SP2 and CU4), which is not compliant as the minimum required
        build is "12.0.5557" (which is SQL 2014 with SP2 and CU8).

    .EXAMPLE
        PS C:\> Test-DbaBuild -Build "12.0.5540" -MaxBehind "1SP"

        Returns information about a build identified by "12.0.5540", making sure it is AT MOST 1 Service Pack "behind". For that version,
        that identifies an SP2, means accepting as the lowest compliance version as "12.0.4110", that identifies 2014 with SP1.

        Output column CUTarget is not relevant (empty). SPTarget and BuildTarget are filled in the result.

    .EXAMPLE
        PS C:\> Test-DbaBuild -Build "12.0.5540" -MaxBehind "1SP 1CU"

        Returns information about a build identified by "12.0.5540", making sure it is AT MOST 1 Service Pack "behind", plus 1 CU "behind". For that version,
        that identifies an SP2 and CU, rolling back 1 SP brings you to "12.0.4110", but given the latest CU for SP1 is CU13, the target "compliant" build
        will be "12.0.4511", which is 2014 with SP1 and CU12.

    .EXAMPLE
        PS C:\> Test-DbaBuild -Build "12.0.5540" -MaxBehind "0CU"

        Returns information about a build identified by "12.0.5540", making sure it is the latest CU release.

        Output columns CUTarget, SPTarget and BuildTarget are relevant. If the latest build is a service pack (not a CU), CUTarget will be empty.

    .EXAMPLE
        PS C:\> Test-DbaBuild -Build "12.0.5540" -Latest

        Returns information about a build identified by "12.0.5540", making sure it is the latest build available.

        Output columns CUTarget and SPTarget are not relevant (empty), only the BuildTarget is.

    .EXAMPLE
        PS C:\> Test-DbaBuild -Build "12.00.4502" -MinimumBuild "12.0.4511" -Update

        Same as before, but tries to fetch the most up to date index online. When the online version is newer, the local one gets overwritten.

    .EXAMPLE
        PS C:\> Test-DbaBuild -Build "12.0.4502","10.50.4260" -MinimumBuild "12.0.4511"

        Returns information builds identified by these versions strings.

    .EXAMPLE
        PS C:\> Get-DbaRegServer -SqlInstance sqlserver2014a | Test-DbaBuild -MinimumBuild "12.0.4511"

        Integrate with other cmdlets to have builds checked for all your registered servers on sqlserver2014a.

    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSUseShouldProcessForStateChangingFunctions", "")]
    [CmdletBinding()]
    param (
        [version[]]$Build,
        [version]$MinimumBuild,
        [string]$MaxBehind,
        [switch] $Latest,
        [parameter(ValueFromPipeline)]
        [DbaInstanceParameter[]]$SqlInstance,
        [PSCredential]$SqlCredential,
        [switch]$Update,
        [switch]$Quiet,
        [switch]$EnableException
    )

    begin {
        #region Helper functions
        function Get-DbaBuildReferenceIndex {
            [CmdletBinding()]

            $DbatoolsData = Get-DbatoolsConfigValue -Name 'Path.DbatoolsData'
            $writable_idxfile = Join-Path $DbatoolsData "dbatools-buildref-index.json"
            $result = Get-Content $writable_idxfile -Raw | ConvertFrom-Json
            $result.Data | Select-Object @{ Name = "VersionObject"; Expression = { [version]$_.Version } }, *
        }

        $ComplianceSpec = @()
        $ComplianceSpecExclusiveParams = @('MinimumBuild', 'MaxBehind', 'Latest')
        foreach ($exclParam in $ComplianceSpecExclusiveParams) {
            if (Test-Bound -Parameter $exclParam) { $ComplianceSpec += $exclParam }
        }
        if ($ComplianceSpec.Length -gt 1) {
            Stop-Function -Category InvalidArgument -Message "-MinimumBuild, -MaxBehind and -Latest are mutually exclusive. Please choose only one. Quitting."
            return
        }
        if ($ComplianceSpec.Length -eq 0) {
            Stop-Function -Category InvalidArgument -Message "You need to choose one from -MinimumBuild, -MaxBehind and -Latest. Quitting."
            return
        }
        if ($MaxBehind) {
            $MaxBehindValidator = [regex]'^(?<howmany>[\d]+)(?<what>SP|CU)$'
            $pieces = $MaxBehind.Split(' ')	| Where-Object { $_ }
            try {
                $ParsedMaxBehind = @{ }
                foreach ($piece in $pieces) {
                    $pieceMatch = $MaxBehindValidator.Match($piece)
                    if ($pieceMatch.Success -ne $true) {
                        Stop-Function -Message "MaxBehind has an invalid syntax ('$piece' could not be parsed correctly)" -ErrorRecord $_
                        return
                    } else {
                        $howmany = [int]$pieceMatch.Groups['howmany'].Value
                        $what = $pieceMatch.Groups['what'].Value
                        if ($ParsedMaxBehind.ContainsKey($what)) {
                            Stop-Function -Message "The specifier $what has been already passed" -ErrorRecord $_
                            return
                        } else {
                            $ParsedMaxBehind[$what] = $howmany
                        }
                    }
                }
                if (-not $ParsedMaxBehind.ContainsKey('SP')) {
                    $ParsedMaxBehind['SP'] = 0
                }
            } catch {
                Stop-Function -Message "Error parsing MaxBehind" -ErrorRecord $_
                return
            }
        }
    }
    process {
        if (Test-FunctionInterrupt) { return }
        $hiddenProps = @()
        if (-not $SqlInstance) {
            $hiddenProps += 'SqlInstance'
        }
        if ($MinimumBuild) {
            $hiddenProps += 'MaxBehind', 'SPTarget', 'CUTarget', 'BuildTarget'
        } elseif ($MaxBehind -or $Latest) {
            $hiddenProps += 'MinimumBuild'
        }
        if ($Build) {
            $BuildVersions = Get-DbaBuild -Build $Build -Update:$Update -EnableException:$EnableException
        } elseif ($SqlInstance) {
            $BuildVersions = Get-DbaBuild -SqlInstance $SqlInstance -SqlCredential $SqlCredential -Update:$Update -EnableException:$EnableException
        }
        # Moving it down here to only trigger after -Update was properly called
        if (!$IdxRef) {
            try {
                $IdxRef = Get-DbaBuildReferenceIndex
            } catch {
                Stop-Function -Message "Error loading SQL build reference" -ErrorRecord $_
                return
            }
        }
        foreach ($BuildVersion in $BuildVersions) {
            $inputbuild = $BuildVersion.Build
            $compliant = $false
            $targetSPName = $null
            $targetCUName = $null
            if ($BuildVersion.MatchType -eq 'Approximate') {
                Write-Message -Level Warning -Message "$($BuildVersion.Build) is not recognized as a correct version"
            }
            if ($MinimumBuild) {
                Write-Message -Level Debug -Message "Comparing $MinimumBuild to $inputbuild"
                if ($inputbuild -ge $MinimumBuild) {
                    $compliant = $true
                }
            } elseif ($MaxBehind -or $Latest) {
                $IdxVersion = $IdxRef | Where-Object Version -like "$($inputbuild.Major).$($inputbuild.Minor).*"
                $lastsp = ''
                $SPsAndCUs = @()
                foreach ($el in $IdxVersion) {
                    if ($null -ne $el.SP) {
                        $lastsp = $el.SP | Where-Object { $_ -ne 'LATEST' }
                        $SPsAndCUs += @{
                            VersionObject = $el.VersionObject
                            SP            = $lastsp
                        }
                    }
                    if ($null -ne $el.CU) {
                        $SPsAndCUs += @{
                            VersionObject = $el.VersionObject
                            SP            = $lastsp
                            CU            = $el.CU
                            Retired       = $el.Retired
                        }
                    }
                }
                $targetedBuild = $SPsAndCUs[0]
                if ($Latest) {
                    $targetedBuild = $IdxVersion[$IdxVersion.Length - 1]
                } else {
                    if ($ParsedMaxBehind.ContainsKey('SP')) {
                        [string[]]$AllSPs = $SPsAndCUs.SP | Select-Object -Unique
                        $targetSP = $AllSPs.Length - $ParsedMaxBehind['SP'] - 1
                        if ($targetSP -lt 0) {
                            $targetSP = 0
                        }
                        $targetSPName = $AllSPs[$targetSP]
                        Write-Message -Level Debug -Message "Target SP is $targetSPName - $targetSP on $($AllSPs.Length)"
                        $targetedBuild = $SPsAndCUs | Where-Object SP -eq $targetSPName | Select-Object -First 1
                    }
                    if ($ParsedMaxBehind.ContainsKey('CU')) {
                        [string[]]$AllCUs = ($SPsAndCUs | Where-Object VersionObject -gt $targetedBuild.VersionObject | Where-Object Retired -ne $true).CU | Select-Object -Unique
                        if ($AllCUs.Length -gt 0) {
                            #CU after the targeted build available
                            $targetCU = $AllCUs.Length - $ParsedMaxBehind['CU'] - 1
                            if ($targetCU -lt 0) {
                                $targetCU = 0
                            }
                            $targetCUName = $AllCUs[$targetCU]
                            Write-Message -Level Debug -Message "Target CU is $targetCUName - $targetCU on $($AllCUs.Length)"
                            $targetedBuild = $SPsAndCUs | Where-Object VersionObject -gt $targetedBuild.VersionObject | Where-Object CU -eq $targetCUName | Select-Object -First 1
                        }
                    }
                }
                if ($inputbuild -ge $targetedBuild.VersionObject) {
                    $compliant = $true
                }
            }
            Add-Member -InputObject $BuildVersion -MemberType NoteProperty -Name Compliant -Value $compliant
            Add-Member -InputObject $BuildVersion -MemberType NoteProperty -Name MinimumBuild -Value $MinimumBuild
            Add-Member -InputObject $BuildVersion -MemberType NoteProperty -Name MaxBehind -Value $MaxBehind
            Add-Member -InputObject $BuildVersion -MemberType NoteProperty -Name SPTarget -Value $targetSPName
            Add-Member -InputObject $BuildVersion -MemberType NoteProperty -Name CUTarget -Value $targetCUName
            Add-Member -InputObject $BuildVersion -MemberType NoteProperty -Name BuildTarget -Value $targetedBuild.VersionObject
            if ($Quiet) {
                $BuildVersion.Compliant
            } else {
                $BuildVersion | Select-Object * | Select-DefaultView -ExcludeProperty $hiddenProps
            }
        }
    }
}
# SIG # Begin signature block
# MIIjYAYJKoZIhvcNAQcCoIIjUTCCI00CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCALPD+Ilx79xDHg
# JfIhrMj0oBwUvg+dFY2O55Kgmi6c0qCCHVkwggUaMIIEAqADAgECAhADBbuGIbCh
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
# BgorBgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCBJlaE8Gmhpb0wamzqS0+6nQ/MO
# Ctdp+gK3taMJgfMtTDANBgkqhkiG9w0BAQEFAASCAQCtgUuegQ0heYGS686Ffpft
# TYQsQcEgVzgEzhvJK2BHrcwUXn0/QIITag6r+ld+ZVcqMz9fxj1aC/82j8cQhHxN
# 7ckLHOygSrbwjQ8lexti9CwqfrGFeUkSPsagiLWjs6f8AblZE9tjOqgrHg+R/iIm
# vF7Zd8k+8DO+9xCzBAxLFk83c2hpm9Q5UaNln6p4pN7IaF769nkf4nsB8obbAzh4
# z2pcfK6ARaqtTqAw8eCUGd9ry8g9epvASdxcEStdKIoK80bDBUL8uQ32477+4hLK
# XcX/GA0QilYPiyr+mtKQObZcgVGXyQ0hYhgvLDF8C+Fo7cflBHVIg7108IAE+7LV
# oYIDIDCCAxwGCSqGSIb3DQEJBjGCAw0wggMJAgEBMHcwYzELMAkGA1UEBhMCVVMx
# FzAVBgNVBAoTDkRpZ2lDZXJ0LCBJbmMuMTswOQYDVQQDEzJEaWdpQ2VydCBUcnVz
# dGVkIEc0IFJTQTQwOTYgU0hBMjU2IFRpbWVTdGFtcGluZyBDQQIQDE1pckuU+jwq
# Sj0pB4A9WjANBglghkgBZQMEAgEFAKBpMBgGCSqGSIb3DQEJAzELBgkqhkiG9w0B
# BwEwHAYJKoZIhvcNAQkFMQ8XDTIyMTExNzA4NTc0NVowLwYJKoZIhvcNAQkEMSIE
# IMe5ttNS9mUm/Dn0o29KFhAqDJHrgsS6lKGYLJ9Zq5qqMA0GCSqGSIb3DQEBAQUA
# BIICAAz9uiRDSgUW9y+q29vE96lKuO8THFiWRtjtc55nyCqmcusKkwTTWvVyC8t9
# bCfwkbpwWgDFFqR+kd6GZ1dfV8PYJLNtBoINlOIfkW8iJ7umuv+sXc2TNVYrNZIh
# WOF+ZDJOF6aQtAEmxgoktdtVX+9pu+LiRO85s+zrgy598YjXZ1MFWW8yIkfGF9/d
# afREacdwQ8NlV8QcZarzcA7CAFnwJr76LPs5y9rkq5kBfyJJNG84ucbzZn5UoriZ
# OB5esgLEt6Gv2XXkUGBTRhTGPUKEbdicbtprwOqpWQ66WGGMjRJ1oA6rnB4p64Km
# SMGS5yYCHPMhtUp1lBVShDTqaHaW/jEaAfzv6spllkwmZfY4CbCMlrfNGttv8xtf
# pdeI68k+vzdRcPfmXv7wlMTINhpSv6niqP1J1TyVx8dH/+BZEEVfmgjZMrQvl1xD
# PiuWcpNmVEYDCkBiGJ6MnwANY/Gze6x/cQYnSl1viMQcDT+TrSUUkHbsNAzKo4Ad
# cZwFQmuCNYUOmSUWR8clmyexuo/sJYW6AdbfttcjHldWOlsFuZkucc2fEvUiUadp
# mDdd9k8ZuTGXmBPpf3zv6oW9HmiMYmoFK3e58EL1pmN2ZGjaQgcI67eelQHMy7/+
# /kbGUff9+EjYEK84p5Cbh6QjjGy7JyhfHadyYa2ST1/U82sS
# SIG # End signature block
