function Set-DbaPrivilege {
    <#
    .SYNOPSIS
        Adds the SQL Service account to local privileges on one or more computers.

    .DESCRIPTION
        Adds the SQL Service account to local privileges 'Lock Pages in Memory', 'Instant File Initialization', 'Logon as Batch', 'Logon as a service' on one or more computers.

        Requires Local Admin rights on destination computer(s).

    .PARAMETER ComputerName
        The target SQL Server instance or instances.

    .PARAMETER Credential
        Credential object used to connect to the computer as a different user.

    .PARAMETER Type
        Use this to choose the privilege(s) to which you want to add the SQL Service account.
        Accepts 'IFI', 'LPIM', 'BatchLogon','SecAudit' and/or 'ServiceLogon' for local privileges 'Instant File Initialization', 'Lock Pages in Memory', 'Logon as Batch','Generate Security Audits' and 'Logon as a service'.

    .PARAMETER User
        If provided, will add requested permissions to this account instead of the the account under which the SQL service is running.

    .PARAMETER WhatIf
        If this switch is enabled, no actions are performed but informational messages will be displayed that explain what would happen if the command were to run.

    .PARAMETER Confirm
        If this switch is enabled, you will be prompted for confirmation before executing any operations that change state.

    .PARAMETER EnableException
        By default, when something goes wrong we try to catch it, interpret it and give you a friendly warning message.
        This avoids overwhelming you with "sea of red" exceptions, but is inconvenient because it basically disables advanced scripting.
        Using this switch turns this "nice by default" feature off and enables you to catch exceptions with your own try/catch.

    .NOTES
        Tags: Privilege, Security
        Author: Klaas Vandenberghe (@PowerDbaKlaas)

        Website: https://dbatools.io
        Copyright: (c) 2018 by dbatools, licensed under MIT
        License: MIT https://opensource.org/licenses/MIT

    .LINK
        https://dbatools.io/Set-DbaPrivilege

    .EXAMPLE
        PS C:\> Set-DbaPrivilege -ComputerName sqlserver2014a -Type LPIM,IFI

        Adds the SQL Service account(s) on computer sqlserver2014a to the local privileges 'SeManageVolumePrivilege' and 'SeLockMemoryPrivilege'.

    .EXAMPLE
        PS C:\> 'sql1','sql2','sql3' | Set-DbaPrivilege -Type IFI

        Adds the SQL Service account(s) on computers sql1, sql2 and sql3 to the local privilege 'SeManageVolumePrivilege'.

    #>
    [CmdletBinding(SupportsShouldProcess)]
    param (
        [parameter(ValueFromPipeline)]
        [Alias("cn", "host", "Server")]
        [dbainstanceparameter[]]$ComputerName = $env:COMPUTERNAME,
        [PSCredential]$Credential,
        [Parameter(Mandatory)]
        [ValidateSet('IFI', 'LPIM', 'BatchLogon', 'SecAudit', 'ServiceLogon')]
        [string[]]$Type,
        [switch]$EnableException,
        [string]$User
    )

    begin {
        $ResolveAccountToSID = @"
function Convert-UserNameToSID ([string] `$Acc ) {
`$objUser = New-Object System.Security.Principal.NTAccount(`"`$Acc`")
`$strSID = `$objUser.Translate([System.Security.Principal.SecurityIdentifier])
`$strSID.Value
}
"@
        $ComputerName = $ComputerName.ComputerName | Select-Object -Unique
    }
    process {
        foreach ($computer in $ComputerName) {
            if ($Pscmdlet.ShouldProcess($computer, "Setting Privilege for SQL Service Account")) {
                try {
                    $null = Test-ElevationRequirement -ComputerName $Computer -Continue
                    if (Test-PSRemoting -ComputerName $Computer) {
                        Write-Message -Level Verbose -Message "Exporting Privileges on $Computer"
                        Invoke-Command2 -Raw -ComputerName $computer -Credential $Credential -ScriptBlock {
                            $temp = ([System.IO.Path]::GetTempPath()).TrimEnd(""); secedit /export /cfg $temp\secpolByDbatools.cfg > $NULL;
                        }

                        $SQLServiceAccounts = @();
                        if (Test-Bound 'User') {
                            $SQLServiceAccounts += $User;
                        } else {
                            Write-Message -Level Verbose -Message "Getting SQL Service Accounts on $computer"
                            $SQLServiceAccounts += (Get-DbaService -ComputerName $computer -Type Engine).StartName
                        }
                        if ($SQLServiceAccounts.count -ge 1) {
                            Write-Message -Level Verbose -Message "Setting Privileges on $Computer"
                            Invoke-Command2 -Raw -ComputerName $computer -Credential $Credential -Verbose -ArgumentList $ResolveAccountToSID, $SQLServiceAccounts, $Type -ScriptBlock {
                                [CmdletBinding()]
                                param ($ResolveAccountToSID,
                                    $SQLServiceAccounts,
                                    $Type
                                )
                                . ([ScriptBlock]::Create($ResolveAccountToSID))
                                $temp = ([System.IO.Path]::GetTempPath()).TrimEnd("");
                                $tempfile = "$temp\secpolByDbatools.cfg"
                                if ('BatchLogon' -in $Type) {
                                    $BLline = Get-Content $tempfile | Where-Object { $_ -match "SeBatchLogonRight" }
                                    ForEach ($acc in $SQLServiceAccounts) {
                                        $SID = Convert-UserNameToSID -Acc $acc;
                                        if (-not $BLline) {
                                            $BLline = "SeBatchLogonRight = *$SID"
                                            (Get-Content $tempfile) -replace "\[Privilege Rights\]", "[Privilege Rights]`n$BLline" |
                                                Set-Content $tempfile
                                            <# DO NOT use Write-Message as this is inside of a script block #>
                                            Write-Verbose "Added $acc to Batch Logon Privileges on $env:ComputerName"
                                        } elseif ($BLline -notmatch $SID) {
                                            (Get-Content $tempfile) -replace "SeBatchLogonRight = ", "SeBatchLogonRight = *$SID," |
                                                Set-Content $tempfile
                                            <# DO NOT use Write-Message as this is inside of a script block #>
                                            Write-Verbose "Added $acc to Batch Logon Privileges on $env:ComputerName"
                                        } else {
                                            <# DO NOT use Write-Message as this is inside of a script block #>
                                            Write-Verbose "$acc already has Batch Logon Privilege on $env:ComputerName"
                                        }
                                    }
                                }
                                if ('IFI' -in $Type) {
                                    $IFIline = Get-Content $tempfile | Where-Object { $_ -match "SeManageVolumePrivilege" }
                                    ForEach ($acc in $SQLServiceAccounts) {
                                        $SID = Convert-UserNameToSID -Acc $acc;
                                        if (-not $IFIline) {
                                            $IFIline = "SeManageVolumePrivilege = *$SID"
                                            (Get-Content $tempfile) -replace "\[Privilege Rights\]", "[Privilege Rights]`n$IFIline" |
                                                Set-Content $tempfile
                                            <# DO NOT use Write-Message as this is inside of a script block #>
                                            Write-Verbose "Added $acc to Instant File Initialization Privileges on $env:ComputerName"
                                        } elseif ($IFIline -notmatch $SID) {
                                            (Get-Content $tempfile) -replace "SeManageVolumePrivilege = ", "SeManageVolumePrivilege = *$SID," |
                                                Set-Content $tempfile
                                            <# DO NOT use Write-Message as this is inside of a script block #>
                                            Write-Verbose "Added $acc to Instant File Initialization Privileges on $env:ComputerName"
                                        } else {
                                            <# DO NOT use Write-Message as this is inside of a script block #>
                                            Write-Verbose "$acc already has Instant File Initialization Privilege on $env:ComputerName"
                                        }
                                    }
                                }
                                if ('LPIM' -in $Type) {
                                    $LPIMline = Get-Content $tempfile | Where-Object { $_ -match "SeLockMemoryPrivilege" }
                                    ForEach ($acc in $SQLServiceAccounts) {
                                        $SID = Convert-UserNameToSID -Acc $acc;
                                        if (-not $LPIMline) {
                                            $LPIMline = "SeLockMemoryPrivilege = *$SID"
                                            (Get-Content $tempfile) -replace "\[Privilege Rights\]", "[Privilege Rights]`n$LPIMline" |
                                                Set-Content $tempfile
                                            <# DO NOT use Write-Message as this is inside of a script block #>
                                            Write-Verbose "Added $acc to Lock Pages in Memory Privileges on $env:ComputerName"
                                        } elseif ($LPIMline -notmatch $SID) {
                                            (Get-Content $tempfile) -replace "SeLockMemoryPrivilege = ", "SeLockMemoryPrivilege = *$SID," |
                                                Set-Content $tempfile
                                            <# DO NOT use Write-Message as this is inside of a script block #>
                                            Write-Verbose "Added $acc to Lock Pages in Memory Privileges on $env:ComputerName"
                                        } else {
                                            <# DO NOT use Write-Message as this is inside of a script block #>
                                            Write-Verbose "$acc already has Lock Pages in Memory Privilege on $env:ComputerName"
                                        }
                                    }
                                }
                                if ('SecAudit' -in $Type) {
                                    $Line = Get-Content $tempfile | Where-Object { $_ -match "SeAuditPrivilege" }
                                    ForEach ($acc in $SQLServiceAccounts) {
                                        $SID = Convert-UserNameToSID -Acc $acc;
                                        if (-not $Line) {
                                            $Line = "SeAuditPrivilege = *$SID"
                                            (Get-Content $tempfile) -replace "\[Privilege Rights\]", "[Privilege Rights]`n$Line" |
                                                Set-Content $tempfile
                                            <# DO NOT use Write-Message as this is inside of a script block #>
                                            Write-Verbose "Added $acc to Security Log Privileges on $env:ComputerName"
                                        } elseif ($Line -notmatch $SID) {
                                            (Get-Content $tempfile) -replace "SeAuditPrivilege = ", "SeAuditPrivilege = *$SID," |
                                                Set-Content $tempfile
                                            <# DO NOT use Write-Message as this is inside of a script block #>
                                            Write-Verbose "Added $acc to Write to Security Log Privileges on $env:ComputerName"
                                        } else {
                                            <# DO NOT use Write-Message as this is inside of a script block #>
                                            Write-Verbose "$acc already has Write To Security Audit Privilege on $env:ComputerName"
                                        }
                                    }
                                }
                                if ('ServiceLogon' -in $Type) {
                                    $SLline = Get-Content $tempfile | Where-Object { $_ -match "SeServiceLogonRight" }
                                    ForEach ($acc in $SQLServiceAccounts) {
                                        $SID = Convert-UserNameToSID -Acc $acc;
                                        if (-not $SLline) {
                                            $SLline = "SeServiceLogonRight = *$SID"
                                            (Get-Content $tempfile) -replace "\[Privilege Rights\]", "[Privilege Rights]`n$SLline" |
                                                Set-Content $tempfile
                                            <# DO NOT use Write-Message as this is inside of a script block #>
                                            Write-Verbose "Added $acc to Service Logon Privileges on $env:ComputerName"
                                        } elseif ($SLline -notmatch $SID) {
                                            (Get-Content $tempfile) -replace "SeServiceLogonRight = ", "SeServiceLogonRight = *$SID," |
                                                Set-Content $tempfile
                                            <# DO NOT use Write-Message as this is inside of a script block #>
                                            Write-Verbose "Added $acc to Service Logon Privileges on $env:ComputerName"
                                        } else {
                                            <# DO NOT use Write-Message as this is inside of a script block #>
                                            Write-Verbose "$acc already has Service Logon Privilege on $env:ComputerName"
                                        }
                                    }
                                }
                                $null = secedit /configure /cfg $tempfile /db secedit.sdb /areas USER_RIGHTS /overwrite /quiet
                            } -ErrorAction SilentlyContinue
                            Write-Message -Level Verbose -Message "Removing secpol file on $computer"
                            Invoke-Command2 -Raw -ComputerName $computer -Credential $Credential -ScriptBlock { $temp = ([System.IO.Path]::GetTempPath()).TrimEnd(""); Remove-Item $temp\secpolByDbatools.cfg -Force > $NULL }
                        } else {
                            Write-Message -Level Warning -Message "No SQL Service Accounts found on $Computer"
                        }
                    } else {
                        Write-Message -Level Warning -Message "Failed to connect to $Computer"
                    }
                } catch {
                    Stop-Function -Message "Failure" -ErrorRecord $_ -Target $computer -Continue
                }
            }
        }
    }
}
# SIG # Begin signature block
# MIIjYAYJKoZIhvcNAQcCoIIjUTCCI00CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCC0HK6ngxGMo0v4
# b59N2nNvAy136BnZuYSA0LH31bWyZqCCHVkwggUaMIIEAqADAgECAhADBbuGIbCh
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
# BgorBgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCCzKhXIjX/yyxguI46SxIE8weyY
# SPVTzItx+ed/llKu8TANBgkqhkiG9w0BAQEFAASCAQARaUPHqOYG2jP+8l1me93q
# wC3EZwru+/NligQ/E0gqjQo2tT/MptTr5n4a4bna+cv09Xc9Xkj/+4L8WcTBgTWt
# 8Z6t3s69ZQypFR4+bZptZ6rS60hdl+M5s/o3+bCnO/1tYRCOGtGi7KNKUoJfMOkE
# Ms4XoL+h9ggS/mvzSmN6ECcIbslEeONES9KUjFgKjF5THN8cUOKM7F685t+4kL6z
# HZtJ2c38vUsclMF/esTmtiIevGA7K0w1f44mAiKQHx4aEdb7s6Un23w+fpr2mEPw
# UoOoYx+A/n/AJJ8jOeYoJRLDDac6CH2qqV4gAKpiLTy5w3GzS2NVr6ZjT2E0+7xi
# oYIDIDCCAxwGCSqGSIb3DQEJBjGCAw0wggMJAgEBMHcwYzELMAkGA1UEBhMCVVMx
# FzAVBgNVBAoTDkRpZ2lDZXJ0LCBJbmMuMTswOQYDVQQDEzJEaWdpQ2VydCBUcnVz
# dGVkIEc0IFJTQTQwOTYgU0hBMjU2IFRpbWVTdGFtcGluZyBDQQIQDE1pckuU+jwq
# Sj0pB4A9WjANBglghkgBZQMEAgEFAKBpMBgGCSqGSIb3DQEJAzELBgkqhkiG9w0B
# BwEwHAYJKoZIhvcNAQkFMQ8XDTIyMTExNzA4NTczNVowLwYJKoZIhvcNAQkEMSIE
# IAvCKmDFp3JVUOGlD8iwKRNtbJRwr5R/G/JEvClC3RP+MA0GCSqGSIb3DQEBAQUA
# BIICAL7NFFcQrCTi/0l0tdEk0FERZEckmPeXU3XILiN7qXF9zQmOwZi+ebf4B2RE
# fW1NuCg6VlUFcNQMer30WyLufZZJ3Q6vRqfRoxYVy8zvF6kAfFA5fXKeQylCEkCF
# OcSXUjRJDb37XCyRPhVn0fPSqjN7sFZOlY5ASXGXQ/FqFjDK89oXnAmBJx8O0O4w
# L9cPGHf58AS5ljZc9ETdfdiVuYcvJJ6ZZ0Z/HIajq2PIEnBVjVK/j0od72n8DumG
# bVhGaMumxgHqMPVJfJ8+dYcpsFSo3pmkWYQf99O4NPHhW6vaeN8P8dpnpYtCkyR7
# Rm6tfOiRLcjMnAQ3r2fkHBMWz2aNnzYR7HHtY85gdQLnN5Z+34uuV1T5nVAL/Mk2
# U9r8la47fdkd/krz95p/dg0xw5QjyveKqPE2AaJCDp6kB/m0Q+OuLa6iamyoZA3Q
# PCVDO7wA4GUql4Qm8xk+B0QBMDo1CfNjuJN7iIJ041m23SQx6V+FgBhqxo37tUMe
# AT4sXk7KclEJPes8Gwai1Y25+nkwcyF0fRqPk+PcJmbsh7cowFiu3NlkSz0kF21A
# yj/h8JSgSgMxqBBbhOdjSezLKbfZEyvVqHbe6vGYR36FSTAkgyYpM3vJzuI04uQB
# W7peNuufS5v8SMyuBTMhrWvCpdLQtoDz5MaMNVtrKPXpXNuX
# SIG # End signature block
