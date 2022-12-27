function Copy-DbaAgentJobCategory {
    <#
    .SYNOPSIS
        Copy-DbaAgentJobCategory migrates SQL Agent categories from one SQL Server to another. This is similar to sp_add_category.

    .DESCRIPTION
        By default, all SQL Agent categories for Jobs, Operators and Alerts are copied.

        The -OperatorCategories parameter is auto-populated for command-line completion and can be used to copy only specific operator categories.
        The -AgentCategories parameter is auto-populated for command-line completion and can be used to copy only specific agent categories.
        The -JobCategories parameter is auto-populated for command-line completion and can be used to copy only specific job categories.

        If the category already exists on the destination, it will be skipped unless -Force is used.

    .PARAMETER Source
        Source SQL Server. You must have sysadmin access and server version must be SQL Server version 2000 or higher.

    .PARAMETER SourceSqlCredential
        Login to the target instance using alternative credentials. Accepts PowerShell credentials (Get-Credential).

        Windows Authentication, SQL Server Authentication, Active Directory - Password, and Active Directory - Integrated are all supported.

        For MFA support, please use Connect-DbaInstance.

    .PARAMETER Destination
        Destination SQL Server. You must have sysadmin access and the server must be SQL Server 2000 or higher.

    .PARAMETER DestinationSqlCredential
        Login to the target instance using alternative credentials. Accepts PowerShell credentials (Get-Credential).

        Windows Authentication, SQL Server Authentication, Active Directory - Password, and Active Directory - Integrated are all supported.

        For MFA support, please use Connect-DbaInstance.

    .PARAMETER CategoryType
        Specifies the Category Type to migrate. Valid options are "Job", "Alert" and "Operator". When CategoryType is specified, all categories from the selected type will be migrated. For granular migrations, use the three parameters below.

    .PARAMETER OperatorCategory
        This parameter is auto-populated for command-line completion and can be used to copy only specific operator categories.

    .PARAMETER AgentCategory
        This parameter is auto-populated for command-line completion and can be used to copy only specific agent categories.

    .PARAMETER JobCategory
        This parameter is auto-populated for command-line completion and can be used to copy only specific job categories.

    .PARAMETER WhatIf
        If this switch is enabled, no actions are performed but informational messages will be displayed that explain what would happen if the command were to run.

    .PARAMETER Confirm
        If this switch is enabled, you will be prompted for confirmation before executing any operations that change state.

    .PARAMETER Force
        If this switch is enabled, the Category will be dropped and recreated on Destination.

    .PARAMETER EnableException
        By default, when something goes wrong we try to catch it, interpret it and give you a friendly warning message.
        This avoids overwhelming you with "sea of red" exceptions, but is inconvenient because it basically disables advanced scripting.
        Using this switch turns this "nice by default" feature off and enables you to catch exceptions with your own try/catch.

    .NOTES
        Tags: Migration, Agent
        Author: Chrissy LeMaire (@cl), netnerds.net

        Website: https://dbatools.io
        Copyright: (c) 2018 by dbatools, licensed under MIT
        License: MIT https://opensource.org/licenses/MIT

        Requires: sysadmin access on SQL Servers

    .LINK
        https://dbatools.io/Copy-DbaAgentJobCategory

    .EXAMPLE
        PS C:\> Copy-DbaAgentJobCategory -Source sqlserver2014a -Destination sqlcluster

        Copies all operator categories from sqlserver2014a to sqlcluster using Windows authentication. If operator categories with the same name exist on sqlcluster, they will be skipped.

    .EXAMPLE
        PS C:\> Copy-DbaAgentJobCategory -Source sqlserver2014a -Destination sqlcluster -OperatorCategory PSOperator -SourceSqlCredential $cred -Force

        Copies a single operator category, the PSOperator operator category from sqlserver2014a to sqlcluster using SQL credentials to authenticate to sqlserver2014a and Windows credentials for sqlcluster. If an operator category with the same name exists on sqlcluster, it will be dropped and recreated because -Force was used.

    .EXAMPLE
        PS C:\> Copy-DbaAgentJobCategory -Source sqlserver2014a -Destination sqlcluster -WhatIf -Force

        Shows what would happen if the command were executed using force.

    #>
    [CmdletBinding(DefaultParameterSetName = "Default", SupportsShouldProcess, ConfirmImpact = "Medium")]
    param (
        [parameter(Mandatory)]
        [DbaInstanceParameter]$Source,
        [PSCredential]$SourceSqlCredential,
        [parameter(Mandatory)]
        [DbaInstanceParameter[]]$Destination,
        [PSCredential]$DestinationSqlCredential,
        [Parameter(ParameterSetName = 'SpecificAlerts')]
        [ValidateSet('Job', 'Alert', 'Operator')]
        [string[]]$CategoryType,
        [string[]]$JobCategory,
        [string[]]$AgentCategory,
        [string[]]$OperatorCategory,
        [switch]$Force,
        [switch]$EnableException
    )

    begin {
        function Copy-JobCategory {
            <#
                .SYNOPSIS
                    Copy-JobCategory migrates job categories from one SQL Server to another.

                .DESCRIPTION
                    By default, all job categories are copied. The -JobCategories parameter is auto-populated for command-line completion and can be used to copy only specific job categories.

                    If the associated credential for the category does not exist on the destination, it will be skipped. If the job category already exists on the destination, it will be skipped unless -Force is used.
            #>
            param (
                [string[]]$jobCategories
            )

            process {

                $serverJobCategories = $sourceServer.JobServer.JobCategories | Where-Object ID -ge 100
                $destJobCategories = $destServer.JobServer.JobCategories | Where-Object ID -ge 100

                foreach ($jobCategory in $serverJobCategories) {
                    $categoryName = $jobCategory.Name

                    $copyJobCategoryStatus = [pscustomobject]@{
                        SourceServer      = $sourceServer.Name
                        DestinationServer = $destServer.Name
                        Name              = $categoryName
                        Type              = "Agent Job Category"
                        Status            = $null
                        Notes             = $null
                        DateTime          = [Sqlcollaborative.Dbatools.Utility.DbaDateTime](Get-Date)
                    }

                    if ($jobCategories.Count -gt 0 -and $jobCategories -notcontains $categoryName) {
                        continue
                    }

                    if ($destJobCategories.Name -contains $jobCategory.name) {
                        if ($force -eq $false) {
                            $copyJobCategoryStatus.Status = "Skipped"
                            $copyJobCategoryStatus.Notes = "Already exists on destination"
                            $copyJobCategoryStatus | Select-DefaultView -Property DateTime, SourceServer, DestinationServer, Name, Type, Status, Notes -TypeName MigrationObject
                            Write-Message -Level Verbose -Message "Job category $categoryName exists at destination. Use -Force to drop and migrate."
                            continue
                        } else {
                            if ($Pscmdlet.ShouldProcess($destinstance, "Dropping job category $categoryName")) {
                                try {
                                    Write-Message -Level Verbose -Message "Dropping Job category $categoryName"
                                    $destServer.JobServer.JobCategories[$categoryName].Drop()
                                } catch {
                                    $copyJobCategoryStatus.Status = "Failed"
                                    $copyJobCategoryStatus | Select-DefaultView -Property DateTime, SourceServer, DestinationServer, Name, Type, Status, Notes -TypeName MigrationObject
                                    Stop-Function -Message "Issue dropping job category" -Target $categoryName -ErrorRecord $_ -Continue
                                }
                            }
                        }
                    }

                    if ($Pscmdlet.ShouldProcess($destinstance, "Creating Job category $categoryName")) {
                        try {
                            Write-Message -Level Verbose -Message "Copying Job category $categoryName"
                            $sql = $jobCategory.Script() | Out-String
                            Write-Message -Level Debug -Message "SQL Statement: $sql"
                            $destServer.Query($sql)

                            $copyJobCategoryStatus.Status = "Successful"
                            $copyJobCategoryStatus | Select-DefaultView -Property DateTime, SourceServer, DestinationServer, Name, Type, Status, Notes -TypeName MigrationObject
                        } catch {
                            $copyJobCategoryStatus.Status = "Failed"
                            $copyJobCategoryStatus | Select-DefaultView -Property DateTime, SourceServer, DestinationServer, Name, Type, Status, Notes -TypeName MigrationObject
                            Stop-Function -Message "Issue copying job category" -Target $categoryName -ErrorRecord $_
                        }
                    }
                }
            }
        }

        function Copy-OperatorCategory {
            <#
                .SYNOPSIS
                    Copy-OperatorCategory migrates operator categories from one SQL Server to another.

                .DESCRIPTION
                    By default, all operator categories are copied. The -OperatorCategories parameter is auto-populated for command-line completion and can be used to copy only specific operator categories.

                    If the associated credential for the category does not exist on the destination, it will be skipped. If the operator category already exists on the destination, it will be skipped unless -Force is used.
            #>
            [CmdletBinding(DefaultParameterSetName = "Default", SupportsShouldProcess)]
            param (
                [string[]]$operatorCategories
            )
            process {
                $serverOperatorCategories = $sourceServer.JobServer.OperatorCategories | Where-Object ID -ge 100
                $destOperatorCategories = $destServer.JobServer.OperatorCategories | Where-Object ID -ge 100

                foreach ($operatorCategory in $serverOperatorCategories) {
                    $categoryName = $operatorCategory.Name

                    $copyOperatorCategoryStatus = [pscustomobject]@{
                        SourceServer      = $sourceServer.Name
                        DestinationServer = $destServer.Name
                        Type              = "Agent Operator Category"
                        Name              = $categoryName
                        Status            = $null
                        Notes             = $null
                        DateTime          = [Sqlcollaborative.Dbatools.Utility.DbaDateTime](Get-Date)
                    }

                    if ($operatorCategories.Count -gt 0 -and $operatorCategories -notcontains $categoryName) {
                        continue
                    }

                    if ($destOperatorCategories.Name -contains $operatorCategory.Name) {
                        if ($force -eq $false) {
                            $copyOperatorCategoryStatus.Status = "Skipped"
                            $copyOperatorCategoryStatus.Notes = "Already exists on destination"
                            $copyOperatorCategoryStatus | Select-DefaultView -Property DateTime, SourceServer, DestinationServer, Name, Type, Status, Notes -TypeName MigrationObject
                            Write-Message -Level Verbose -Message "Operator category $categoryName exists at destination. Use -Force to drop and migrate."
                            continue
                        } else {
                            if ($Pscmdlet.ShouldProcess($destinstance, "Dropping operator category $categoryName and recreating")) {
                                try {
                                    Write-Message -Level Verbose -Message "Dropping Operator category $categoryName"
                                    $destServer.JobServer.OperatorCategories[$categoryName].Drop()
                                    Write-Message -Level Verbose -Message "Copying Operator category $categoryName"
                                    $sql = $operatorCategory.Script() | Out-String
                                    Write-Message -Level Debug -Message $sql
                                    $destServer.Query($sql)
                                } catch {
                                    $copyOperatorCategoryStatus.Status = "Failed"
                                    $copyOperatorCategoryStatus | Select-DefaultView -Property DateTime, SourceServer, DestinationServer, Name, Type, Status, Notes -TypeName MigrationObject
                                    Stop-Function -Message "Issue dropping operator category" -Target $categoryName -ErrorRecord $_
                                }
                            }
                        }
                    } else {
                        if ($Pscmdlet.ShouldProcess($destinstance, "Creating Operator category $categoryName")) {
                            try {
                                Write-Message -Level Verbose -Message "Copying Operator category $categoryName"
                                $sql = $operatorCategory.Script() | Out-String
                                Write-Message -Level Debug -Message $sql
                                $destServer.Query($sql)

                                $copyOperatorCategoryStatus.Status = "Successful"
                                $copyOperatorCategoryStatus | Select-DefaultView -Property DateTime, SourceServer, DestinationServer, Name, Type, Status, Notes -TypeName MigrationObject
                            } catch {
                                $copyOperatorCategoryStatus.Status = "Failed"
                                $copyOperatorCategoryStatus | Select-DefaultView -Property DateTime, SourceServer, DestinationServer, Name, Type, Status, Notes -TypeName MigrationObject
                                Stop-Function -Message "Issue copying operator category" -Target $categoryName -ErrorRecord $_
                            }
                        }
                    }
                }
            }
        }

        function Copy-AlertCategory {
            <#
                .SYNOPSIS
                    Copy-AlertCategory migrates alert categories from one SQL Server to another.

                .DESCRIPTION
                    By default, all alert categories are copied. The -AlertCategories parameter is auto-populated for command-line completion and can be used to copy only specific alert categories.

                    If the associated credential for the category does not exist on the destination, it will be skipped. If the alert category already exists on the destination, it will be skipped unless -Force is used.
            #>
            [CmdletBinding(DefaultParameterSetName = "Default", SupportsShouldProcess)]
            param (
                [string[]]$AlertCategories
            )

            process {
                if ($sourceServer.VersionMajor -lt 9 -or $destServer.VersionMajor -lt 9) {
                    throw "Server AlertCategories are only supported in SQL Server 2005 and above. Quitting."
                }

                $serverAlertCategories = $sourceServer.JobServer.AlertCategories | Where-Object ID -ge 100
                $destAlertCategories = $destServer.JobServer.AlertCategories | Where-Object ID -ge 100

                foreach ($alertCategory in $serverAlertCategories) {
                    $categoryName = $alertCategory.Name

                    $copyAlertCategoryStatus = [pscustomobject]@{
                        SourceServer      = $sourceServer.Name
                        DestinationServer = $destServer.Name
                        Type              = "Agent Alert Category"
                        Name              = $categoryName
                        Status            = $null
                        Notes             = $null
                        DateTime          = [Sqlcollaborative.Dbatools.Utility.DbaDateTime](Get-Date)
                    }

                    if ($alertCategories.Length -gt 0 -and $alertCategories -notcontains $categoryName) {
                        continue
                    }

                    if ($destAlertCategories.Name -contains $alertCategory.name) {
                        if ($force -eq $false) {
                            $copyAlertCategoryStatus.Status = "Skipped"
                            $copyAlertCategoryStatus.Notes = "Already exists on destination"
                            $copyAlertCategoryStatus | Select-DefaultView -Property DateTime, SourceServer, DestinationServer, Name, Type, Status, Notes -TypeName MigrationObject
                            Write-Message -Level Verbose -Message "Alert category $categoryName exists at destination. Use -Force to drop and migrate."
                            continue
                        } else {
                            if ($Pscmdlet.ShouldProcess($destinstance, "Dropping alert category $categoryName and recreating")) {
                                try {
                                    Write-Message -Level Verbose -Message "Dropping Alert category $categoryName"
                                    $destServer.JobServer.AlertCategories[$categoryName].Drop()
                                    Write-Message -Level Verbose -Message "Copying Alert category $categoryName"
                                    $sql = $alertcategory.Script() | Out-String
                                    Write-Message -Level Debug -Message "SQL Statement: $sql"
                                    $destServer.Query($sql)
                                } catch {
                                    $copyAlertCategoryStatus.Status = "Failed"
                                    $copyAlertCategoryStatus | Select-DefaultView -Property DateTime, SourceServer, DestinationServer, Name, Type, Status, Notes -TypeName MigrationObject
                                    Stop-Function -Message "Issue dropping alert category" -Target $categoryName -ErrorRecord $_
                                }
                            }
                        }
                    } else {
                        if ($Pscmdlet.ShouldProcess($destinstance, "Creating Alert category $categoryName")) {
                            try {
                                Write-Message -Level Verbose -Message "Copying Alert category $categoryName"
                                $sql = $alertCategory.Script() | Out-String
                                Write-Message -Level Debug -Message $sql
                                $destServer.Query($sql)

                                $copyAlertCategoryStatus.Status = "Successful"
                                $copyAlertCategoryStatus | Select-DefaultView -Property DateTime, SourceServer, DestinationServer, Name, Type, Status, Notes -TypeName MigrationObject
                            } catch {
                                $copyAlertCategoryStatus.Status = "Failed"
                                $copyAlertCategoryStatus | Select-DefaultView -Property DateTime, SourceServer, DestinationServer, Name, Type, Status, Notes -TypeName MigrationObject
                                Stop-Function -Message "Issue creating alert category" -Target $categoryName -ErrorRecord $_
                            }
                        }
                    }
                }
            }
        }

        try {
            $sourceServer = Connect-DbaInstance -SqlInstance $Source -SqlCredential $SourceSqlCredential
        } catch {
            Stop-Function -Message "Failure" -Category ConnectionError -ErrorRecord $_ -Target $Source
            return
        }

        if ($Force) { $ConfirmPreference = 'none' }
    }
    process {
        if (Test-FunctionInterrupt) { return }
        foreach ($destinstance in $Destination) {
            try {
                $destServer = Connect-DbaInstance -SqlInstance $destinstance -SqlCredential $DestinationSqlCredential
            } catch {
                Stop-Function -Message "Failure" -Category ConnectionError -ErrorRecord $_ -Target $destinstance -Continue
            }

            if ($CategoryType.count -gt 0) {

                switch ($CategoryType) {
                    "Job" {
                        Copy-JobCategory
                    }

                    "Alert" {
                        Copy-AlertCategory
                    }

                    "Operator" {
                        Copy-OperatorCategory
                    }
                }
                continue
            }

            if (($OperatorCategory.Count + $AlertCategory.Count + $jobCategory.Count) -gt 0) {

                if ($OperatorCategory.Count -gt 0) {
                    Copy-OperatorCategory -OperatorCategories $OperatorCategory
                }

                if ($AlertCategory.Count -gt 0) {
                    Copy-AlertCategory -AlertCategories $AlertCategory
                }

                if ($jobCategory.Count -gt 0) {
                    Copy-JobCategory -JobCategories $jobCategory
                }
                continue
            }
            Copy-OperatorCategory
            Copy-AlertCategory
            Copy-JobCategory
        }
    }
}
# SIG # Begin signature block
# MIIjYAYJKoZIhvcNAQcCoIIjUTCCI00CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCDCFhpflT8rJ3RW
# 012Rv8m3CMYAvtjAkFo2t5zOHEpMmaCCHVkwggUaMIIEAqADAgECAhADBbuGIbCh
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
# BgorBgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCBSwziBLv4AF7CJDZ2wvah+s9/f
# nELdY0t2ZtTkIMofHDANBgkqhkiG9w0BAQEFAASCAQCqSTUBoe4gKpx1VnD2hsAp
# fF9HWhvoNsic9wOf9+5yUKl42c2bf35wWbCbZauaXJezyAZzvChPmouSQ164IQ9Z
# SbA8IMyFtLkhxlOf05V6ksp1O01lrtDrPRSm3M03UatZA6hHe5X/NePt6ZXh/zjW
# 3AcJs87QvWi5KmB7H55eDLE57+5TdIeZZdKJ9hirUk1JtA+AtUGVMoC7zNFfgBvr
# k3PEZ3uSc7ajAKuIqG2jF0/uN5mc6yWw94jWUtN4mgc7Oydr4T/avhT5JxWhwrSx
# GWsrEFR8i1qLpySovf5PSSwQTLDtS7bpPhG65fEhugakNiRTTHagVOgsDA50w7jS
# oYIDIDCCAxwGCSqGSIb3DQEJBjGCAw0wggMJAgEBMHcwYzELMAkGA1UEBhMCVVMx
# FzAVBgNVBAoTDkRpZ2lDZXJ0LCBJbmMuMTswOQYDVQQDEzJEaWdpQ2VydCBUcnVz
# dGVkIEc0IFJTQTQwOTYgU0hBMjU2IFRpbWVTdGFtcGluZyBDQQIQDE1pckuU+jwq
# Sj0pB4A9WjANBglghkgBZQMEAgEFAKBpMBgGCSqGSIb3DQEJAzELBgkqhkiG9w0B
# BwEwHAYJKoZIhvcNAQkFMQ8XDTIyMTExNzA4NTUxNVowLwYJKoZIhvcNAQkEMSIE
# IKi/RkBIbpp8rYALGELjZRrLy2x8wVAjy87+ODfki6xCMA0GCSqGSIb3DQEBAQUA
# BIICAHTj+FLF1V0N5tvee0ewn7VInU1ExayamwIPU2HA2Bt8AwvmjsDCLFNFs8jh
# m3lhXfLM+TQu93mmnE+pG/O+bqRDj4bXh01RvrWtkNoAjA9Zz0aHzd3T3tOv7Qnz
# k/pugw0a6wa0TccT7GKHFuAdDkwXUrQek0Ht2+NcqcsVOTnUlUqkCCk2Pi3SjIoA
# zeMGLpzXRp8YJz/HSLTxu0kTNiWP413JAPcwyzgJ1mzT7H3KXYSiaMoMqgM8hqZi
# hzCohHW4Ev3gHLp6hv+inUEKTThJH4j7x/yPm78IL8I5C8jX4dc8ymDNS3N6Rjtb
# CrxHSHk1TWE/7O5z5cnR2IOyjt8YnOEC0SVxGioAdGgSQKKDZTb8epxgVp6GgwUA
# 4cILiT0Zp13GxuKYwl92v1QJvJjjbkjkVkZfasluLo8VpA2/rz1jveSJmbgXSW2v
# XdYdo0m/k1R/jf16Bl477GfFAJdBJiGo8EqzhJMyE7XY/HKOT1/cNr75z4YIuWmu
# uY4L3HYlLhbw/pwwKv6s6gMO3TcrvCfgOUqax0r5FP8vEtu2qskWW9TndfyDzZWj
# CPXIIy4fgGewv4MynNbdleQa2c/v/nqjFT5CFyVWsJ3BM+QznpYWmrCJvbvjWCLv
# AFOF6T96288j+QYFsHyJkminytm4v0DbbgG1VuJJ2wUhmPjS
# SIG # End signature block
