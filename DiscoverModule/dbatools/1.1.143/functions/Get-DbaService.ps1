function Get-DbaService {
    <#
    .SYNOPSIS
        Gets the SQL Server related services on a computer.

    .DESCRIPTION
        Gets the SQL Server related services on one or more computers.

        Requires Local Admin rights on destination computer(s).

    .PARAMETER ComputerName
        The target computer(s).

    .PARAMETER InstanceName
        Only returns services that belong to the specific instances on all target computers.

    .PARAMETER SqlInstance
        Use a combination of computername and instancename to get the SQL Server related services for specific instances on specific computers.

        Parameters ComputerName and InstanceName will be ignored if SqlInstance is used.

    .PARAMETER Credential
        Credential object used to connect to the computer as a different user.

    .PARAMETER Type
        Use -Type to collect only services of the desired SqlServiceType.
        Can be one of the following: "Agent", "Browser", "Engine", "FullText", "SSAS", "SSIS", "SSRS", "PolyBase", "Launchpad"

    .PARAMETER ServiceName
        Can be used to specify service names explicitly, without looking for service types/instances.

    .PARAMETER AdvancedProperties
        Collect additional properties from the SqlServiceAdvancedProperty Namespace
        This collects information about Version, Service Pack Level", SkuName, Clustered status and the Cluster Service Name
        This adds additional overhead to the command.

    .PARAMETER EnableException
        By default, when something goes wrong we try to catch it, interpret it and give you a friendly warning message.
        This avoids overwhelming you with "sea of red" exceptions, but is inconvenient because it basically disables advanced scripting.
        Using this switch turns this "nice by default" feature off and enables you to catch exceptions with your own try/catch.

    .NOTES
        Tags: Service, SqlServer, Instance, Connect
        Author: Klaas Vandenberghe (@PowerDbaKlaas)

        Website: https://dbatools.io
        Copyright: (c) 2018 by dbatools, licensed under MIT
        License: MIT https://opensource.org/licenses/MIT

    .LINK
        https://dbatools.io/Get-DbaService

    .EXAMPLE
        PS C:\> Get-DbaService -ComputerName sqlserver2014a

        Gets the SQL Server related services on computer sqlserver2014a.

    .EXAMPLE
        PS C:\> 'sql1','sql2','sql3' | Get-DbaService -AdvancedProperties

        Gets the SQL Server related services on computers sql1, sql2 and sql3. Includes Advanced Properties from the SqlServiceAdvancedProperty Namespace

    .EXAMPLE
        PS C:\> $cred = Get-Credential WindowsUser
        PS C:\> Get-DbaService -ComputerName sql1,sql2 -Credential $cred  | Out-GridView

        Gets the SQL Server related services on computers sql1 and sql2 via the user WindowsUser, and shows them in a grid view.

    .EXAMPLE
        PS C:\> Get-DbaService -ComputerName sql1,sql2 -InstanceName MSSQLSERVER

        Gets the SQL Server related services related to the default instance MSSQLSERVER on computers sql1 and sql2.

    .EXAMPLE
        PS C:\> Get-DbaService -SqlInstance sql1, sql1\test, sql2\test

        Gets the SQL Server related services related to the default instance MSSQLSERVER on computers sql1, the named instances test on sql1 and sql2.

    .EXAMPLE
        PS C:\> Get-DbaService -ComputerName $MyServers -Type SSRS

        Gets the SQL Server related services of type "SSRS" (Reporting Services) on computers in the variable MyServers.

    .EXAMPLE
        PS C:\> $MyServers =  Get-Content .\servers.txt
        PS C:\> Get-DbaService -ComputerName $MyServers -ServiceName MSSQLSERVER,SQLSERVERAGENT

        Gets the SQL Server related services with ServiceName MSSQLSERVER or SQLSERVERAGENT  for all the servers that are stored in the file. Every line in the file can only contain one hostname for a server.

    .EXAMPLE
        PS C:\> $services = Get-DbaService -ComputerName sql1 -Type Agent,Engine
        PS C:\> $services.ChangeStartMode('Manual')

        Gets the SQL Server related services of types Sql Agent and DB Engine on computer sql1 and changes their startup mode to 'Manual'.

    .EXAMPLE
        PS C:\> (Get-DbaService -ComputerName sql1 -Type Engine).Restart($true)

        Calls a Restart method for each Engine service on computer sql1.

    #>
    [CmdletBinding(DefaultParameterSetName = "Search")]
    param (
        [parameter(ValueFromPipeline, Position = 1)]
        [Alias("cn", "host", "Server")]
        [DbaInstanceParameter[]]$ComputerName = $env:COMPUTERNAME,
        [Parameter(ParameterSetName = "Search")]
        [Alias("Instance")]
        [string[]]$InstanceName,
        [Parameter(ParameterSetName = "Search")]
        [DbaInstanceParameter[]]$SqlInstance,
        [PSCredential]$Credential,
        [Parameter(ParameterSetName = "Search")]
        [ValidateSet("Agent", "Browser", "Engine", "FullText", "SSAS", "SSIS", "SSRS", "PolyBase", "Launchpad")]
        [string[]]$Type,
        [Parameter(ParameterSetName = "ServiceName")]
        [string[]]$ServiceName,
        [switch]$AdvancedProperties,
        [switch]$EnableException
    )

    begin {
        if ($SqlInstance) {
            # If SqlInstance is used, we select the list of computers for ComputerName
            $ComputerName = $SqlInstance | Select-Object -ExpandProperty ComputerName -Unique
        }

        #Dictionary to transform service type IDs into the names from Microsoft.SqlServer.Management.Smo.Wmi.ManagedComputer.Services.Type
        $ServiceIdMap = @(
            @{ Name = "Engine"; Id = 1 },
            @{ Name = "Agent"; Id = 2 },
            @{ Name = "FullText"; Id = 3, 9 },
            @{ Name = "SSIS"; Id = 4 },
            @{ Name = "SSAS"; Id = 5 },
            @{ Name = "SSRS"; Id = 6 },
            @{ Name = "Browser"; Id = 7 },
            @{ Name = "PolyBase"; Id = 10, 11 },
            @{ Name = "Launchpad"; Id = 12 },
            @{ Name = "Unknown"; Id = 8 }
        )
        if ($PsCmdlet.ParameterSetName -match 'Search') {
            if ($Type) {
                $searchClause = ""
                foreach ($itemType in $Type) {
                    foreach ($id in ($ServiceIdMap | Where-Object { $_.Name -eq $itemType }).Id) {
                        if ($searchClause) { $searchClause += ' OR ' }
                        $searchClause += "SQLServiceType = $id"
                    }
                }
            } else {
                $searchClause = "SQLServiceType > 0"
            }
        } elseif ($PsCmdlet.ParameterSetName -match 'ServiceName') {
            if ($ServiceName) {
                $searchClause = ""
                foreach ($sn in $ServiceName) {
                    if ($searchClause) { $searchClause += ' OR ' }
                    $searchClause += "ServiceName = '$sn'"
                }
            } else {
                $searchClause = "SQLServiceType > 0"
            }
        }
    }
    process {
        foreach ($computer in $ComputerName.ComputerName) {
            if ($SqlInstance) {
                # If SqlInstance is used, we select the list of instances for the current computer
                $InstanceName = $SqlInstance | Where-Object ComputerName -eq $computer | Select-Object -ExpandProperty InstanceName
            }

            try {
                $resolvedComputerName = (Resolve-DbaNetworkName -ComputerName $computer -Credential $Credential -EnableException).FullComputerName
                $null = Get-DbaCmObject -ComputerName $resolvedComputerName -Credential $Credential -Namespace root\Microsoft -ClassName __NAMESPACE -EnableException
            } catch {
                Stop-Function -Message "Failed to resolve or to connect to $computer." -Target $computer -Category ConnectionError -ErrorRecord $_ -Continue
            }

            $namespaces = @( )
            $services = @()
            $outputServices = @()

            if (!$Type -or 'SSRS' -in $Type) {
                Write-Message -Level Verbose -Message "Getting SQL Reporting Server services on $computer" -Target $computer
                $reportingServices = Get-DbaReportingService -ComputerName $resolvedComputerName -InstanceName $InstanceName -Credential $Credential -ServiceName $ServiceName
                $outputServices += $reportingServices
            }

            Write-Message -Level Verbose -Message "Getting SQL Server namespaces on $computer" -Target $computer
            try {
                $namespaces = Get-DbaCmObject -ComputerName $resolvedComputerName -Credential $Credential -Namespace root\Microsoft\SQLServer -Query "Select Name FROM __NAMESPACE WHERE Name Like 'ComputerManagement%'" -EnableException | Sort-Object Name -Descending
                Write-Message -Level Verbose -Message "The following namespaces have been found: $($namespaces.Name -join ', ')."
            } catch {
                Write-Message -Level Verbose -Message "No namespaces found in relevant namespace on $computer."
            }

            foreach ($namespace in $namespaces) {
                try {
                    Write-Message -Level Verbose -Message "Getting Cim class SqlService in Namespace $($namespace.Name) on $computer." -Target $computer
                    foreach ($service in (Get-DbaCmObject -ComputerName $resolvedComputerName -Credential $Credential -Namespace "root\Microsoft\SQLServer\$($namespace.Name)" -Query "SELECT * FROM SqlService WHERE $searchClause" -EnableException)) {
                        Write-Message -Level Verbose -Message "Found service $($service.ServiceName) in namespace $($namespace.Name)."
                        $services += $service
                    }
                    # Use highest namespace available, so break if services have been found
                    break
                } catch {
                    Write-Message -Level Verbose -Message "Failed to acquire services from namespace $($namespace.Name)." -Target $Computer -ErrorRecord $_
                }
            }

            # Remove services returned by the SSRS namespace
            $services = $services | Where-Object ServiceName -notin $reportingServices.ServiceName

            # Add custom properties and methods to the service objects
            foreach ($service in $services) {
                Add-Member -Force -InputObject $service -MemberType NoteProperty -Name ComputerName -Value $service.HostName
                Add-Member -Force -InputObject $service -MemberType NoteProperty -Name ServiceType -Value ($ServiceIdMap | Where-Object { $_.Id -contains $service.SQLServiceType }).Name
                Add-Member -Force -InputObject $service -MemberType NoteProperty -Name State -Value $(switch ($service.State) { 1 { 'Stopped' } 2 { 'Start Pending' }  3 { 'Stop Pending' } 4 { 'Running' } })
                Add-Member -Force -InputObject $service -MemberType NoteProperty -Name StartMode -Value $(switch ($service.StartMode) { 1 { 'Unknown' } 2 { 'Automatic' }  3 { 'Manual' } 4 { 'Disabled' } })

                if ($service.ServiceName -in ("MSSQLSERVER", "SQLSERVERAGENT", "ReportServer", "MSSQLServerOLAPService", "MSSQLFDLauncher", "SQLPBDMS", "SQLPBENGINE", "MSSQLLAUNCHPAD")) {
                    $instance = "MSSQLSERVER"
                } else {
                    if ($service.ServiceType -in @("Agent", "Engine", "SSRS", "SSAS", "FullText", "PolyBase", "Launchpad")) {
                        if ($service.ServiceName.indexof('$') -ge 0) {
                            $instance = $service.ServiceName.split('$')[1]
                        } else {
                            $instance = "Unknown"
                        }
                    } else {
                        $instance = ""
                    }
                }
                $priority = switch ($service.ServiceType) {
                    "Engine" { 200 }
                    default { 100 }
                }
                #If only specific instances are selected
                if (!$InstanceName -or $instance -in $InstanceName) {
                    #Add other properties and methods
                    Add-Member -Force -InputObject $service -NotePropertyName InstanceName -NotePropertyValue $instance
                    Add-Member -Force -InputObject $service -NotePropertyName ServicePriority -NotePropertyValue $priority
                    Add-Member -Force -InputObject $service -MemberType ScriptMethod -Name "Stop" -Value {
                        param ([bool]$Force = $false)
                        Stop-DbaService -InputObject $this -Force:$Force
                    }
                    Add-Member -Force -InputObject $service -MemberType ScriptMethod -Name "Start" -Value { Start-DbaService -InputObject $this }
                    Add-Member -Force -InputObject $service -MemberType ScriptMethod -Name "Restart" -Value {
                        param ([bool]$Force = $false)
                        Restart-DbaService -InputObject $this -Force:$Force
                    }
                    Add-Member -Force -InputObject $service -MemberType ScriptMethod -Name "ChangeStartMode" -Value {
                        param (
                            [parameter(Mandatory)]
                            [string]$Mode
                        )
                        $supportedModes = @("Automatic", "Manual", "Disabled")
                        if ($Mode -notin $supportedModes) {
                            Stop-Function -Message ("Incorrect mode '$Mode'. Use one of the following values: {0}" -f ($supportedModes -join ' | ')) -EnableException $false -FunctionName 'Get-DbaService'
                            Return
                        }
                        Set-ServiceStartMode -InputObject $this -Mode $Mode -ErrorAction Stop
                        $this.StartMode = $Mode
                    }

                    if ($AdvancedProperties) {
                        $namespaceValue = $service.CimClass.ToString().ToUpper().Replace(":SQLSERVICE", "").Replace("ROOT/MICROSOFT/SQLSERVER/", "")
                        $serviceAdvancedProperties = Get-DbaCmObject -ComputerName $Computer -Namespace "root\Microsoft\SQLServer\$($namespaceValue)" -Query "SELECT * FROM SqlServiceAdvancedProperty WHERE ServiceName = '$($service.ServiceName)'"

                        Add-Member -Force -InputObject $service -MemberType NoteProperty -Name Version -Value ($serviceAdvancedProperties | Where-Object PropertyName -eq 'VERSION' ).PropertyStrValue
                        Add-Member -Force -InputObject $service -MemberType NoteProperty -Name SPLevel -Value ($serviceAdvancedProperties | Where-Object PropertyName -eq 'SPLEVEL' ).PropertyNumValue
                        Add-Member -Force -InputObject $service -MemberType NoteProperty -Name SkuName -Value ($serviceAdvancedProperties | Where-Object PropertyName -eq 'SKUNAME' ).PropertyStrValue

                        $ClusterServiceTypeList = @(1, 2, 5, 7)
                        if ($ClusterServiceTypeList -contains $service.SQLServiceType) {
                            Add-Member -Force -InputObject $service -MemberType NoteProperty -Name Clustered -Value ($serviceAdvancedProperties | Where-Object PropertyName -eq 'CLUSTERED' ).PropertyNumValue
                            Add-Member -Force -InputObject $service -MemberType NoteProperty -Name VSName -Value ($serviceAdvancedProperties | Where-Object PropertyName -eq 'VSNAME' ).PropertyStrValue
                        } else {
                            Add-Member -Force -InputObject $service -MemberType NoteProperty -Name Clustered -Value ''
                            Add-Member -Force -InputObject $service -MemberType NoteProperty -Name VSName -Value ''
                        }
                    }
                    $outputServices += $service
                }
            }
            if ($AdvancedProperties) {
                $defaults = "ComputerName", "ServiceName", "ServiceType", "InstanceName", "DisplayName", "StartName", "State", "StartMode", "Version", "SPLevel", "SkuName", "Clustered", "VSName"
            } else {
                $defaults = "ComputerName", "ServiceName", "ServiceType", "InstanceName", "DisplayName", "StartName", "State", "StartMode"
            }
            if ($outputServices) {
                $outputServices | Select-DefaultView -Property $defaults -TypeName DbaSqlService
            } else {
                Write-Message -Level Verbose -Message "No services found in relevant namespaces on $computer."
            }
        }
    }
}
# SIG # Begin signature block
# MIIjYAYJKoZIhvcNAQcCoIIjUTCCI00CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCB7csKx9QwFMzJ4
# cN8tYD9/kHIsUT5eVkpO+Dv7vs13QKCCHVkwggUaMIIEAqADAgECAhADBbuGIbCh
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
# BgorBgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCAAebwoiTcK13MgeZ7xUF6S3I0s
# 97I8maLfdIjfSqT6SzANBgkqhkiG9w0BAQEFAASCAQAbZ5GJiBdHyBcDZae1CaaP
# MO+j4W9/NufOI29Reth9M3yf3vH6oD4vqBHQhYKM2Bc8xNNuSodafrCra5jTqdqy
# Of5nAqGT72GhO0DNDatu7qYMxEV48QlVVOLBVJA1mdb1t16kcg30Wd6AiCZc4bqU
# I9XNG2eYbLOjd/wwQDRc7Z6jPv9tgskZV6LpD6Fm/G7A4G6gwxKQhpJxK8CvsUKD
# HqddUEzv1MnYKk0HmcJeIkEj+uhNJ7KR+YnaErDqtNN4NFHP+QGvllBjZ4ljescJ
# ZH8qOE7RgP0QlX74eP6JaLcCbYSckwBKYoD8RbGyYXwX0n5Moo6ifnnBCieU6hwy
# oYIDIDCCAxwGCSqGSIb3DQEJBjGCAw0wggMJAgEBMHcwYzELMAkGA1UEBhMCVVMx
# FzAVBgNVBAoTDkRpZ2lDZXJ0LCBJbmMuMTswOQYDVQQDEzJEaWdpQ2VydCBUcnVz
# dGVkIEc0IFJTQTQwOTYgU0hBMjU2IFRpbWVTdGFtcGluZyBDQQIQDE1pckuU+jwq
# Sj0pB4A9WjANBglghkgBZQMEAgEFAKBpMBgGCSqGSIb3DQEJAzELBgkqhkiG9w0B
# BwEwHAYJKoZIhvcNAQkFMQ8XDTIyMTExNzA4NTYyNVowLwYJKoZIhvcNAQkEMSIE
# IBw9P4XKbMsPxUjtzn7T7q23UIKa4SM/hDLAZJqiX3KjMA0GCSqGSIb3DQEBAQUA
# BIICAMGjw/wKJHot7IhH+3QpYYDDRM/w3Gdsh96zTyy2Y1UMFkCzRk85nMEN4hH/
# C3+QitBGwpVTV+KqJQcZClfkYrIuy9fca4u0r2xbo/go9xpA3i7pP9CuRuBdrrXh
# cXWa5yR1Jb+oFmPKzUecL+IjiWOm8RTSuoPbZ1/pY12KbIGID8AmtO1opZq443Re
# 6851vIX/DVfxI72AaVCWNrRfZzY4pXqdV2ry5uyWWkCAG0Qwx7AiM9oBkMIDiB6t
# xnMSxFpheDqCcFa2XXY2J7ln2hTI01CIlaF9jwKODP7l+4UkL5nWPOGdoSquuJq+
# m9iKTmc+Tq3s5ZbxdoPzTuEa8eaKlxOcZGvfkL+DT3Z0zJhP67BVwFniOZ7pSJbi
# clY99/XpECoWADxRqicR4QKCrS6x8rwrcGoDyL75di1GiVAi29tpc7qbEmh/wc6H
# VDQ9ZUK58Bo1OXN85fxnPsdKU6rm5anMrv+HVzWKUZhWULbIgXRBohf7Fv2aS5Lv
# i/9m7WW0ryhkzE/POnavJzbeW55s4QtPUBw+FYVt02cXZOpyrtaWKDuVVmwtady1
# usJzdRqqlFHZlZ11q9UWLE9TjtR92mAxPKi57rsVjVQ+yOTTX7EdFeSqVqYTVHmD
# onBgp13SaUNNgXFhZd/KtCZ/s4fPqlL4/LqBSpn6tjYsy3eX
# SIG # End signature block
