function New-DbaFirewallRule {
    <#
    .SYNOPSIS
        Creates a new inbound firewall rule for a SQL Server instance and adds the rule to the target computer.

    .DESCRIPTION
        Creates a new inbound firewall rule for a SQL Server instance and adds the rule to the target computer.

        This is basically a wrapper around New-NetFirewallRule executed at the target computer.
        So this only works if New-NetFirewallRule works on the target computer.

        Both DisplayName and Name are set to the same value, since DisplayName is required
        but only Name uniquely defines the rule, thus avoiding duplicate rules with different settings.
        The names and the group for all rules are fixed to be able to get them back with Get-DbaFirewallRule.

        The functionality is currently limited. Help to extend the functionality is welcome.

        As long as you can read this note here, there may be breaking changes in future versions.
        So please review your scripts using this command after updating dbatools.

        The firewall rule for the instance itself will have the following configuration (parameters for New-NetFirewallRule):

            DisplayName = 'SQL Server default instance' or 'SQL Server instance <InstanceName>'
            Name        = 'SQL Server default instance' or 'SQL Server instance <InstanceName>'
            Group       = 'SQL Server'
            Enabled     = 'True'
            Direction   = 'Inbound'
            Protocol    = 'TCP'
            LocalPort   = '<Port>' (for instances with static port)
            Program     = '<Path ending with MSSQL\Binn\sqlservr.exe>' (for instances with dynamic port)

        The firewall rule for the SQL Server Browser will have the following configuration (parameters for New-NetFirewallRule):

            DisplayName = 'SQL Server Browser'
            Name        = 'SQL Server Browser'
            Group       = 'SQL Server'
            Enabled     = 'True'
            Direction   = 'Inbound'
            Protocol    = 'UDP'
            LocalPort   = '1434'

        The firewall rule for the dedicated admin connection (DAC) will have the following configuration (parameters for New-NetFirewallRule):

            DisplayName = 'SQL Server default instance (DAC)' or 'SQL Server instance <InstanceName> (DAC)'
            Name        = 'SQL Server default instance (DAC)' or 'SQL Server instance <InstanceName> (DAC)'
            Group       = 'SQL Server'
            Enabled     = 'True'
            Direction   = 'Inbound'
            Protocol    = 'TCP'
            LocalPort   = '<Port>' (typically 1434 for a default instance, but will be fetched from ERRORLOG)

        The firewall rule for the DAC will only be created if the DAC is configured for listening remotely.
        Use `Set-DbaSpConfigure -SqlInstance SRV1 -Name RemoteDacConnectionsEnabled -Value 1` to enable remote DAC before running this command.

    .PARAMETER SqlInstance
        The target SQL Server instance or instances.

    .PARAMETER Credential
        Credential object used to connect to the Computer as a different user.

    .PARAMETER Type
        Creates firewall rules for the given type(s).

        Valid values are:
        * Engine - for the SQL Server instance
        * Browser - for the SQL Server Browser
        * DAC - for the dedicated admin connection (DAC)

        If this parameter is not used:
        * The firewall rule for the SQL Server instance will be created.
        * In case the instance is listening on a port other than 1433, also the firewall rule for the SQL Server Browser will be created if not already in place.
        * In case the DAC is configured for listening remotely, also the firewall rule for the DAC will be created.

    .PARAMETER Configuration
        A hashtable with custom configuration parameters that are used when calling New-NetFirewallRule.
        These will override the default settings.
        Parameters Name, DisplayName and Group are not allowed here and will be silently ignored.

        https://docs.microsoft.com/en-us/powershell/module/netsecurity/new-netfirewallrule

    .PARAMETER Force
        If the rule to be created already exists, a warning is displayed.
        If this switch is enabled, the rule will be deleted and created again.

    .PARAMETER EnableException
        By default, when something goes wrong we try to catch it, interpret it and give you a friendly warning message.
        This avoids overwhelming you with "sea of red" exceptions, but is inconvenient because it basically disables advanced scripting.
        Using this switch turns this "nice by default" feature off and enables you to catch exceptions with your own try/catch.

    .PARAMETER WhatIf
        If this switch is enabled, no actions are performed but informational messages will be displayed that explain what would happen if the command were to run.

    .PARAMETER Confirm
        If this switch is enabled, you will be prompted for confirmation before executing any operations that change state.

    .NOTES
        Tags: Network, Connection, Firewall
        Author: Andreas Jordan (@JordanOrdix), ordix.de

        Website: https://dbatools.io
        Copyright: (c) 2021 by dbatools, licensed under MIT
        License: MIT https://opensource.org/licenses/MIT

    .LINK
        https://dbatools.io/New-DbaFirewallRule

    .EXAMPLE
        PS C:\> New-DbaFirewallRule -SqlInstance SRV1, SRV1\TEST

        Automatically configures the needed firewall rules for both the default instance and the instance named TEST on SRV1.

    .EXAMPLE
        PS C:\> New-DbaFirewallRule -SqlInstance SRV1, SRV1\TEST -Configuration @{ Profile = 'Domain' }

        Automatically configures the needed firewall rules for both the default instance and the instance named TEST on SRV1,
        but configures the firewall rule for the domain profile only.

    .EXAMPLE
        PS C:\> New-DbaFirewallRule -SqlInstance SRV1\TEST -Type Engine -Force -Confirm:$false

        Creates or recreates the firewall rule for the instance TEST on SRV1. Does not prompt for confirmation.

    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = "High")]
    param (
        [parameter(Mandatory, ValueFromPipeline)]
        [DbaInstanceParameter[]]$SqlInstance,
        [PSCredential]$Credential,
        [ValidateSet('Engine', 'Browser', 'DAC')]
        [string[]]$Type,
        [hashtable]$Configuration,
        [switch]$Force,
        [switch]$EnableException
    )

    begin {
        if ($Configuration) {
            foreach ($notAllowedKey in 'Name', 'DisplayName', 'Group') {
                if ($notAllowedKey -in $Configuration.Keys) {
                    Write-Message -Level Verbose -Message "Key $notAllowedKey is not allowed in Configuration and will be removed."
                    $Configuration.Remove($notAllowedKey)
                }
            }
        }

        $cmdScriptBlock = {
            # This scriptblock will be processed by Invoke-Command2.
            $firewallRuleParameters = $args[0]
            $force = $args[1]

            try {
                if (-not (Get-Command -Name New-NetFirewallRule -ErrorAction SilentlyContinue)) {
                    throw 'The module NetSecurity with the command New-NetFirewallRule is missing on the target computer, so New-DbaFirewallRule is not supported.'
                }
                $successful = $true
                if ($force) {
                    $null = Remove-NetFirewallRule -Name $firewallRuleParameters.Name -WarningAction SilentlyContinue -ErrorAction SilentlyContinue
                }
                $cimInstance = New-NetFirewallRule @firewallRuleParameters -WarningVariable warn -ErrorVariable err -WarningAction SilentlyContinue -ErrorAction SilentlyContinue
                if ($warn.Count -gt 0) {
                    $successful = $false
                } else {
                    # Change from an empty System.Collections.ArrayList to $null for better readability
                    $warn = $null
                }
                if ($err.Count -gt 0) {
                    $successful = $false
                } else {
                    # Change from an empty System.Collections.ArrayList to $null for better readability
                    $err = $null
                }
                [PSCustomObject]@{
                    Successful  = $successful
                    CimInstance = $cimInstance
                    Warning     = $warn
                    Error       = $err
                    Exception   = $null
                }
            } catch {
                [PSCustomObject]@{
                    Successful  = $false
                    CimInstance = $null
                    Warning     = $null
                    Error       = $null
                    Exception   = $_
                }
            }
        }
    }

    process {
        foreach ($instance in $SqlInstance) {
            $rules = @( )
            $programNeeded = $false
            $browserNeeded = $false
            if ($PSBoundParameters.Type) {
                $browserOptional = $false
            } else {
                $browserOptional = $true
            }

            # Create rule for instance
            if (-not $PSBoundParameters.Type -or 'Engine' -in $PSBoundParameters.Type) {
                # Apply the defaults
                $rule = @{
                    Type         = 'Engine'
                    InstanceName = $instance.InstanceName
                    Config       = @{
                        Group     = 'SQL Server'
                        Enabled   = 'True'
                        Direction = 'Inbound'
                        Protocol  = 'TCP'
                    }
                }

                # Test for default or named instance
                if ($instance.InstanceName -eq 'MSSQLSERVER') {
                    $rule.Config.DisplayName = 'SQL Server default instance'
                    $rule.Config.Name = 'SQL Server default instance'
                    $rule.SqlInstance = $instance.ComputerName
                } else {
                    $rule.Config.DisplayName = "SQL Server instance $($instance.InstanceName)"
                    $rule.Config.Name = "SQL Server instance $($instance.InstanceName)"
                    $rule.SqlInstance = $instance.ComputerName + '\' + $instance.InstanceName
                    $browserNeeded = $true
                }

                # Get information about IP addresses for LocalPort
                try {
                    $tcpIpAddresses = Get-DbaNetworkConfiguration -SqlInstance $instance -Credential $Credential -OutputType TcpIpAddresses -EnableException
                } catch {
                    Stop-Function -Message "Failed." -Target $instance -ErrorRecord $_ -Continue
                }

                if ($tcpIpAddresses.Count -gt 1) {
                    # I would have to test this, so I better not support this in the first version.
                    # As LocalPort is [<String[]>], $tcpIpAddresses.TcpPort will probably just work with the current implementation.
                    Stop-Function -Message "SQL Server instance $instance listens on more than one IP addresses. This is currently not supported by this command." -Continue
                }

                if ($tcpIpAddresses.TcpPort -ne '') {
                    $rule.Config.LocalPort = $tcpIpAddresses.TcpPort
                    if ($tcpIpAddresses.TcpPort -ne '1433') {
                        $browserNeeded = $true
                    }
                } else {
                    $programNeeded = $true
                }

                if ($programNeeded) {
                    # Get information about service for Program
                    try {
                        $service = Get-DbaService -ComputerName $instance.ComputerName -InstanceName $instance.InstanceName -Credential $Credential -Type Engine -EnableException
                    } catch {
                        Stop-Function -Message "Failed." -Target $instance -ErrorRecord $_ -Continue
                    }
                    $rule.Config.Program = $service.BinaryPath -replace '^"?(.*sqlservr.exe).*$', '$1'
                }

                $rules += $rule
            }

            # Create rule for Browser
            if ((-not $PSBoundParameters.Type -and $browserNeeded) -or 'Browser' -in $PSBoundParameters.Type) {
                # Apply the defaults
                $rule = @{
                    Type         = 'Browser'
                    InstanceName = $null
                    SqlInstance  = $null
                    Config       = @{
                        DisplayName = 'SQL Server Browser'
                        Name        = 'SQL Server Browser'
                        Group       = 'SQL Server'
                        Enabled     = 'True'
                        Direction   = 'Inbound'
                        Protocol    = 'UDP'
                        LocalPort   = '1434'
                    }
                }

                $rules += $rule
            }

            # Create rule for the dedicated admin connection (DAC)
            if (-not $PSBoundParameters.Type -or 'DAC' -in $PSBoundParameters.Type) {
                # As we create firewall rules, we probably don't have access to the instance yet. So we have to get the port of the DAC via Invoke-Command2.
                # Get-DbaStartupParameter also uses Invoke-Command2 to get the location of ERRORLOG.
                # We only scan the current log because this command is typically run shortly after the installation and should include the needed information.
                try {
                    $errorLogPath = Get-DbaStartupParameter -SqlInstance $instance -Credential $Credential -Simple -EnableException | Select-Object -ExpandProperty ErrorLog
                    $dacMessage = Invoke-Command2 -Raw -ComputerName $instance.ComputerName -ArgumentList $errorLogPath -ScriptBlock {
                        Get-Content -Path $args[0] |
                            Select-String -Pattern 'Dedicated admin connection support was established for listening.+' |
                            Select-Object -Last 1 |
                            ForEach-Object { $_.Matches.Value }
                    }
                    Write-Message -Level Debug -Message "Last DAC message in ERRORLOG: '$dacMessage'"
                } catch {
                    Stop-Function -Message "Failed to execute command to get information for DAC on $($instance.ComputerName) for instance $($instance.InstanceName)." -Target $instance -ErrorRecord $_ -Continue
                }

                if (-not $dacMessage) {
                    Write-Message -Level Warning -Message "No information about the dedicated admin connection (DAC) found in ERRORLOG, cannot create firewall rule for DAC. Use 'Set-DbaSpConfigure -SqlInstance '$instance' -Name RemoteDacConnectionsEnabled -Value 1' to enable remote DAC and try again."
                } elseif ($dacMessage -match 'locally') {
                    Write-Message -Level Verbose -Message "Dedicated admin connection is only listening locally, so no firewall rule is needed."
                } else {
                    $dacPort = $dacMessage -replace '^.* (\d+).$', '$1'
                    Write-Message -Level Verbose -Message "Dedicated admin connection is listening remotely on port $dacPort."

                    # Apply the defaults
                    $rule = @{
                        Type         = 'DAC'
                        InstanceName = $instance.InstanceName
                        Config       = @{
                            Group     = 'SQL Server'
                            Enabled   = 'True'
                            Direction = 'Inbound'
                            Protocol  = 'TCP'
                            LocalPort = $dacPort
                        }
                    }

                    # Test for default or named instance
                    if ($instance.InstanceName -eq 'MSSQLSERVER') {
                        $rule.Config.DisplayName = 'SQL Server default instance (DAC)'
                        $rule.Config.Name = 'SQL Server default instance (DAC)'
                        $rule.SqlInstance = $instance.ComputerName
                    } else {
                        $rule.Config.DisplayName = "SQL Server instance $($instance.InstanceName) (DAC)"
                        $rule.Config.Name = "SQL Server instance $($instance.InstanceName) (DAC)"
                        $rule.SqlInstance = $instance.ComputerName + '\' + $instance.InstanceName
                    }

                    $rules += $rule
                }
            }

            foreach ($rule in $rules) {
                # Apply the given configuration
                if ($Configuration) {
                    foreach ($param in $Configuration.Keys) {
                        $rule.Config.$param = $Configuration.$param
                    }
                }

                # Run the command for the instance
                if ($PSCmdlet.ShouldProcess($instance, "Creating firewall rule for instance $($instance.InstanceName) on $($instance.ComputerName)")) {
                    try {
                        $commandResult = Invoke-Command2 -ComputerName $instance.ComputerName -Credential $Credential -ScriptBlock $cmdScriptBlock -ArgumentList $rule.Config, $Force
                    } catch {
                        Stop-Function -Message "Failed to execute command on $($instance.ComputerName) for instance $($instance.InstanceName)." -Target $instance -ErrorRecord $_ -Continue
                    }

                    if ($commandResult.Error.Count -eq 1 -and $commandResult.Error[0] -match 'Cannot create a file when that file already exists') {
                        $status = 'The desired rule already exists. Use -Force to remove and recreate the rule.'
                        $commandResult.Error = $null
                        if ($rule.Type -eq 'Browser' -and $browserOptional) {
                            $commandResult.Successful = $true
                        }
                    } elseif ($commandResult.CimInstance.Status -match 'The rule was parsed successfully from the store') {
                        $status = 'The rule was successfully created.'
                    } else {
                        $status = $commandResult.CimInstance.Status
                    }

                    if ($commandResult.Warning) {
                        Write-Message -Level Verbose -Message "commandResult.Warning: $($commandResult.Warning)."
                        $status += " Warning: $($commandResult.Warning)."
                    }
                    if ($commandResult.Error) {
                        Write-Message -Level Verbose -Message "commandResult.Error: $($commandResult.Error)."
                        $status += " Error: $($commandResult.Error)."
                    }
                    if ($commandResult.Exception) {
                        Write-Message -Level Verbose -Message "commandResult.Exception: $($commandResult.Exception)."
                        $status += " Exception: $($commandResult.Exception)."
                    }

                    # Output information
                    [PSCustomObject]@{
                        ComputerName = $instance.ComputerName
                        InstanceName = $rule.InstanceName
                        SqlInstance  = $rule.SqlInstance
                        DisplayName  = $rule.Config.DisplayName
                        Name         = $rule.Config.Name
                        Type         = $rule.Type
                        Protocol     = $rule.Config.Protocol
                        LocalPort    = $rule.Config.LocalPort
                        Program      = $rule.Config.Program
                        RuleConfig   = $rule.Config
                        Successful   = $commandResult.Successful
                        Status       = $status
                        Details      = $commandResult
                    } | Select-DefaultView -Property ComputerName, InstanceName, SqlInstance, DisplayName, Type, Successful, Status, Protocol, LocalPort, Program
                }
            }
        }
    }
}
# SIG # Begin signature block
# MIIjYAYJKoZIhvcNAQcCoIIjUTCCI00CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCBwIFWhNjKEAHQx
# ljFKgiuj0ZhgwwdDMU2gsDLDU/pmmqCCHVkwggUaMIIEAqADAgECAhADBbuGIbCh
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
# BgorBgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCBHsAHVt6OHHk/Mszoq9aIrNp2x
# L6kuzMVT/bRMwFwASjANBgkqhkiG9w0BAQEFAASCAQBFsg4F4xIp2C+c86cSYSyD
# d7/Xxhj89DB0wl1DMshmhw6QOaeW1GsUeSl8KZnXvHD/19mk+fpnWspErfYJXaV7
# KdHTIPiHm+bPn0cdOC+JWVegTtvO5JAr5EezRZvmbaMNHw/fN+LaGV4GL84NQty5
# 6iPjyjxKZ+0WadrK51rB/OLrSeOUT8AwTWnQrgtvB1dhW2fYIJvDVzDAsGYXtVhX
# Y7v8qaok7uKKmK0mlhmUdolL5+/2HS4OYA9uSyXgo1+QMfj0ehwHdciJkFAj42tP
# Y4thLIV70uiyf6oEUnW6q5U/Wf1J0bWEEmRP8+y4DF9LjW2Bi0RTzI4n+dv6iTu2
# oYIDIDCCAxwGCSqGSIb3DQEJBjGCAw0wggMJAgEBMHcwYzELMAkGA1UEBhMCVVMx
# FzAVBgNVBAoTDkRpZ2lDZXJ0LCBJbmMuMTswOQYDVQQDEzJEaWdpQ2VydCBUcnVz
# dGVkIEc0IFJTQTQwOTYgU0hBMjU2IFRpbWVTdGFtcGluZyBDQQIQDE1pckuU+jwq
# Sj0pB4A9WjANBglghkgBZQMEAgEFAKBpMBgGCSqGSIb3DQEJAzELBgkqhkiG9w0B
# BwEwHAYJKoZIhvcNAQkFMQ8XDTIyMTExNzA4NTY1OVowLwYJKoZIhvcNAQkEMSIE
# IOQCaf26oRdEFwqgiRWzxIHfNbFToY0PD2Ia3cQZZzBXMA0GCSqGSIb3DQEBAQUA
# BIICAIVVmQ3FfoMh23fDV8iKHNF0Eh1jL8UKGcoDMTzxUhMoUZunXMdUxgdmAJIa
# 48eowRI1EXOwHucLfr6i/2O2vZRiGyGujmN3mb9kVZTZdqohynWEODxDcAOpfIls
# c4TCKUvtehODd+P4aF9yP6txozNifXexGx5J01luhZ3PmuD8Yz1SR1M6ow7ijkEG
# cBLiRGBylCatZn6CWXDQ64ZZG13XqUgmVBljXE+sBx+p0UgHhKbnQ+p1Rf+o68wI
# mbML8mq/mj9zcisbkQZDvUZPrkbR/H88skPwilR6l/UM2eyc3AZciKiPED+iMoar
# mmTXFSFa3OWBrzdpmf+nfqZHXRYhSTHWrrXzZpSVxZLsPshb2bYjh8KVJS3U1Yhd
# rkAFxA1V9bAbJkZC8QMryEu8IcRwYJmE26/FdmXaYEkqGg1qsPCbyOWqvkIYUQez
# p4cBBJjPLRejCsGb73mT4PgnCZ4iftYX16VOzIgdcjkIz0ZgKkTAnGJnbG2yhFhX
# gqCqqPu9LK2vyOPWUnbhAzSgLyrULGE+Ig1+DtcSmCHmb8Dt/4M8vdPyd1NTNF4N
# usJlfI2d2NNf3cJCAWijRizr3oLU2HdUsZ/MXeGkujJ+fCa74cGqgSPXgLUmiNM8
# nSvKyeP7pgxeCLVpMeuq08Ma6KtwhIAp+zV6Wijp+XtnjZKs
# SIG # End signature block
