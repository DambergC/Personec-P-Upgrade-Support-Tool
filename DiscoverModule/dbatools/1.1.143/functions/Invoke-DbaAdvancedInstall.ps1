function Invoke-DbaAdvancedInstall {
    <#
    .SYNOPSIS
        Designed for internal use, implements parallel execution for Install-DbaInstance.

    .DESCRIPTION
        Invokes an install process for a single computer and restarts it if needed

    .PARAMETER ComputerName
        Target computer with SQL instance or instances.

    .PARAMETER Port
        After successful installation, changes SQL Server TCP port to this value. Overrides the port specified in -SqlInstance.

    .PARAMETER InstallationPath
        Path to setup.exe

    .PARAMETER ConfigurationPath
        Path to Configuration.ini on a local machine

    .PARAMETER ArgumentList
        Array of command line arguments for setup.exe

    .PARAMETER Version
        Canonic version of SQL Server, e.g. 10.50, 11.0

    .PARAMETER InstanceName
        Instance name to be used for the installation

    .PARAMETER Configuration
        A hashtable with custom configuration items that you want to use during the installation.
        Overrides all other parameters.
        For example, to define a custom server collation you can use the following parameter:
        PS> Install-DbaInstance -Version 2017 -Configuration @{ SQLCOLLATION = 'Latin1_General_BIN' }

        Full list of parameters can be found here: https://docs.microsoft.com/en-us/sql/database-engine/install-windows/install-sql-server-from-the-command-prompt#Install

    .PARAMETER Restart
        Restart computer automatically after a successful installation of Sql Server and wait until it comes back online.
        Using this parameter is the only way to chain-install more than 1 instance, since every single patch will require a restart of said computer.

    .PARAMETER Credential
        Windows Credential with permission to log on to the remote server.
        Must be specified for any remote connection if installation media is located on a network folder.

    .PARAMETER Authentication
        Chooses an authentication protocol for remote connections.
        If the protocol fails to establish a connection

        Defaults:
        * CredSSP when -Credential is specified - due to the fact that repository Path is usually a network share and credentials need to be passed to the remote host to avoid the double-hop issue.
        * Default when -Credential is not specified. Will likely fail if a network path is specified.

    .PARAMETER PerformVolumeMaintenanceTasks
        Allow SQL Server service account to perform Volume Maintenance tasks.

    .PARAMETER SaveConfiguration
        Save installation configuration file in a custom location. Will not be preserved otherwise.

    .PARAMETER SaCredential
        Securely provide the password for the sa account when using mixed mode authentication.

    .PARAMETER NoPendingRenameCheck
        Disables pending rename validation when checking for a pending reboot.

    .PARAMETER WhatIf
        Shows what would happen if the command were to run. No actions are actually performed.

    .PARAMETER Confirm
        Prompts you for confirmation before executing any changing operations within the command.

    .PARAMETER EnableException
        By default, when something goes wrong we try to catch it, interpret it and give you a friendly warning message.
        This avoids overwhelming you with "sea of red" exceptions, but is inconvenient because it basically disables advanced scripting.
        Using this switch turns this "nice by default" feature off and enables you to catch exceptions with your own try/catch.

    .NOTES
        Tags: Deployment, Install, Patching
        Author: Chrissy LeMaire (@cl), netnerds.net

        Website: https://dbatools.io
        Copyright: (c) 2018 by dbatools, licensed under MIT
        License: MIT https://opensource.org/licenses/MIT

    .LINK
    https://dbatools.io/Invoke-DbaAdvancedInstall

    .EXAMPLE
    PS C:\> Invoke-DbaAdvancedUpdate -ComputerName SQL1 -Action $actions

    Invokes update actions on SQL1 after restarting it.
    #>
    [CmdletBinding()]
    Param (
        [string]$ComputerName,
        [string]$InstanceName,
        [nullable[int]]$Port,
        [string]$InstallationPath,
        [string]$ConfigurationPath,
        [string[]]$ArgumentList,
        [version]$Version,
        [hashtable]$Configuration,
        [bool]$Restart,
        [bool]$PerformVolumeMaintenanceTasks,
        [string]$SaveConfiguration,
        [ValidateSet('Default', 'Basic', 'Negotiate', 'NegotiateWithImplicitCredential', 'Credssp', 'Digest', 'Kerberos')]
        [string]$Authentication = 'Credssp',
        [pscredential]$Credential,
        [pscredential]$SaCredential,
        [switch]$NoPendingRenameCheck,
        [switch]$EnableException
    )
    Function Get-SqlInstallSummary {
        # Reads Summary.txt from the SQL Server Installation Log folder
        Param (
            [DbaInstanceParameter]$ComputerName,
            [pscredential]$Credential,
            [parameter(Mandatory)]
            [version]$Version
        )
        $getSummary = {
            Param (
                [parameter(Mandatory)]
                [version]$Version
            )
            $versionNumber = "$($Version.Major)$($Version.Minor)".Substring(0, 3)
            $rootPath = "$([System.Environment]::GetFolderPath("ProgramFiles"))\Microsoft SQL Server\$versionNumber\Setup Bootstrap\Log"
            $summaryPath = "$rootPath\Summary.txt"
            $output = [PSCustomObject]@{
                Path              = $null
                Content           = $null
                ExitMessage       = $null
                ConfigurationFile = $null
            }
            if (Test-Path $summaryPath) {
                $output.Path = $summaryPath
                $output.Content = Get-Content -Path $summaryPath
                $output.ExitMessage = ($output.Content | Select-String "Exit message").Line -replace '^ *Exit message: *', ''
                # get last folder created - that's our setup
                $lastLogFolder = Get-ChildItem -Path $rootPath -Directory | Sort-Object -Property Name -Descending | Select-Object -First 1 -ExpandProperty FullName
                if (Test-Path $lastLogFolder\ConfigurationFile.ini) {
                    $output.ConfigurationFile = "$lastLogFolder\ConfigurationFile.ini"
                }
                return $output
            }
        }
        $params = @{
            ComputerName = $ComputerName.ComputerName
            Credential   = $Credential
            ScriptBlock  = $getSummary
            ArgumentList = @($Version.ToString())
            ErrorAction  = 'Stop'
            Raw          = $true
        }
        return Invoke-Command2 @params
    }
    $isLocalHost = ([DbaInstanceParameter]$ComputerName).IsLocalHost
    $output = [pscustomobject]@{
        ComputerName      = $ComputerName
        Version           = $Version
        SACredential      = $SaCredential
        Successful        = $false
        Restarted         = $false
        Configuration     = $Configuration
        InstanceName      = $InstanceName
        Installer         = $InstallationPath
        Port              = $Port
        Notes             = @()
        ExitCode          = $null
        ExitMessage       = $null
        Log               = $null
        LogFile           = $null
        ConfigurationFile = $null

    }
    $restartParams = @{
        ComputerName = $ComputerName
        ErrorAction  = 'Stop'
        For          = 'WinRM'
        Wait         = $true
        Force        = $true
    }
    if ($Credential) {
        $restartParams.Credential = $Credential
        $restartParams.WsmanAuthentication = $Authentication
    }
    $activity = "Installing SQL Server ($Version) components on $ComputerName"
    try {
        $restartNeeded = Test-PendingReboot -ComputerName $ComputerName -Credential $Credential -NoPendingRename:$NoPendingRenameCheck
    } catch {
        $restartNeeded = $false
        Stop-Function -Message "Failed to get reboot status from $computer" -ErrorRecord $_
    }
    if ($restartNeeded -and $Restart) {
        # Restart the computer prior to doing anything
        $msgPending = "Restarting computer $($ComputerName) due to pending restart"
        Write-ProgressHelper -ExcludePercent -Activity $activity -Message $msgPending
        Write-Message -Level Verbose $msgPending
        try {
            $null = Restart-Computer @restartParams
            $output.Restarted = $true
        } catch {
            Stop-Function -Message "Failed to restart computer $($ComputerName)" -ErrorRecord $_
        }
    }
    # save config if needed
    if ($SaveConfiguration) {
        try {
            $null = Copy-Item $ConfigurationPath -Destination $SaveConfiguration -ErrorAction Stop
        } catch {
            $msg = "Could not save configuration file to $SaveConfiguration"
            Stop-Function -Message $msg -ErrorRecord $_
            $output.Notes += $msg
        }
    }
    $connectionParams = @{
        ComputerName = $ComputerName
        ErrorAction  = "Stop"
        UseSSL       = (Get-DbatoolsConfigValue -FullName 'PSRemoting.PsSession.UseSSL' -Fallback $false)
    }

    [nullable[int]]$WinRMPort = Get-DbatoolsConfigValue -FullName 'PSRemoting.PsSession.Port' -Fallback $null
    if (($null -ne $WinRMPort) -and ($WinRMPort -gt 0)) {
        $connectionParams.Port = $WinRMPort
        Write-Message -Level Verbose -Message "Using Port: $($connectionParams.Port)"
    }

    if ($Credential) { $connectionParams.Credential = $Credential }
    # need to figure out where to store the config file
    if ($isLocalHost) {
        $remoteConfig = $ConfigurationPath
    } else {
        try {
            Write-ProgressHelper -ExcludePercent -Activity $activity -Message "Copying configuration file to $ComputerName"
            $session = New-PSSession @connectionParams
            $chosenPath = Invoke-Command -Session $session -ScriptBlock { (Get-Item ([System.IO.Path]::GetTempPath())).FullName } -ErrorAction Stop
            $remoteConfig = Join-DbaPath $chosenPath.TrimEnd('\') (Split-Path $ConfigurationPath -Leaf)
            Write-Message -Level Verbose -Message "Copying $($ConfigurationPath) to remote machine into $chosenPath"
            $null = Send-File -Path $ConfigurationPath -Destination $chosenPath -Session $session -ErrorAction Stop
            $session | Remove-PSSession
        } catch {
            Stop-Function -Message "Failed to copy file $($ConfigurationPath) to $remoteConfig on $($ComputerName), exiting" -ErrorRecord $_
            return
        }
    }
    $installParams = $ArgumentList
    $installParams += "/CONFIGURATIONFILE=`"$remoteConfig`""
    Write-Message -Level Verbose -Message "Setup starting from $($InstallationPath)"
    $execParams = @{
        ComputerName   = $ComputerName
        ErrorAction    = 'Stop'
        Authentication = $Authentication
    }
    if ($Credential) {
        $execParams.Credential = $Credential
    } else {
        if (Test-Bound -Not Authentication) {
            # Use Default authentication instead of CredSSP when Authentication is not specified and Credential is null
            $execParams.Authentication = "Default"
        }
    }
    try {
        Write-ProgressHelper -ExcludePercent -Activity $activity -Message "Installing SQL Server on $ComputerName from $InstallationPath"
        $installResult = Invoke-Program @execParams -Path $InstallationPath -ArgumentList $installParams -Fallback
        $output.ExitCode = $installResult.ExitCode
        # Get setup log summary contents
        try {
            $summary = Get-SqlInstallSummary -ComputerName $ComputerName -Credential $Credential -Version $Version
            $output.ExitMessage = $summary.ExitMessage
            $output.Log = $summary.Content
            $output.LogFile = $summary.Path
            $output.ConfigurationFile = $summary.ConfigurationFile
        } catch {
            Write-Message -Level Warning -Message "Could not get the contents of the summary file from $($ComputerName). Related properties will be empty" -ErrorRecord $_
        }
    } catch {
        Stop-Function -Message "Installation failed" -ErrorRecord $_
        $output.Notes += $_.Exception.Message
        return $output
    } finally {
        try {
            # Cleanup remote temp
            Write-ProgressHelper -ExcludePercent -Activity $activity -Message "Cleaning up temporary files on $ComputerName"
            if (-not $isLocalHost) {
                $null = Invoke-Command2 @connectionParams -ScriptBlock {
                    if ($args[0] -like '*\Configuration_*.ini' -and (Test-Path $args[0])) {
                        Remove-Item -LiteralPath $args[0] -ErrorAction Stop
                    }
                } -Raw -ArgumentList $remoteConfig
            }
            # cleanup local temp config file
            Remove-Item $ConfigurationPath
        } catch {
            Stop-Function -Message "Temp cleanup failed" -ErrorRecord $_
        }
    }
    if ($installResult.Successful) {
        $output.Successful = $true
    } else {
        $msg = "Installation failed with exit code $($installResult.ExitCode). Expand 'ExitMessage' and 'Log' property to find more details."
        $output.Notes += $msg
        Stop-Function -Message $msg
        return $output
    }
    # perform volume maintenance tasks if requested
    if ($PerformVolumeMaintenanceTasks) {
        $null = Set-DbaPrivilege -ComputerName $ComputerName -Credential $Credential -Type IFI -EnableException:$EnableException
    }
    # change port after the installation
    if ($Port) {
        $null = Set-DbaTcpPort -SqlInstance "$($ComputerName)\$($InstanceName)" -Credential $Credential -Port $Port -EnableException:$EnableException -Confirm:$false
        try {
            $null = Restart-DbaService -ComputerName $ComputerName -InstanceName $InstanceName -Credential $Credential -Type Engine -Force -EnableException:$EnableException -Confirm:$false
        } catch {
            $output.Notes += "Port for $($ComputerName)\$($InstanceName) has been changed, but instance restart failed ($_). Restart of instance is necessary for the new settings to become effective."
        }

    }
    # restart if necessary
    try {
        $restartNeeded = Test-PendingReboot -ComputerName $ComputerName -Credential $Credential -NoPendingRename:$NoPendingRenameCheck
    } catch {
        $restartNeeded = $false
        Stop-Function -Message "Failed to get reboot status from $($ComputerName)" -ErrorRecord $_
    }
    if ($installResult.ExitCode -eq 3010 -or $restartNeeded) {
        if ($Restart) {
            # Restart the computer
            $restartMsg = "Restarting computer $($ComputerName) and waiting for it to come back online"
            Write-ProgressHelper -ExcludePercent -Activity $activity -Message $restartMsg
            Write-Message -Level Verbose -Message $restartMsg
            try {
                $null = Restart-Computer @restartParams
                $output.Restarted = $true
            } catch {
                Stop-Function -Message "Failed to restart computer $($ComputerName)" -ErrorRecord $_
                $output.Notes += "Restart is required for computer $($ComputerName) to finish the installation of Sql Server version $Version"
            }
        } else {
            $output.Notes += "Restart is required for computer $($ComputerName) to finish the installation of Sql Server version $Version"
        }
    }
    $output | Select-DefaultView -Property ComputerName, InstanceName, Version, Port, Successful, Restarted, Installer, ExitCode, LogFile, Notes
    Write-Progress -Activity $activity -Completed
}

# SIG # Begin signature block
# MIIjYAYJKoZIhvcNAQcCoIIjUTCCI00CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCDZHBrMxNZBnDj5
# 3gBNWFX8HsDbeP4ISZ5ztFTUo05MIqCCHVkwggUaMIIEAqADAgECAhADBbuGIbCh
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
# BgorBgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCDkA+YxZGYgxSzNd2cBRsZtg0HA
# kdE7NIxSQicCMk55HjANBgkqhkiG9w0BAQEFAASCAQAgggiuKZeF2ajWigCpd9j8
# 3bIWO3GWI6W7MEDlsp3upCfkXo4ZNbKVNBlNmK8IOeszmM86jYBpf1BFXM5sEPLE
# bXoUGCASM0Uex0ojFOgiCx9S7p0WiN34rRRvfgtdAZPRf/AWxGLnV5StWSeqRigZ
# Pa4kAfP3aA2cnEDL5/gK7fcBRt1QvA+gr471bpmvIMLfSB6DLLaPYwgu+dl8PN7m
# Q5dd4Z/7OiTDTA4K0hHHqsSjHAJ6DpZxrA6G+zB/KrcVQNFpD5lJDLSk91J74DwR
# OfsXcsLWeSpwJt+Ehz8HD3NBUfoCvI7Xgt6WSHPa/TjPd+AU7dFB2UyQCX4po50h
# oYIDIDCCAxwGCSqGSIb3DQEJBjGCAw0wggMJAgEBMHcwYzELMAkGA1UEBhMCVVMx
# FzAVBgNVBAoTDkRpZ2lDZXJ0LCBJbmMuMTswOQYDVQQDEzJEaWdpQ2VydCBUcnVz
# dGVkIEc0IFJTQTQwOTYgU0hBMjU2IFRpbWVTdGFtcGluZyBDQQIQDE1pckuU+jwq
# Sj0pB4A9WjANBglghkgBZQMEAgEFAKBpMBgGCSqGSIb3DQEJAzELBgkqhkiG9w0B
# BwEwHAYJKoZIhvcNAQkFMQ8XDTIyMTExNzA4NTYzOVowLwYJKoZIhvcNAQkEMSIE
# IEL77pYgp/YoRyKUeoDXRDCKaP9RNi+RHauXM75JV2tnMA0GCSqGSIb3DQEBAQUA
# BIICAMky1waE7bx/PlvpjnQZyeB/nfrS3KC7NW6cn2YIptXkosuveizNcUQJkAXG
# Wd7BvfiPq1Q2eXiVRUB/Om3Bh6wXLWwXShiOwt0TEQomcrH3b2jyXYaN/ojGu9Ze
# PfvHRNz7PgfeiHrIUpUVCfx7d9P1o6IbyfpkcYElOQDZQSMhvrTZPmLYQatby9tK
# eIPo8Z8YZAoKS7JPydi7+tnVqxv4sdFykpbeyfc46cQvZVk55drNi+oJ18xFgCmX
# 2BC6TTfq2DFU7sI/mhRSjgPHBrhBCHxmm2tE/vrP5pVqr3L0App0M5dYdHrWgRC1
# K2Qy7hKNgiZjfHe6hL/SqJEpid/k6qBInwI6G1sbXrznhfxlZImNRIcnGVwdnzLR
# 8HotYZkPOFnlDzFl/cdrqwo9qbudpvib7AJvMBWFvHSLP1JpZT6MudGlSYkwSY/c
# u3OKXp5ZEZXXPJWDNrgwaeCzyto0jkmITiv2IuYofu81anAvVxOOmDmysLMsEBjR
# PvcPjQ5CsYSrIFmEBkUXSFQrk5rxGXbxeKGKXbeasR/QYdKN3cu8w+NoRtq0ihJs
# H3yW3ZpCaqmaq2cgNGKejqPorYibyrCz9sYmz3LzfvbeVwnob2rb9uiUdK/zdkhD
# N8TUdkTGsV4gbB8k1FIO/2FesGEj9E9K1LSqLtKQSW+FpiIh
# SIG # End signature block
