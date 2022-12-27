function Update-DbaServiceAccount {
    <#
    .SYNOPSIS
        Changes service account (or just its password) of the SQL Server service.

    .DESCRIPTION
        Reconfigure the service account or update the password of the specified SQL Server service. The service will be restarted in the event of changing the account.

    .PARAMETER ComputerName
        The target SQL Server instance or instances.

    .PARAMETER Credential
        Windows Credential with permission to log on to the server running the SQL instance

    .PARAMETER InputObject
        A collection of services. Basically, any object that has ComputerName and ServiceName properties. Can be piped from Get-DbaService.

    .PARAMETER ServiceName
        A name of the service on which the action is performed. E.g. MSSQLSERVER or SqlAgent$INSTANCENAME

    .PARAMETER ServiceCredential
        Windows Credential object under which the service will be setup to run. Cannot be used with -Username. For local service accounts use one of the following usernames with empty password:
        LOCALSERVICE
        NETWORKSERVICE
        LOCALSYSTEM

    .PARAMETER PreviousPassword
        An old password of the service account. Optional when run under local admin privileges.

    .PARAMETER SecurePassword
        New password of the service account. The function will ask for a password if not specified. MSAs and local system accounts will ignore the password.

    .PARAMETER Username
        Username of the service account. Cannot be used with -ServiceCredential. For local service accounts use one of the following usernames omitting the -SecurePassword parameter:
        LOCALSERVICE
        NETWORKSERVICE
        LOCALSYSTEM

    .PARAMETER NoRestart
        Do not immediately restart the service after changing the password.

        **Note that the changes will not go into effect until you restart the SQL Services**

    .PARAMETER WhatIf
        Shows what would happen if the command were to run. No actions are actually performed.

    .PARAMETER Confirm
        Prompts you for confirmation before executing any changing operations within the command.

    .PARAMETER EnableException
        By default, when something goes wrong we try to catch it, interpret it and give you a friendly warning message.
        This avoids overwhelming you with "sea of red" exceptions, but is inconvenient because it basically disables advanced scripting.
        Using this switch turns this "nice by default" feature off and enables you to catch exceptions with your own try/catch.

    .LINK
        https://dbatools.io/Update-DbaServiceAccount

    .NOTES
        Tags: Service, SqlServer, Instance, Connect
        Author: Kirill Kravtsov (@nvarscar)

        Website: https://dbatools.io
        Copyright: (c) 2018 by dbatools, licensed under MIT
        License: MIT https://opensource.org/licenses/MIT

        Requires Local Admin rights on destination computer(s).

    .EXAMPLE
        PS C:\> $SecurePassword = (Get-Credential NoUsernameNeeded).Password
        PS C:\> Update-DbaServiceAccount -ComputerName sql1 -ServiceName 'MSSQL$MYINSTANCE' -SecurePassword $SecurePassword

        Changes the current service account's password of the service MSSQL$MYINSTANCE to 'Qwerty1234'

    .EXAMPLE
        PS C:\> $cred = Get-Credential
        PS C:\> Get-DbaService sql1 -Type Engine,Agent -Instance MYINSTANCE | Update-DbaServiceAccount -ServiceCredential $cred

        Requests credentials from the user and configures them as a service account for the SQL Server engine and agent services of the instance sql1\MYINSTANCE

    .EXAMPLE
        PS C:\> Update-DbaServiceAccount -ComputerName sql1,sql2 -ServiceName 'MSSQLSERVER','SQLSERVERAGENT' -Username NETWORKSERVICE

        Configures SQL Server engine and agent services on the machines sql1 and sql2 to run under Network Service system user.

    .EXAMPLE
        PS C:\> Get-DbaService sql1 -Type Engine -Instance MSSQLSERVER | Update-DbaServiceAccount -Username 'MyDomain\sqluser1'

        Configures SQL Server engine service on the machine sql1 to run under MyDomain\sqluser1. Will request user to input the account password.


    .EXAMPLE
        PS C:\> Get-DbaService sql1 -Type Engine -Instance MSSQLSERVER | Update-DbaServiceAccount -Username 'MyDomain\sqluser1' -NoRestart

        Configures SQL Server engine service on the machine sql1 to run under MyDomain\sqluser1. Will request user to input the account password.

        Will not restart, which means the changes will not go into effect, so you will still have to restart during your planned outage window.

    #>
    [CmdletBinding(SupportsShouldProcess, DefaultParameterSetName = "ServiceName" )]
    param (
        [parameter(ParameterSetName = "ServiceName")]
        [Alias("cn", "host", "Server")]
        [DbaInstanceParameter[]]$ComputerName = $env:COMPUTERNAME,
        [PSCredential]$Credential,
        [parameter(ValueFromPipeline, Mandatory, ParameterSetName = "InputObject")]
        [Alias("ServiceCollection")]
        [object[]]$InputObject,
        [parameter(ParameterSetName = "ServiceName", Position = 1, Mandatory)]
        [Alias("Name", "Service")]
        [string[]]$ServiceName,
        [Alias("User")]
        [string]$Username,
        [PSCredential]$ServiceCredential,
        [securestring]$PreviousPassword = (New-Object System.Security.SecureString),
        [Alias("Password", "NewPassword")]
        [securestring]$SecurePassword = (New-Object System.Security.SecureString),
        [switch]$NoRestart,
        [switch]$EnableException
    )
    begin {
        $svcCollection = @()
        $scriptAccountChange = {
            $service = $wmi.Services[$args[0]]
            $service.SetServiceAccount($args[1], $args[2])
            $service.Alter()
        }
        $scriptPasswordChange = {
            $service = $wmi.Services[$args[0]]
            $service.ChangePassword($args[1], $args[2])
            $service.Alter()
        }
        #Check parameters
        if ($Username) {
            $actionType = 'Account'
            if ($ServiceCredential) {
                Stop-Function -EnableException $EnableException -Message "You cannot specify both -UserName and -ServiceCredential parameters" -Category InvalidArgument
                return
            }
            #System logins should not have a domain name, whitespaces or passwords
            $trimmedUsername = (Split-Path $Username -Leaf).Trim().Replace(' ', '')
            #Request password input if password was not specified and account is not MSA or system login
            if ($SecurePassword.Length -eq 0 -and $PSBoundParameters.Keys -notcontains 'SecurePassword' -and $trimmedUsername -notin 'NETWORKSERVICE', 'LOCALSYSTEM', 'LOCALSERVICE' -and $Username.EndsWith('$') -eq $false -and $Username.StartsWith('NT Service\') -eq $false) {
                $SecurePassword = Read-Host -Prompt "Input new password for account $UserName" -AsSecureString
                $NewPassword2 = Read-Host -Prompt "Repeat password" -AsSecureString
                if ((New-Object System.Management.Automation.PSCredential ("user", $SecurePassword)).GetNetworkCredential().Password -ne `
                    (New-Object System.Management.Automation.PSCredential ("user", $NewPassword2)).GetNetworkCredential().Password) {
                    Stop-Function -Message "Passwords do not match" -Category InvalidArgument -EnableException $EnableException
                    return
                }
            }
            $currentCredential = New-Object System.Management.Automation.PSCredential ($Username, $SecurePassword)
        } elseif ($ServiceCredential) {
            $actionType = 'Account'
            $currentCredential = $ServiceCredential
        } else {
            $actionType = 'Password'
        }
        if ($actionType -eq 'Account') {
            #System logins should not have a domain name, whitespaces or passwords
            $credUserName = (Split-Path $currentCredential.UserName -Leaf).Trim().Replace(' ', '')
            #Check for system logins and replace the Credential object to simplify passing localsystem-like login names
            if ($credUserName -in 'NETWORKSERVICE', 'LOCALSYSTEM', 'LOCALSERVICE') {
                $currentCredential = New-Object System.Management.Automation.PSCredential ($credUserName, (New-Object System.Security.SecureString))
            }
        }
    }
    process {
        if (Test-FunctionInterrupt) { return }

        if ($PsCmdlet.ParameterSetName -match 'ServiceName') {
            foreach ($Computer in $ComputerName.ComputerName) {
                $Server = Resolve-DbaNetworkName -ComputerName $Computer -Credential $credential
                if ($Server.FullComputerName) {
                    foreach ($service in $ServiceName) {
                        $svcCollection += [psobject]@{
                            ComputerName = $server.FullComputerName
                            ServiceName  = $service
                        }
                    }
                } else {
                    Stop-Function -EnableException $EnableException -Message "Failed to connect to $Computer" -Continue
                }
            }
        } elseif ($PsCmdlet.ParameterSetName -match 'InputObject') {
            foreach ($service in $InputObject) {
                if ($service.ServiceName -eq 'PowerBIReportServer') {
                    Stop-Function -Message "PowerBIReportServer service is not supported, skipping." -Continue
                } else {
                    $Server = Resolve-DbaNetworkName -ComputerName $service.ComputerName -Credential $credential
                    if ($Server.FullComputerName) {
                        $svcCollection += [psobject]@{
                            ComputerName = $Server.FullComputerName
                            ServiceName  = $service.ServiceName
                        }
                    } else {
                        Stop-Function -EnableException $EnableException -Message "Failed to connect to $($service.FullComputerName)" -Continue
                    }
                }
            }
        }

    }
    end {
        foreach ($svc in $svcCollection) {
            if ($serviceObject = Get-DbaService -ComputerName $svc.ComputerName -ServiceName $svc.ServiceName -Credential $Credential -EnableException:$EnableException) {
                $outMessage = $outStatus = $agent = $null
                if ($actionType -eq 'Password' -and $SecurePassword.Length -eq 0) {
                    $currentPassword = Read-Host -Prompt "New password for $($serviceObject.StartName) ($($svc.ServiceName) on $($svc.ComputerName))" -AsSecureString
                    $currentPassword2 = Read-Host -Prompt "Repeat password" -AsSecureString
                    if ((New-Object System.Management.Automation.PSCredential ("user", $currentPassword)).GetNetworkCredential().Password -ne `
                        (New-Object System.Management.Automation.PSCredential ("user", $currentPassword2)).GetNetworkCredential().Password) {
                        Stop-Function -Message "Passwords do not match. This service will not be updated" -Category InvalidArgument -EnableException $EnableException -Continue
                    }
                } else {
                    $currentPassword = $SecurePassword
                }
                if ($serviceObject.ServiceType -eq 'Engine') {
                    #Get SQL Agent running status
                    $agent = Get-DbaService -ComputerName $svc.ComputerName -Type Agent -InstanceName $serviceObject.InstanceName
                }
                if ($PsCmdlet.ShouldProcess($serviceObject, "Changing account information for service $($svc.ServiceName) on $($svc.ComputerName)")) {
                    try {
                        if ($actionType -eq 'Account') {
                            # Test if a certificate is used. If so, remove it and set it again later.
                            $certificate = $null
                            if ($serviceObject.ServiceType -eq 'Engine') {
                                $sqlInstance = $svc.ComputerName
                                if ($svc.ServiceName -ne 'MSSQLSERVER') {
                                    $instanceName = $svc.ServiceName -replace '^MSSQL\$', ''
                                    $sqlInstance += '\' + $instanceName
                                }
                                # We try to get the certificate, but don't fail in case we are not able to.
                                $certificate = Get-DbaNetworkConfiguration -SqlInstance $sqlInstance -Credential $Credential -OutputType Certificate
                                if ($certificate.Thumbprint) {
                                    Write-Message -Level Verbose -Message "Removing certificate from service $($svc.ServiceName) on $($svc.ComputerName)"
                                    $null = Remove-DbaNetworkCertificate -SqlInstance $sqlInstance -Credential $Credential -EnableException
                                }
                            }
                            Write-Message -Level Verbose -Message "Attempting an account change for service $($svc.ServiceName) on $($svc.ComputerName)"
                            $null = Invoke-ManagedComputerCommand -ComputerName $svc.ComputerName -Credential $Credential -ScriptBlock $scriptAccountChange -ArgumentList @($svc.ServiceName, $currentCredential.UserName, $currentCredential.GetNetworkCredential().Password) -EnableException:$EnableException
                            $outMessage = "The login account for the service has been successfully set."
                            if ($certificate.Thumbprint) {
                                Write-Message -Level Verbose -Message "Setting certificate for service $($svc.ServiceName) on $($svc.ComputerName)"
                                $null = Set-DbaNetworkCertificate -SqlInstance $sqlInstance -Credential $Credential -Thumbprint $certificate.Thumbprint -EnableException
                            }
                        } elseif ($actionType -eq 'Password') {
                            Write-Message -Level Verbose -Message "Attempting a password change for service $($svc.ServiceName) on $($svc.ComputerName)"
                            $null = Invoke-ManagedComputerCommand -ComputerName $svc.ComputerName -Credential $Credential -ScriptBlock $scriptPasswordChange -ArgumentList @($svc.ServiceName, (New-Object System.Management.Automation.PSCredential ("user", $PreviousPassword)).GetNetworkCredential().Password, (New-Object System.Management.Automation.PSCredential ("user", $currentPassword)).GetNetworkCredential().Password) -EnableException:$EnableException
                            $outMessage = "The password has been successfully changed."
                        }
                        $outStatus = 'Successful'
                    } catch {
                        $outStatus = 'Failed'
                        $outMessage = $_.Exception.Message
                        if ($certificate.Thumbprint) {
                            # Depending on where the process failed, the certificate might be already removed but not yet set again.
                            $outMessage += " Please check if certificate with thumbprint $($certificate.Thumbprint) is still in place."
                        }
                        Stop-Function -Message $outMessage -Continue
                    }
                } else {
                    $outStatus = 'Successful'
                    $outMessage = 'No changes made - running in -WhatIf mode.'
                }
                if ($serviceObject.ServiceType -eq 'Engine' -and $actionType -eq 'Account' -and $outStatus -eq 'Successful' -and $agent.State -eq 'Running' -and -not $NoRestart) {
                    #Restart SQL Agent after SQL Engine has been restarted
                    if ($PsCmdlet.ShouldProcess($serviceObject, "Starting SQL Agent after Engine account change on $($svc.ComputerName)")) {
                        $res = Start-DbaService -ComputerName $svc.ComputerName -Type Agent -InstanceName $serviceObject.InstanceName
                        if ($res.Status -ne 'Successful') {
                            Write-Message -Level Warning -Message "Failed to restart SQL Agent after changing credentials. $($res.Message)"
                        }
                    }
                }
                if ($NoRestart) {
                    Write-Message -Level Warning -Message "Changes will not go into effect until you restart. Please restart the services manually during your designated outage window."
                }
                $serviceObject = Get-DbaService -ComputerName $svc.ComputerName -ServiceName $svc.ServiceName -Credential $Credential -EnableException:$EnableException
                Add-Member -Force -InputObject $serviceObject -NotePropertyName Message -NotePropertyValue $outMessage
                Add-Member -Force -InputObject $serviceObject -NotePropertyName Status -NotePropertyValue $outStatus
                Select-DefaultView -InputObject $serviceObject -Property ComputerName, ServiceName, State, StartName, Status, Message
            } Else {
                Stop-Function -Message "The service $($svc.ServiceName) has not been found on $($svc.ComputerName)" -EnableException $EnableException -Continue
            }
        }
    }
}

# SIG # Begin signature block
# MIIjYAYJKoZIhvcNAQcCoIIjUTCCI00CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCCljs8E08zX4Yxv
# focxdY3Ynvj8siDs7cxx4a3nK7tHJKCCHVkwggUaMIIEAqADAgECAhADBbuGIbCh
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
# BgorBgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCAHFY1lGKVcHPUSfZxlx+jSMvoF
# FeMHindTz2EMtdhqVDANBgkqhkiG9w0BAQEFAASCAQAicjLCeJbI1U338S+WVEtj
# CMCpzpOrqm6uXpTheXZFx1kWIKuZSQlYD/OWd5TRRLNLSPOXz7WcCeU65f3c6rB5
# 8MhcqUrriXAercwFE0XDCNs4dYV3tGbbW1Swpd1yLaT+bNgLTCSpQRrKRhdi77tW
# 8qc0tlFGebm1+L7+bQ4cQenO+FrXn7gRAes2KnFR5cggpWzB6FOvsaaTXnfkW6qi
# qBfNa6a6QxFh9a8+ad021Rk/Fxx4tuuJZ9+iR52oYZgtMPkyfeBqo1cHxRVYx46B
# C8/plrVglZSdWF5+cDKDKL4XzRO8kPkw0dOO5+5xuxHGHBsFbwZDk7wtMRk1MZpH
# oYIDIDCCAxwGCSqGSIb3DQEJBjGCAw0wggMJAgEBMHcwYzELMAkGA1UEBhMCVVMx
# FzAVBgNVBAoTDkRpZ2lDZXJ0LCBJbmMuMTswOQYDVQQDEzJEaWdpQ2VydCBUcnVz
# dGVkIEc0IFJTQTQwOTYgU0hBMjU2IFRpbWVTdGFtcGluZyBDQQIQDE1pckuU+jwq
# Sj0pB4A9WjANBglghkgBZQMEAgEFAKBpMBgGCSqGSIb3DQEJAzELBgkqhkiG9w0B
# BwEwHAYJKoZIhvcNAQkFMQ8XDTIyMTExNzA4NTc1NVowLwYJKoZIhvcNAQkEMSIE
# IBmrUjo5ltNVGtk9RJaZALSxyFAmsbK4BnJow5bKb446MA0GCSqGSIb3DQEBAQUA
# BIICAIMNO67fBW61jdA03ZpVVO2K5/+f5bkjdIfeJqsEBXsyyDhFU6B5F+4uLpnV
# X4EMn7NFwZraYD4ujq2YWgyQDWWVQ9840KH5U6vOwaGSLC/6cTA4tah3VnwqIRWA
# cEiVf5W2ovGLsUct2JcpSiRZA3eIxfOykgvm3QgKPWsY6Rcmyg0u9KPCbjrp9FfE
# 5Y3DlZb7w2wondDY5LL8APDjq3ARnzut6xnANn6yPQFY5ra0q5t2UGvM+IO/oUhh
# OIU2erDTME8I6UtZK5XZZt5Qg4HNZOjimcrsXd/Q/ovBz8kMcudZUQY2ekYZs3Av
# 6tNnSjPZr+vqUCHfKvloudP/xHNvAGLPxvFMV6MWqmas17WEiYLaUeW8oSHBUcRl
# s4Nl+qUlIeTW1tayXL4WkUWg/ebHJoPbSrRIsVTaw+dUmk7hMjzi9hL7eYcUTHor
# zZhi4yfxG2onGRSUxg4M/2RtZx/twMDg/jzrnpwvJUUbbBYuf3K1vAbpqrBiuaKw
# RzCKttgRrVAi0xjQzocNuNVvqPK6rhm+YCEkAJ606MR2SXanLsvgdBcaFkRIyNeX
# D7TsZjSSN1SpNYPd8DJxQzFzxYVAB5yEOZ8XBGnfXKt7HYNxzr9uOWltG+Z2FK93
# 2tkDv2+91sgze+xpRTk2gPPOGxWyhRHJIaazyXY879b2M3t9
# SIG # End signature block
