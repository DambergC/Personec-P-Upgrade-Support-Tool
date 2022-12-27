function Save-DbaCommunitySoftware {
    <#
    .SYNOPSIS
        Download and extract software from Github to update the local cached version of that software.

    .DESCRIPTION
        Download and extract software from Github to update the local cached version of that software.
        This command is run from inside of Install-Dba* and Update-Dba* commands to update the local cache if needed.

        In case you don't have internet access on the target computer, you can download the zip files from the following URLs
        at another computer, transfer them to the target computer or place them on a network share and then use -LocalFile
        to update the local cache:
        * MaintenanceSolution: https://github.com/olahallengren/sql-server-maintenance-solution
        * FirstResponderKit: https://github.com/BrentOzarULTD/SQL-Server-First-Responder-Kit/releases
        * DarlingData: https://github.com/erikdarlingdata/DarlingData
        * SQLWATCH: https://github.com/marcingminski/sqlwatch/releases
        * WhoIsActive: https://github.com/amachanic/sp_whoisactive/releases
        * DbaMultiTool: https://github.com/LowlyDBA/dba-multitool/releases

    .PARAMETER Software
        Name of the software to download.
        Options include:
        * MaintenanceSolution: SQL Server Maintenance Solution created by Ola Hallengren (https://ola.hallengren.com)
        * FirstResponderKit: First Responder Kit created by Brent Ozar (http://FirstResponderKit.org)
        * DarlingData: Erik Darling's stored procedures (https://www.erikdarlingdata.com)
        * SQLWATCH: SQL Server Monitoring Solution created by Marcin Gminski (https://sqlwatch.io/)
        * WhoIsActive: Adam Machanic's comprehensive activity monitoring stored procedure sp_WhoIsActive (https://github.com/amachanic/sp_whoisactive)
        * DbaMultiTool: John McCall's T-SQL scripts for the long haul: optimizing storage, on-the-fly documentation, and general administrative needs (https://dba-multitool.org)

    .PARAMETER Branch
        Specifies the branch. Defaults to master or main. Can only be used if Software is used.

    .PARAMETER LocalFile
        Specifies the path to a local file to install from instead of downloading from Github.

    .PARAMETER Url
        Specifies the URL to download from. Is not needed if Software is used.

    .PARAMETER LocalDirectory
        Specifies the local directory to extract the downloaded file to. Is not needed if Software is used.

    .PARAMETER WhatIf
        If this switch is enabled, no actions are performed but informational messages will be displayed that explain what would happen if the command were to run.

    .PARAMETER Confirm
        If this switch is enabled, you will be prompted for confirmation before executing any operations that change state.

    .PARAMETER EnableException
        By default, when something goes wrong we try to catch it, interpret it and give you a friendly warning message.
        This avoids overwhelming you with "sea of red" exceptions, but is inconvenient because it basically disables advanced scripting.
        Using this switch turns this "nice by default" feature off and enables you to catch exceptions with your own try/catch.

    .NOTES
        Tags: Community
        Author: Andreas Jordan, @JordanOrdix

        Website: https://dbatools.io
        Copyright: (c) 2021 by dbatools, licensed under MIT
        License: MIT https://opensource.org/licenses/MIT

    .LINK
         https://dbatools.io/Save-DbaCommunitySoftware

    .EXAMPLE
        PS C:\> Save-DbaCommunitySoftware -Software MaintenanceSolution

        Updates the local cache of Ola Hallengren's Solution objects.

    .EXAMPLE
        PS C:\> Save-DbaCommunitySoftware -Software FirstResponderKit -LocalFile \\fileserver\Software\SQL-Server-First-Responder-Kit-20211106.zip

        Updates the local cache of the First Responder Kit based on the given file.

    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = "Medium")]
    param (
        [ValidateSet('MaintenanceSolution', 'FirstResponderKit', 'DarlingData', 'SQLWATCH', 'WhoIsActive', 'DbaMultiTool')]
        [string]$Software,
        [string]$Branch,
        [string]$LocalFile,
        [string]$Url,
        [string]$LocalDirectory,
        [switch]$EnableException
    )

    process {
        $dbatoolsData = Get-DbatoolsConfigValue -FullName "Path.DbatoolsData"

        # Set Branch, Url and LocalDirectory for known Software
        if ($Software -eq 'MaintenanceSolution') {
            if (-not $Branch) {
                $Branch = 'master'
            }
            if (-not $Url) {
                $Url = "https://github.com/olahallengren/sql-server-maintenance-solution/archive/$Branch.zip"
            }
            if (-not $LocalDirectory) {
                $LocalDirectory = Join-Path -Path $dbatoolsData -ChildPath "sql-server-maintenance-solution-$Branch"
            }
        } elseif ($Software -eq 'FirstResponderKit') {
            if (-not $Branch) {
                $Branch = 'main'
            }
            if (-not $Url) {
                $Url = "https://github.com/BrentOzarULTD/SQL-Server-First-Responder-Kit/archive/$Branch.zip"
            }
            if (-not $LocalDirectory) {
                $LocalDirectory = Join-Path -Path $dbatoolsData -ChildPath "SQL-Server-First-Responder-Kit-$Branch"
            }
        } elseif ($Software -eq 'DarlingData') {
            if (-not $Branch) {
                $Branch = 'main'
            }
            if (-not $Url) {
                $Url = "https://github.com/erikdarlingdata/DarlingData/archive/$Branch.zip"
            }
            if (-not $LocalDirectory) {
                $LocalDirectory = Join-Path -Path $dbatoolsData -ChildPath "DarlingData-$Branch"
            }
        } elseif ($Software -eq 'SQLWATCH') {
            if ($Branch -in 'prerelease', 'pre-release') {
                $preRelease = $true
            } else {
                $preRelease = $false
            }
            if (-not $Url -and -not $LocalFile) {
                $releasesUrl = "https://api.github.com/repos/marcingminski/sqlwatch/releases"
                try {
                    try {
                        $releasesJson = Invoke-TlsWebRequest -Uri $releasesUrl -UseBasicParsing -ErrorAction Stop
                    } catch {
                        # Try with default proxy and usersettings
                        (New-Object System.Net.WebClient).Proxy.Credentials = [System.Net.CredentialCache]::DefaultNetworkCredentials
                        $releasesJson = Invoke-TlsWebRequest -Uri $releasesUrl -UseBasicParsing -ErrorAction Stop
                    }
                } catch {
                    Stop-Function -Message "Unable to get release information from $releasesUrl." -ErrorRecord $_
                    return
                }
                $latestRelease = ($releasesJson | ConvertFrom-Json) | Where-Object prerelease -eq $preRelease | Select-Object -First 1
                if ($null -eq $latestRelease) {
                    Stop-Function -Message "No release found." -ErrorRecord $_
                    return
                }
                $Url = $latestRelease.assets[0].browser_download_url
            }
            if (-not $LocalDirectory) {
                if ($preRelease) {
                    $LocalDirectory = Join-Path -Path $dbatoolsData -ChildPath "SQLWATCH-prerelease"
                } else {
                    $LocalDirectory = Join-Path -Path $dbatoolsData -ChildPath "SQLWATCH"
                }
            }
        } elseif ($Software -eq 'WhoIsActive') {
            # We currently ignore -Branch as there is only one branch and there are no pre-releases.
            if (-not $Url -and -not $LocalFile) {
                $releasesUrl = "https://api.github.com/repos/amachanic/sp_whoisactive/releases"
                try {
                    try {
                        $releasesJson = Invoke-TlsWebRequest -Uri $releasesUrl -UseBasicParsing -ErrorAction Stop
                    } catch {
                        # Try with default proxy and usersettings
                        (New-Object System.Net.WebClient).Proxy.Credentials = [System.Net.CredentialCache]::DefaultNetworkCredentials
                        $releasesJson = Invoke-TlsWebRequest -Uri $releasesUrl -UseBasicParsing -ErrorAction Stop
                    }
                } catch {
                    Stop-Function -Message "Unable to get release information from $releasesUrl." -ErrorRecord $_
                    return
                }
                $latestRelease = ($releasesJson | ConvertFrom-Json) | Select-Object -First 1
                if ($null -eq $latestRelease) {
                    Stop-Function -Message "No release found." -ErrorRecord $_
                    return
                }
                $Url = $latestRelease.zipball_url
            }
            if (-not $LocalDirectory) {
                $LocalDirectory = Join-Path -Path $dbatoolsData -ChildPath "WhoIsActive"
            }
        } elseif ($Software -eq 'DbaMultiTool') {
            if (-not $Branch) {
                $Branch = 'master'
            }
            if (-not $Url) {
                $Url = "https://github.com/LowlyDBA/dba-multitool/archive/$Branch.zip"
            }
            if (-not $LocalDirectory) {
                $LocalDirectory = Join-Path -Path $dbatoolsData -ChildPath "dba-multitool-$Branch"
            }
        }

        # Test if we now have source and destination for the following actions.
        if (-not ($Url -or $LocalFile)) {
            Stop-Function -Message 'Url or LocalFile is missing.'
            return
        }
        if (-not $LocalDirectory) {
            Stop-Function -Message 'LocalDirectory is missing.'
            return
        }

        # First part is download and extract and we use the temp directory for that and clean up afterwards.
        # So we use a file and a folder with a random name to reduce potential conflicts,
        # but name them with dbatools to be able to recognize them.
        $temp = [System.IO.Path]::GetTempPath()
        $random = Get-Random
        $zipFile = Join-DbaPath -Path $temp -Child "dbatools_software_download_$random.zip"
        $zipFolder = Join-DbaPath -Path $temp -Child "dbatools_software_download_$random"

        if ($Software -eq 'WhoIsActive' -and $LocalFile.EndsWith('.sql')) {
            # For WhoIsActive, we allow to pass in the sp_WhoIsActive.sql file or any other sql file with the source code.
            # We create the zip folder with a subfolder named WhoIsActive and copy the LocalFile there as sp_WhoIsActive.sql.
            $appFolder = Join-DbaPath -Path $zipFolder -Child 'WhoIsActive'
            $appFile = Join-DbaPath -Path $appFolder -Child 'sp_WhoIsActive.sql'
            $null = New-Item -Path $zipFolder -ItemType Directory
            $null = New-Item -Path $appFolder -ItemType Directory
            Copy-Item -Path $LocalFile -Destination $appFile
        } elseif ($LocalFile) {
            # No download, so we just extract the given file if it exists and is a zip file.
            if (-not (Test-Path $LocalFile)) {
                Stop-Function -Message "$LocalFile doesn't exist"
                return
            }
            if (-not ($LocalFile.EndsWith('.zip'))) {
                Stop-Function -Message "$LocalFile has to be a zip file"
                return
            }
            if ($PSCmdlet.ShouldProcess($LocalFile, "Extracting archive to $zipFolder path")) {
                try {
                    Unblock-File $LocalFile -ErrorAction SilentlyContinue
                    Expand-Archive -LiteralPath $LocalFile -DestinationPath $zipFolder -Force -ErrorAction Stop
                } catch {
                    Stop-Function -Message "Unable to extract $LocalFile to $zipFolder." -ErrorRecord $_
                    return
                }
            }
        } else {
            # Download and extract.
            if ($PSCmdlet.ShouldProcess($Url, "Downloading to $zipFile")) {
                try {
                    try {
                        Invoke-TlsWebRequest -Uri $Url -OutFile $zipFile -UseBasicParsing -ErrorAction Stop
                    } catch {
                        # Try with default proxy and usersettings
                        (New-Object System.Net.WebClient).Proxy.Credentials = [System.Net.CredentialCache]::DefaultNetworkCredentials
                        Invoke-TlsWebRequest -Uri $Url -OutFile $zipFile -UseBasicParsing -ErrorAction Stop
                    }
                } catch {
                    Stop-Function -Message "Unable to download $Url to $zipFile." -ErrorRecord $_
                    return
                }
            }
            if ($PSCmdlet.ShouldProcess($zipFile, "Extracting archive to $zipFolder path")) {
                try {
                    Unblock-File $zipFile -ErrorAction SilentlyContinue
                    Expand-Archive -Path $zipFile -DestinationPath $zipFolder -Force -ErrorAction Stop
                } catch {
                    Stop-Function -Message "Unable to extract $zipFile to $zipFolder." -ErrorRecord $_
                    Remove-Item -Path $zipFile -ErrorAction SilentlyContinue
                    return
                }
            }
        }

        # As a safety net, we test whether the archive contained exactly the desired destination directory.
        # But inside of zip files that are downloaded by the user via a webbrowser and not the api,
        # the directory name is the name of the zip file. So we have to test for that as well.
        if ($PSCmdlet.ShouldProcess($zipFolder, "Testing for correct content")) {
            $localDirectoryBase = Split-Path -Path $LocalDirectory
            $localDirectoryName = Split-Path -Path $LocalDirectory -Leaf
            $sourceDirectory = Get-ChildItem -Path $zipFolder -Directory
            $sourceDirectoryName = $sourceDirectory.Name
            if ($Software -eq 'SQLWATCH') {
                # As this software is downloaded as a release, the directory has a different name.
                # Rename the directory from like 'SQLWATCH 4.3.0.23725 20210721131116' to 'SQLWATCH' to be able to handle this like the other software.
                if ($sourceDirectoryName -like 'SQLWATCH*') {
                    # Write a file with version info, to be able to check if version is outdated
                    Set-Content -Path "$($sourceDirectory.FullName)\version.txt" -Value $sourceDirectoryName
                    Rename-Item -Path $sourceDirectory.FullName -NewName 'SQLWATCH'
                    $sourceDirectory = Get-ChildItem -Path $zipFolder -Directory
                    $sourceDirectoryName = $sourceDirectory.Name
                }
            } elseif ($Software -eq 'WhoIsActive') {
                # As this software is downloaded as a release, the directory has a different name.
                # Rename the directory from like 'amachanic-sp_whoisactive-459d2bc' to 'WhoIsActive' to be able to handle this like the other software.
                if ($sourceDirectoryName -like '*sp_whoisactive-*') {
                    Rename-Item -Path $sourceDirectory.FullName -NewName 'WhoIsActive'
                    $sourceDirectory = Get-ChildItem -Path $zipFolder -Directory
                    $sourceDirectoryName = $sourceDirectory.Name
                }
            } elseif ($Software -eq 'FirstResponderKit') {
                # As this software is downloadable as a release, the directory might have a different name.
                # Rename the directory from like 'SQL-Server-First-Responder-Kit-20211106' to 'SQL-Server-First-Responder-Kit-main' to be able to handle this like the other software.
                if ($sourceDirectoryName -like 'SQL-Server-First-Responder-Kit-20*') {
                    Rename-Item -Path $sourceDirectory.FullName -NewName 'SQL-Server-First-Responder-Kit-main'
                    $sourceDirectory = Get-ChildItem -Path $zipFolder -Directory
                    $sourceDirectoryName = $sourceDirectory.Name
                }
            } elseif ($Software -eq 'DbaMultiTool') {
                # As this software is downloadable as a release, the directory might have a different name.
                # Rename the directory from like 'dba-multitool-1.7.5' to 'dba-multitool-master' to be able to handle this like the other software.
                if ($sourceDirectoryName -like 'dba-multitool-[0-9]*') {
                    Rename-Item -Path $sourceDirectory.FullName -NewName 'dba-multitool-master'
                    $sourceDirectory = Get-ChildItem -Path $zipFolder -Directory
                    $sourceDirectoryName = $sourceDirectory.Name
                }
            }
            if ((Get-ChildItem -Path $zipFolder).Count -gt 1 -or $sourceDirectoryName -ne $localDirectoryName) {
                Stop-Function -Message "The archive does not contain the desired directory $localDirectoryName but $sourceDirectoryName."
                Remove-Item -Path $zipFile -ErrorAction SilentlyContinue
                Remove-Item -Path $zipFolder -Recurse -ErrorAction SilentlyContinue
                return
            }
        }

        # Replace the target directory by the extracted directory.
        if ($PSCmdlet.ShouldProcess($zipFolder, "Copying content to $LocalDirectory")) {
            try {
                if (Test-Path -Path $LocalDirectory) {
                    Remove-Item -Path $LocalDirectory -Recurse -ErrorAction Stop
                }
            } catch {
                Stop-Function -Message "Unable to remove the old target directory $LocalDirectory." -ErrorRecord $_
                Remove-Item -Path $zipFile -ErrorAction SilentlyContinue
                Remove-Item -Path $zipFolder -Recurse -ErrorAction SilentlyContinue
                return
            }
            try {
                Copy-Item -Path $sourceDirectory.FullName -Destination $localDirectoryBase -Recurse -ErrorAction Stop
            } catch {
                Stop-Function -Message "Unable to copy the directory $sourceDirectory to the target directory $localDirectoryBase." -ErrorRecord $_
                Remove-Item -Path $zipFile -ErrorAction SilentlyContinue
                Remove-Item -Path $zipFolder -Recurse -ErrorAction SilentlyContinue
                return
            }
        }

        if ($PSCmdlet.ShouldProcess($zipFile, "Removing temporary file")) {
            Remove-Item -Path $zipFile -ErrorAction SilentlyContinue
        }
        if ($PSCmdlet.ShouldProcess($zipFolder, "Removing temporary folder")) {
            Remove-Item -Path $zipFolder -Recurse -ErrorAction SilentlyContinue
        }
    }
}

# SIG # Begin signature block
# MIIjYAYJKoZIhvcNAQcCoIIjUTCCI00CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCCDQbKRbmWkWIJs
# ssD6TJrRQg9ddPV4pF12VGoE9aICVKCCHVkwggUaMIIEAqADAgECAhADBbuGIbCh
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
# BgorBgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCDWjBFwtl4AbB98s/iGA3RWrg7R
# UDTtl+4JvX3II+EUMDANBgkqhkiG9w0BAQEFAASCAQBw9bnzMZPnzr6EQGlSYN7B
# Iw6yQI6QUVSfcHL/vKOVntxy779nOXNVPb/AlEji+kNRKSn031Cc2dLlGmOXtlbX
# 3T7iHlVrz09kp5nno7oJOIpRkn3qPubAcvbJxtCOXwoezXpjhFHyUp5h6F8ZNjlt
# TGqY7bqcUEHSN0C8IQuXNKpCZmQOVzOsfbQ9qlPoCVtMGQD8RDPp0Adtbs7Sq1dO
# EBUshasYrZ7aKGwxszu6ZEDYvKaV+IgZBtTQiNxNfZErWIGGYFTnJNdb91rR5hxM
# c5f/BiP2nr50wvKR9Px2DX89I1i8pqMDtPdkUIR2DD5VJNJADcyjlu96Qd8wX+K9
# oYIDIDCCAxwGCSqGSIb3DQEJBjGCAw0wggMJAgEBMHcwYzELMAkGA1UEBhMCVVMx
# FzAVBgNVBAoTDkRpZ2lDZXJ0LCBJbmMuMTswOQYDVQQDEzJEaWdpQ2VydCBUcnVz
# dGVkIEc0IFJTQTQwOTYgU0hBMjU2IFRpbWVTdGFtcGluZyBDQQIQDE1pckuU+jwq
# Sj0pB4A9WjANBglghkgBZQMEAgEFAKBpMBgGCSqGSIb3DQEJAzELBgkqhkiG9w0B
# BwEwHAYJKoZIhvcNAQkFMQ8XDTIyMTExNzA4NTcyNVowLwYJKoZIhvcNAQkEMSIE
# IORZAcHFOKyMLBRUxnJH9u66b/DJRWuzyCsErSPEjuIwMA0GCSqGSIb3DQEBAQUA
# BIICAEsaWYy5sRe3nU13MMzD7gAHmpf8ZwhLKctieU0gK3mAPlhWDWo5ZqYtikuX
# VyAnsTXReZ9VBaXXRGhvcV2Zmdkd/jgR7aPi3A1fiKybZGD8VfKobs+8zZ8Dnxbh
# 4h7hicUev2/k5qLuuaErxjqf0e8IECStQVh3WR+pKXMeA7bQrWAqhlGwxukKeE+r
# 9KhLmn1wMX7oScxsedZhfw0Fszuqh64J6eznpCAJHUN165hqfLxAHjDCyh/0aOud
# QJGU0CRn1bl2dyfNtMoHXIykObBXrTIFU2DxYj7/xfeqBW6t+hs2UEsJ1FunZXJb
# WVuiCR4Z8Ga+vKmatNOWjJLJbnG4lrf+NxyQylZyfL8mKUU8MPSoL6HfR4sD+T9n
# ggnDc5IFWu1lWcCiXz1D+45VOxDzUrew561D06HYoigbL5ljcZtXAhsEcecn72HS
# 4emlGl1LOtY0gEAIrUUqP9BCpTF9bjBWMiB0HcEsELwAdU0e693k6ncTvw2Hh2tb
# 0BK0tnGKCf7y2sxBYvSt4zEyabu+MbRC+KaaeB4HhUPMNxeUCrVOIUKZfitTlhIA
# nZek3LX5N6z2Gff5tvtZNH2SRUybbe4ilneHhz+mW+oG6rMNF6vfwETqGRTA76w1
# Jk7t0dtY9uQ2ib3XDCh6fnCBFzacfs+xnY6Yz9N5NkWUJSJq
# SIG # End signature block
