function New-DbaDatabase {
    <#
    .SYNOPSIS
        Creates a new database

    .DESCRIPTION
        This command creates a new database.

        It allows creation with multiple files, and sets all growth settings to be fixed size rather than percentage growth. The autogrowth settings are obtained from the modeldev file in the model database when not supplied as command line arguments.

    .PARAMETER SqlInstance
        The target SQL Server instance or instances.

    .PARAMETER SqlCredential
        Login to the target instance using alternative credentials. Accepts PowerShell credentials (Get-Credential).

        Windows Authentication, SQL Server Authentication, Active Directory - Password, and Active Directory - Integrated are all supported.

        For MFA support, please use Connect-DbaInstance.

    .PARAMETER Name
        The name of the new database or databases to be created.

    .PARAMETER DataFilePath
        The location that data files will be placed, otherwise the default SQL Server data path will be used.

    .PARAMETER LogFilePath
        The location the log file will be placed, otherwise the default SQL Server log path will be used.

    .PARAMETER Collation
        The database collation, if not supplied the default server collation will be used.

    .PARAMETER RecoveryModel
        The recovery model for the database, if not supplied the recovery model from the model database will be used.
        Valid options are: Simple, Full, BulkLogged.

    .PARAMETER Owner
        The login that will be used as the database owner.

    .PARAMETER PrimaryFilesize
        The size in MB for the Primary file. If this is less than the primary file size for the model database, then the model size will be used instead.

    .PARAMETER PrimaryFileGrowth
        The size in MB that the Primary file will autogrow by.

    .PARAMETER PrimaryFileMaxSize
        The maximum permitted size in MB for the Primary File. If this is less than the primary file size for the model database, then the model size will be used instead.

    .PARAMETER LogSize
        The size in MB that the Transaction log will be created.

    .PARAMETER LogGrowth
        The amount in MB that the log file will be set to autogrow by.

    .PARAMETER LogMaxSize
        The maximum permitted size in MB. If this is less than the log file size for the model database, then the model log size will be used instead.

    .PARAMETER SecondaryFileCount
        The number of files to create in the Secondary filegroup for the database.

    .PARAMETER SecondaryFilesize
        The size in MB of the files to be added to the Secondary filegroup. Each file added will be created with this size setting.

    .PARAMETER SecondaryFileMaxSize
        The maximum permitted size in MB for the Secondary data files to grow to. Each file added will be created with this max size setting.

    .PARAMETER SecondaryFileGrowth
        The amount in MB that the Secondary files will be set to autogrow by. Use 0 for no growth allowed. Each file added will be created with this growth setting.

    .PARAMETER DefaultFileGroup
        Sets the default file group. Either primary or secondary.

    .PARAMETER DataFileSuffix
        The data file suffix.

    .PARAMETER LogFileSuffix
        The log file suffix. Defaults to "_log"

    .PARAMETER SecondaryDataFileSuffix
        The secondary data file suffix.

    .PARAMETER WhatIf
        If this switch is enabled, no actions are performed but informational messages will be displayed that explain what would happen if the command were to run.

    .PARAMETER Confirm
        If this switch is enabled, you will be prompted for confirmation before executing any operations that change state.

    .PARAMETER EnableException
        By default, when something goes wrong we try to catch it, interpret it and give you a friendly warning message.
        This avoids overwhelming you with "sea of red" exceptions, but is inconvenient because it basically disables advanced scripting.
        Using this switch turns this "nice by default" feature off and enables you to catch exceptions with your own try/catch.

    .NOTES
        Tags: Database
        Author: Matthew Darwin (@evoDBA, naturalselectiondba.wordpress.com)  | Chrissy LeMaire (@cl)

        Website: https://dbatools.io
        Copyright: (c) 2018 by dbatools, licensed under MIT
        License: MIT https://opensource.org/licenses/MIT

    .LINK
        https://dbatools.io/New-DbaDatabase

    .EXAMPLE
        New-DbaDatabase -SqlInstance sql1

        Creates a randomly named database (random-N) on instance sql1

    .EXAMPLE
        New-DbaDatabase -SqlInstance sql1 -Name dbatools, dbachecks

        Creates a database named dbatools and a database named dbachecks on sql1

    .EXAMPLE
        New-DbaDatabase -SqlInstance sql1, sql2, sql3 -Name multidb, multidb2 -SecondaryFilesize 20 -SecondaryFileGrowth 20 -LogSize 20 -LogGrowth 20

        Creates two databases, multidb and multidb2, on 3 instances (sql1, sql2 and sql3) and sets the secondary data file size to 20MB, the file growth to 20MB and the log growth to 20MB for each

    .EXAMPLE
        New-DbaDatabase -SqlInstance sql1 -Name nondefault -DataFilePath M:\Data -LogFilePath 'L:\Logs with spaces' -SecondaryFileCount 2

        Creates a database named nondefault and places data files in in the M:\data directory and log files in "L:\Logs with spaces".

        Creates a secondary group with 2 files in the Secondary filegroup.

    .EXAMPLE
        PS C:\> $databaseParams = @{
        >> SqlInstance             = "sql1"
        >> Name                    = "newDb"
        >> LogSize                 = 32
        >> LogMaxSize              = 512
        >> PrimaryFilesize         = 64
        >> PrimaryFileMaxSize      = 512
        >> SecondaryFilesize       = 64
        >> SecondaryFileMaxSize    = 512
        >> LogGrowth               = 32
        >> PrimaryFileGrowth       = 64
        >> SecondaryFileGrowth     = 64
        >> DataFileSuffix          = "_PRIMARY"
        >> LogFileSuffix           = "_Log"
        >> SecondaryDataFileSuffix = "_MainData"
        >> }
        >> New-DbaDatabase @databaseParams

        Creates a new database named newDb on the sql1 instance and sets the file sizes, max sizes, and growth as specified. The resulting filenames will take the form:

        newDb_PRIMARY
        newDb_Log
        newDb_MainData_1  (Secondary filegroup files)

    #>
    [Cmdletbinding(SupportsShouldProcess, ConfirmImpact = "Low")]
    param
    (
        [parameter(Mandatory, ValueFromPipeline)]
        [DbaInstanceParameter[]]$SqlInstance,
        [PSCredential]$SqlCredential,
        [Alias('Database')]
        [string[]]$Name,
        [string]$Collation,
        [ValidateSet('Simple', 'Full', 'BulkLogged')]
        [string]$RecoveryModel,
        [string]$Owner,
        [string]$DataFilePath,
        [string]$LogFilePath,
        [int32]$PrimaryFilesize,
        [int32]$PrimaryFileGrowth,
        [int32]$PrimaryFileMaxSize,
        [int32]$LogSize,
        [int32]$LogGrowth,
        [int32]$LogMaxSize,
        [int32]$SecondaryFilesize,
        [int32]$SecondaryFileGrowth,
        [int32]$SecondaryFileMaxSize,
        [int32]$SecondaryFileCount,
        [ValidateSet('Primary', 'Secondary')]
        [string]$DefaultFileGroup,
        [string]$DataFileSuffix,
        [string]$LogFileSuffix = '_log',
        [string]$SecondaryDataFileSuffix,
        [switch]$EnableException
    )

    begin {
        # do some checks to see if the advanced config settings will be invoked
        if (Test-Bound -ParameterName DataFilePath, DefaultFileGroup, LogFilePath, LogGrowth, LogMaxSize, LogSize, PrimaryFileGrowth, PrimaryFileMaxSize, PrimaryFilesize, SecondaryFileCount, SecondaryFileGrowth, SecondaryFileMaxSize, SecondaryFilesize, DataFileSuffix, LogFileSuffix, SecondaryDataFileSuffix) {
            $advancedconfig = $true
            Write-Message -Message "Advanced data file configuration will be invoked" -Level Verbose
        }
    }

    process {
        if (Test-FunctionInterrupt) {
            return
        }

        foreach ($instance in $SqlInstance) {
            try {
                $server = Connect-DbaInstance -SqlInstance $instance -SqlCredential $SqlCredential
            } catch {
                Stop-Function -Message "Failure" -Category ConnectionError -ErrorRecord $_ -Target $instance -Continue
            }

            if ($advancedconfig -and $server.VersionMajor -eq 8) {
                Stop-Function -Message "Advanced configuration options are not available to SQL Server 2000. Aborting creation of database on $instance" -Target $instance -Continue
            }

            # validate the collation
            if ($Collation) {
                $collations = Get-DbaAvailableCollation -SqlInstance $server

                if ($collations.Name -notcontains $Collation) {
                    Stop-Function -Message "$Collation is not a valid collation on $instance" -Target $instance -Continue
                }
            }

            if (-not (Test-Bound -ParameterName Name)) {
                $Name = "random-$(Get-Random)"
            }

            if (-not (Test-Bound -ParameterName DataFilePath)) {
                $DataFilePath = (Get-DbaDefaultPath -SqlInstance $server).Data
            }

            if (-not (Test-Bound -ParameterName LogFilePath)) {
                $LogFilePath = (Get-DbaDefaultPath -SqlInstance $server).Log
            }

            if (-not (Test-DbaPath -SqlInstance $server -Path $LogFilePath)) {
                try {
                    Write-Message -Message "Creating directory $LogFilePath" -Level Verbose
                    $null = New-DbaDirectory -SqlInstance $server -Path $LogFilePath -EnableException
                } catch {
                    Stop-Function -Message "Error creating log file directory $LogFilePath" -Target $instance -Continue
                }
            }

            if (-not (Test-DbaPath -SqlInstance $server -Path $DataFilePath)) {
                try {
                    Write-Message -Message "Creating directory $DataFilePath" -Level Verbose
                    $null = New-DbaDirectory -SqlInstance $server -Path $DataFilePath -EnableException
                } catch {
                    Stop-Function -Message "Error creating secondary file directory $DataFilePath on $instance" -Target $instance -Continue
                }
            }

            Write-Message -Message "Set local data path to $DataFilePath and local log path to $LogFilePath" -Level Verbose

            foreach ($dbName in $Name) {
                if ($server.Databases[$dbName].Name) {
                    Stop-Function -Message "Database $dbName already exists on $instance" -Target $instance -Continue
                }

                try {
                    Write-Message -Message "Creating smo object for new database $dbName" -Level Verbose
                    $newdb = New-Object Microsoft.SqlServer.Management.Smo.Database($server, $dbName)
                } catch {
                    Stop-Function -Message "Error creating database object for $dbName on server $server" -ErrorRecord $_ -Target $instance -Continue
                }

                if ($Collation) {
                    Write-Message -Message "Setting collation to $Collation" -Level Verbose
                    $newdb.Collation = $Collation
                }

                if ($RecoveryModel) {
                    Write-Message -Message "Setting recovery model to $RecoveryModel" -Level Verbose
                    $newdb.RecoveryModel = $RecoveryModel
                }

                if ($advancedconfig) {
                    try {
                        Write-Message -Message "Creating PRIMARY filegroup" -Level Verbose
                        $primaryfg = New-Object Microsoft.SqlServer.Management.Smo.Filegroup($newdb, "PRIMARY")
                        $newdb.Filegroups.Add($primaryfg)
                    } catch {
                        Stop-Function -Message "Error creating Primary filegroup object" -ErrorRecord $_ -Target $instance -Continue
                    }

                    #add the primary file
                    try {
                        $primaryfilename = $dbName + $DataFileSuffix
                        Write-Message -Message "Creating file name $primaryfilename in filegroup PRIMARY" -Level Verbose

                        # if PrimaryFilesize and PrimaryFileMaxSize were passed in then check the size of the modeldev file; if larger than our $PrimaryFilesize setting use that instead
                        if ($server.Databases["model"].FileGroups["PRIMARY"].Files["modeldev"].Size -gt ($PrimaryFilesize * 1024)) {
                            Write-Message -Message "model database modeldev larger than our the PrimaryFilesize so using modeldev size for Primary file" -Level Verbose
                            $PrimaryFilesize = ($server.Databases["model"].FileGroups["PRIMARY"].Files["modeldev"].Size / 1024)
                            if ($PrimaryFilesize -gt $PrimaryFileMaxSize) {
                                Write-Message -Message "Resetting Primary File Max size to be the new Primary File Size setting" -Level Verbose
                                $PrimaryFileMaxSize = $PrimaryFilesize
                            }
                        }

                        #create the primary file
                        $primaryfile = New-Object Microsoft.SqlServer.Management.Smo.DataFile($primaryfg, $primaryfilename)
                        $primaryfile.FileName = $DataFilePath + "\" + $primaryfilename + ".mdf"
                        $primaryfile.IsPrimaryFile = $true

                        if (Test-Bound -ParameterName PrimaryFilesize) {
                            $primaryfile.Size = ($PrimaryFilesize * 1024)
                        } else {
                            $primaryfile.Size = $server.Databases["model"].FileGroups["PRIMARY"].Files["modeldev"].Size
                        }
                        if (Test-Bound -ParameterName PrimaryFileGrowth) {
                            $primaryfile.Growth = ($PrimaryFileGrowth * 1024)
                            $primaryfile.GrowthType = "KB"
                        } else {
                            $primaryfile.Growth = $server.Databases["model"].FileGroups["PRIMARY"].Files["modeldev"].Growth
                            $primaryfile.GrowthType = $server.Databases["model"].FileGroups["PRIMARY"].Files["modeldev"].GrowthType
                        }
                        if (Test-Bound -ParameterName PrimaryFileMaxSize) {
                            $primaryfile.MaxSize = ($PrimaryFileMaxSize * 1024)
                        } else {
                            $primaryfile.MaxSize = $server.Databases["model"].FileGroups["PRIMARY"].Files["modeldev"].MaxSize
                        }

                        #add the file to the filegroup
                        $primaryfg.Files.Add($primaryfile)
                    } catch {
                        Stop-Function -Message "Error adding file to Primary filegroup" -ErrorRecord $_ -Target $instance -Continue
                    }

                    try {
                        $logname = $dbName + $LogFileSuffix
                        Write-Message -Message "Creating log $logname" -Level Verbose

                        # if LogSize and LogMaxSize were passed in then check the size of the modellog file; if larger than our $LogSize setting use that instead
                        if ($server.Databases["model"].LogFiles["modellog"].Size -gt ($LogSize * 1024)) {
                            Write-Message -Message "model database modellog larger than our the LogSize so using modellog size for Log file size" -Level Verbose
                            $LogSize = ($server.Databases["model"].LogFiles["modellog"].Size / 1024)
                            if ($LogSize -gt $LogMaxSize) {
                                Write-Message -Message "Resetting Log File Max size to be the new Log File Size setting" -Level Verbose
                                $LogMaxSize = $LogSize
                            }
                        }

                        $tlog = New-Object Microsoft.SqlServer.Management.Smo.LogFile($newdb, $logname)
                        $tlog.FileName = $LogFilePath + "\" + $logname + ".ldf"

                        if (Test-Bound -ParameterName LogSize) {
                            $tlog.Size = ($LogSize * 1024)
                        } else {
                            $tlog.Size = $server.Databases["model"].LogFiles["modellog"].Size
                        }
                        if (Test-Bound -ParameterName LogGrowth) {
                            $tlog.Growth = ($LogGrowth * 1024)
                            $tlog.GrowthType = "KB"
                        } else {
                            $tlog.Growth = $server.Databases["model"].LogFiles["modellog"].Growth
                            $tlog.GrowthType = $server.Databases["model"].LogFiles["modellog"].GrowthType
                        }
                        if (Test-Bound -ParameterName LogMaxSize) {
                            $tlog.MaxSize = ($LogMaxSize * 1024)
                        } else {
                            $tlog.MaxSize = $server.Databases["model"].LogFiles["modellog"].MaxSize
                        }

                        #add the log to the db
                        $newdb.LogFiles.Add($tlog)
                    } catch {
                        Stop-Function -Message "Error adding log file to database." -ErrorRecord $_ -Target $instance -Continue
                    }

                    if ($DefaultFileGroup -eq "Secondary" -or (Test-Bound -ParameterName SecondaryFileMaxSize, SecondaryFileGrowth, SecondaryFilesize, SecondaryFileCount)) {
                        #add the Secondary data file group
                        try {
                            $secondaryfilegroupname = $dbName + $SecondaryDataFileSuffix
                            Write-Message -Message "Creating Secondary filegroup $secondaryfilegroupname" -Level Verbose

                            $secondaryfg = New-Object Microsoft.SqlServer.Management.Smo.Filegroup($newdb, $secondaryfilegroupname)
                            $newdb.Filegroups.Add($secondaryfg)
                        } catch {
                            Stop-Function -Message "Error creating Secondary filegroup" -ErrorRecord $_ -Target $instance -Continue
                        }

                        # if SecondaryFilesize and SecondaryFileMaxSize were passed in then check the size of the modeldev file; if larger than our $SecondaryFilesize setting use that instead
                        if ($server.Databases["model"].FileGroups["PRIMARY"].Files["modeldev"].Size -gt ($SecondaryFilesize * 1024)) {
                            Write-Message -Message "model database modeldev larger than our the SecondaryFilesize so using modeldev size for the Secondary file" -Level Verbose
                            $SecondaryFilesize = ($server.Databases["model"].FileGroups["PRIMARY"].Files["modeldev"].Size / 1024)
                            if ($SecondaryFilesize -gt $SecondaryFileMaxSize) {
                                Write-Message -Message "Resetting Secondary File Max size to be the new Secondary File Size setting" -Level Verbose
                                $SecondaryFileMaxSize = $SecondaryFilesize
                            }
                        }

                        # add the required number of files to the filegroup in a loop
                        $secondaryfgcount = $bail = 0

                        # open a loop while the filecounter is less than the required number of files
                        do {
                            $secondaryfgcount++
                            try {
                                $secondaryfilename = "$($secondaryfilegroupname)_$($secondaryfgcount)"
                                Write-Message -Message "Creating file name $secondaryfilename in filegroup $secondaryfilegroupname" -Level Verbose
                                $secondaryfile = New-Object Microsoft.SQLServer.Management.Smo.Datafile($secondaryfg, $secondaryfilename)
                                $secondaryfile.FileName = $DataFilePath + "\" + $secondaryfilename + ".ndf"

                                if (Test-Bound -ParameterName SecondaryFilesize) {
                                    $secondaryfile.Size = ($SecondaryFilesize * 1024)
                                } else {
                                    $secondaryfile.Size = $server.Databases["model"].FileGroups["PRIMARY"].Files["modeldev"].Size
                                }
                                if (Test-Bound -ParameterName SecondaryFileGrowth) {
                                    $secondaryfile.Growth = ($SecondaryFileGrowth * 1024)
                                    $secondaryfile.GrowthType = "KB"
                                } else {
                                    $secondaryfile.Growth = $server.Databases["model"].FileGroups["PRIMARY"].Files["modeldev"].Growth
                                    $secondaryfile.GrowthType = $server.Databases["model"].FileGroups["PRIMARY"].Files["modeldev"].GrowthType
                                }
                                if (Test-Bound -ParameterName SecondaryFileMaxSize) {
                                    $secondaryfile.MaxSize = ($SecondaryFileMaxSize * 1024)
                                } else {
                                    $secondaryfile.MaxSize = $server.Databases["model"].FileGroups["PRIMARY"].Files["modeldev"].MaxSize
                                }

                                $secondaryfg.Files.Add($secondaryfile)
                            } catch {
                                $bail = $true
                                Stop-Function -Message "Error adding file $secondaryfg to $secondaryfilegroupname" -ErrorRecord $_ -Target $instance
                                return
                            }
                        } while ($secondaryfgcount -lt $SecondaryFileCount -or $bail)
                    }
                }

                Write-Message -Message "Creating Database $dbName" -Level Verbose
                if ($PSCmdlet.ShouldProcess($instance, "Creating the database $dbName on instance $instance")) {
                    try {
                        $newdb.Create()
                    } catch {
                        Stop-Function -Message "Error creating Database $dbName on server $instance" -ErrorRecord $_ -Target $instance -Continue
                    }

                    if ($Owner) {
                        Write-Message -Message "Setting database owner to $Owner" -Level Verbose
                        try {
                            $newdb.SetOwner($Owner)
                            $newdb.Refresh()
                        } catch {
                            Stop-Function -Message "Error setting Database Owner to $Owner" -ErrorRecord $_ -Target $instance -Continue
                        }
                    }

                    if ($DefaultFileGroup -eq "Secondary") {
                        Write-Message -Message "Setting default filegroup to $secondaryfilegroupname" -Level Verbose
                        try {
                            $newdb.SetDefaultFileGroup($secondaryfilegroupname)
                        } catch {
                            Stop-Function -Message "Error setting default filegroup to $secondaryfilegroupname" -ErrorRecord $_ -Target $instance -Continue
                        }
                    }

                    Add-TeppCacheItem -SqlInstance $server -Type database -Name $dbName
                    Get-DbaDatabase -SqlInstance $server -Database $dbName
                }
            }
        }
    }
}
# SIG # Begin signature block
# MIIjYAYJKoZIhvcNAQcCoIIjUTCCI00CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCDBw6av2wGTwUJE
# SwWg2pyWQkRM2MzDB1dPGg5/lJjR06CCHVkwggUaMIIEAqADAgECAhADBbuGIbCh
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
# BgorBgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCC8QYq4h9472Vdsi+tL4T3eypdJ
# y+sPRNXoFz2BdBp+CTANBgkqhkiG9w0BAQEFAASCAQAYPaiRIMuX2aLDziWTAlo/
# qVUrAhruiC+hDjbWb7htPGUkPaT2Q8TM7UZnenioy0o7vwsYm4E37Qacd2bEkJkB
# 3mqODzYLm43hRqDdg80HTPczDsuiyovek9TRCCyf7AVVFphcPfpSetrAjkZLkT2d
# 7zQKLNfC5TTWr3velexGSdUNnSNiRR7+ufpYNzKu/uYbJ3z9/juOjNn2ATFVToTo
# 3ynci4vW+jmhFAOzx/Jr4JEUjclpj901MGgMHAiLx/2WesnXRJlPwo5JN5jV76Jy
# FdHPzorkPepYEKQ28kLAgzdfww9YPQqOwncXzOVR4VrI2ULpqaKnHc1WfE187dEd
# oYIDIDCCAxwGCSqGSIb3DQEJBjGCAw0wggMJAgEBMHcwYzELMAkGA1UEBhMCVVMx
# FzAVBgNVBAoTDkRpZ2lDZXJ0LCBJbmMuMTswOQYDVQQDEzJEaWdpQ2VydCBUcnVz
# dGVkIEc0IFJTQTQwOTYgU0hBMjU2IFRpbWVTdGFtcGluZyBDQQIQDE1pckuU+jwq
# Sj0pB4A9WjANBglghkgBZQMEAgEFAKBpMBgGCSqGSIb3DQEJAzELBgkqhkiG9w0B
# BwEwHAYJKoZIhvcNAQkFMQ8XDTIyMTExNzA4NTY1NFowLwYJKoZIhvcNAQkEMSIE
# IJD8DQWtjnpV6B7ElLv3aOzeR7FiPSmb8P1baKmc5dhFMA0GCSqGSIb3DQEBAQUA
# BIICAHMHWXcfEEpX+/muDPAUuIi7ngQ96FygDB+KVUj/nnxU2M85G2mHgn5j6n0Y
# uG/OohJbjdjk0xczXc60/KwAe2RtUHIy37TWmqvrD4qgq+QQLih+UyWkhQRk1hmi
# cmSGMQBDeOcqkTDBtIgTSYLgJIM0iPNdB8lN2ZvF/YxI8eZ2dShUwaQ8jE5m8Uyr
# AoEL/qsNio5lqhQ3WAbtCHK8R6Sm2XVawt9aZEFKcPl8o/3Y1aoIN4VKaEC9ayWV
# 2+0LeuKQhEs/HtFeQ+HPQy9+XOS3XdJ3gxv7VKAr/r2cDtY8yOmMFzk1z0DEJpD0
# ysefs3zQvXmVmaVAU6AMVQARkC7DGJ/fG2ukoy9r6rjOZRMydi0N6Uzj83aW7KNA
# xlmQUnCiy2ae5NXMWdj+depdiHDLlMYfJVC2cXtV2aKJ5mVMfeM4Y4j/2DtzdonA
# TWCfnmOp/menvf4CWDzI8Ug7ffrsBH28+30YvecM4pq55AkmmUgQs65/RkXTHVTN
# I16+M7DiAAZrUGgFwfh9sJiU5D8Hd39kYaUpFpErVivI9ulp7HYM8F7CXtcyKo8h
# j87cXiRjmLI0D0snR0w76QDFB2qCl/BMSGxCbfPorF/Mvzf9TUZXpdvKEkxRBCgb
# bOD//JBexTc7w8/goiIOdDTkLYpVf6JlGqZCyBn4CbCWpbZM
# SIG # End signature block
