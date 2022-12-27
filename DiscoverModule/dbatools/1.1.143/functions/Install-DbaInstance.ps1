function Install-DbaInstance {
    <#
    .SYNOPSIS
        This function will help you to quickly install a SQL Server instance.

    .DESCRIPTION
        This function will help you to quickly install a SQL Server instance on one or many computers.
        Some of the things this function will do for you:
        * Add your login as an admin to the new instance
        * Search for SQL Server installations in the specified file repository
        * Generate SA password if needed
        * Install specific features using 'Default' and 'All' templates or cherry-pick the ones you need
        * Set number of tempdb files based on number of cores (SQL2016+)
        * Activate .Net 3.5 feature for SQL2012/2014
        * Restart the machine if needed after the installation is done

        Fully customizable installation parameters allow you to:
        * Use existing Configuration.ini files for the installation
        * Define service account credentials using native Powershell syntax
        * Override any configurations by using -Configuration switch
        * Change the TCP port after the installation is done
        * Enable 'Perform volume maintenance tasks' for the SQL Server account

        Note that the downloaded installation media must be extracted and available to the server where the installation runs.
        NOTE: If no ProductID (PID) is found in the configuration files/parameters, Evaluation version is going to be installed.

        When using CredSSP authentication, this function will try to configure CredSSP authentication for PowerShell Remoting sessions.
        If this is not desired (e.g.: CredSSP authentication is managed externally, or is already configured appropriately,)
        it can be disabled by setting the dbatools configuration option 'commands.initialize-credssp.bypass' value to $true.
        To be able to configure CredSSP, the command needs to be run in an elevated PowerShell session.

    .PARAMETER SqlInstance
        The target computer and, optionally, a new instance name and a port number.
        Use one of the following generic formats:
        Server1
        Server2\Instance1
        Server1\Alpha:1533, Server2\Omega:1566
        "ServerName\NewInstanceName,1534"

        You can also define instance name and port using -InstanceName and -Port parameters.

    .PARAMETER SaCredential
        Securely provide the password for the sa account when using mixed mode authentication.

    .PARAMETER Credential
        Windows Credential with permission to log on to the remote server.
        Must be specified for any remote connection if SQL Server installation media is located on a network folder.

        Authentication will default to CredSSP if -Credential is used.
        For CredSSP see also additional information in DESCRIPTION.

    .PARAMETER ConfigurationFile
        The path to the custom Configuration.ini file.

    .PARAMETER Configuration
        A hashtable with custom configuration items that you want to use during the installation.
        Overrides all other parameters.
        For example, to define a custom server collation you can use the following parameter:
        PS> Install-DbaInstance -Version 2017 -Configuration @{ SQLCOLLATION = 'Latin1_General_BIN' }

        As long as you don't specify the item ACTION, some items are already set by the command, like SQLSYSADMINACCOUNTS or *SVCSTARTUPTYPE.
        If you specify the item ACTION, only INSTANCENAME and FEATURES are set based on the corresponding parameters and QUIET is set to True.
        You will have to set all other needed items for your specific ACTION.
        But this way it is possible to use the command so install a Failover Cluster Instance or even to remove a SQL Server instance.

        More information about how to install a Failover Cluster Instance can be found here: https://github.com/dataplat/dbatools/discussions/7447

        Full list of parameters can be found here: https://docs.microsoft.com/en-us/sql/database-engine/install-windows/install-sql-server-from-the-command-prompt#Install

    .PARAMETER Authentication
        Chooses an authentication protocol for remote connections.
        Allowed values: 'Default', 'Basic', 'Negotiate', 'NegotiateWithImplicitCredential', 'Credssp', 'Digest', 'Kerberos'.
        If the protocol fails to establish a connection and explicit -Credentials were used, a failback authentication method would be attempted that configures PSSessionConfiguration
        on the remote machine. This method, however, is considered insecure and would, therefore, prompt an additional confirmation when used.

        Defaults:
        * CredSSP when -Credential is specified - due to the fact that repository Path is usually a network share and credentials need to be passed to the remote host to avoid the double-hop issue.
        * Default when -Credential is not specified. Will likely fail if a network path is specified.

        For CredSSP see also additional information in DESCRIPTION.

    .PARAMETER Version
        SQL Server version you wish to install.
        This is the year version (e.g. "2008R2", "2017", "2019")

    .PARAMETER InstanceName
        Name of the SQL Server instance to install. Overrides the instance name specified in -SqlInstance.

    .PARAMETER Feature
        Features to install. Templates like "Default" and "All" can be used to setup a predefined set of components. Full list of features:

        Default: Engine, Replication, FullText, Tools
        All
        Engine
        Tools: SSMS, BackwardsCompatibility, Connectivity
        Replication
        FullText
        DataQuality
        PolyBase
        MachineLearning
        AnalysisServices
        ReportingServices
        ReportingForSharepoint
        SharepointAddin
        IntegrationServices
        MasterDataServices
        PythonPackages
        RPackages
        BackwardsCompatibility
        Connectivity
        ReplayController
        ReplayClient
        SDK
        BIDS
        SSMS: SSMS, ADV_SSMS

    .PARAMETER InstancePath
        Root folder for instance components. Includes SQL Server logs, system databases, etc.

    .PARAMETER DataPath
        Path to the Data folder.

    .PARAMETER LogPath
        Path to the Log folder.

    .PARAMETER TempPath
        Path to the TempDB folder.

    .PARAMETER BackupPath
        Path to the Backup folder.

    .PARAMETER UpdateSourcePath
        Path to the updates that you want to slipstream into the installation.

    .PARAMETER AdminAccount
        One or more members of the sysadmin group. Uses UserName from the -Credential parameter if specified, or current Windows user by default.

    .PARAMETER Port
        After successful installation, changes SQL Server TCP port to this value. Overrides the port specified in -SqlInstance.

    .PARAMETER ProductID
        Product ID, or simply, serial number of your SQL Server installation, which will determine which version to install.
        If the PID is already built into the installation media, can be ignored.

    .PARAMETER AsCollation
        Collation for the Analysis Service.
        Default value: Latin1_General_CI_AS

    .PARAMETER SqlCollation
        Collation for the Database Engine.
        The default depends on the Windows locale:
        https://docs.microsoft.com/en-us/sql/relational-databases/collations/collation-and-unicode-support#Server-level-collations

    .PARAMETER EngineCredential
        Service account of the SQL Server Database Engine

    .PARAMETER AgentCredential
        Service account of the SQL Server Agent

    .PARAMETER ASCredential
        Service account of the Analysis Services

    .PARAMETER ISCredential
        Service account of the Integration Services

    .PARAMETER RSCredential
        Service account of the Reporting Services

    .PARAMETER FTCredential
        Service account of the Full-Text catalog service

    .PARAMETER PBEngineCredential
        Service account of the PolyBase service

    .PARAMETER Path
        Path to the folder(s) with SQL Server installation media downloaded. It will be scanned recursively for a corresponding setup.exe.
        Path should be available from the remote server.
        If a setup.exe file is missing in the repository, the installation will fail.
        Consider setting the following configuration in your session if you want to omit this parameter: `Set-DbatoolsConfig -Name Path.SQLServerSetup -Value '\\path\to\installations'`

    .PARAMETER PerformVolumeMaintenanceTasks
        Allow SQL Server service account to perform Volume Maintenance tasks.

    .PARAMETER SaveConfiguration
        Save installation configuration file in a custom location. Will not be preserved otherwise.

    .PARAMETER Throttle
        Maximum number of computers updated in parallel. Once reached, the update operations will queue up.
        Default: 50

    .PARAMETER Restart
        Restart computer automatically if a restart is required before or after the installation.

    .PARAMETER AuthenticationMode
        Chooses authentication mode for SQL Server. Allowed values: Mixed, Windows.

    .PARAMETER NoPendingRenameCheck
        Disables pending rename validation when checking for a pending reboot.

    .PARAMETER EnableException
        By default, when something goes wrong we try to catch it, interpret it and give you a friendly warning message.
        This avoids overwhelming you with "sea of red" exceptions, but is inconvenient because it basically disables advanced scripting.
        Using this switch turns this "nice by default" feature off and enables you to catch exceptions with your own try/catch.

    .PARAMETER WhatIf
        Shows what would happen if the command were to run. No actions are actually performed.

    .PARAMETER Confirm
        Prompts you for confirmation before executing any changing operations within the command.

    .NOTES
        Tags: Deployment, Install
        Author: Reitse Eskens (@2meterDBA), Kirill Kravtsov (@nvarscar)

        Website: https://dbatools.io
        Copyright: (c) 2018 by dbatools, licensed under MIT
        License: MIT https://opensource.org/licenses/MIT

    .LINK
        https://dbatools.io/Install-DbaInstance

    .Example
        PS C:\> Install-DbaInstance -Version 2017 -Feature All

        Install a default SQL Server instance and run the installation enabling all features with default settings. Automatically generates configuration.ini

    .Example
        PS C:\> Install-DbaInstance -SqlInstance sql2017\sqlexpress, server01 -Version 2017 -Feature Default

        Install a named SQL Server instance named sqlexpress on sql2017, and a default instance on server01. Automatically generates configuration.ini.
        Default features will be installed.

    .Example
        PS C:\> Install-DbaInstance -Version 2008R2 -SqlInstance sql2017 -ConfigurationFile C:\temp\configuration.ini

        Install a default named SQL Server instance on the remote machine, sql2017 and use the local configuration.ini

    .Example
        PS C:\> Install-DbaInstance -Version 2017 -InstancePath G:\SQLServer -UpdateSourcePath '\\my\updates'

        Run the installation locally with default settings apart from the application volume, this will be redirected to G:\SQLServer.
        The installation procedure would search for SQL Server updates in \\my\updates and slipstream them into the installation.

    .Example
        PS C:\> $svcAcc = Get-Credential MyDomain\SvcSqlServer
        PS C:\> Install-DbaInstance -Version 2016 -InstancePath D:\Root -DataPath E: -LogPath L: -PerformVolumeMaintenanceTasks -EngineCredential $svcAcc

        Install SQL Server 2016 instance into D:\Root drive, set default data folder as E: and default logs folder as L:.
        Perform volume maintenance tasks permission is granted. MyDomain\SvcSqlServer is used as a service account for SqlServer.

    .Example
        PS C:\> $config = @{
        >> AGTSVCSTARTUPTYPE = "Manual"
        >> BROWSERSVCSTARTUPTYPE = "Manual"
        >> FILESTREAMLEVEL = 1
        >> }
        PS C:\> Install-DbaInstance -SqlInstance localhost\v2017:1337 -Version 2017 -SqlCollation Latin1_General_CI_AS -Configuration $config

        Run the installation locally with default settings overriding the value of specific configuration items.
        Instance name will be defined as 'v2017'; TCP port will be changed to 1337 after installation.
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    param (
        [Alias('ComputerName')]
        [DbaInstanceParameter[]]$SqlInstance = $env:COMPUTERNAME,
        [parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [ValidateSet("2008", "2008R2", "2012", "2014", "2016", "2017", "2019")]
        [string]$Version,
        [string]$InstanceName,
        [PSCredential]$SaCredential,
        [PSCredential]$Credential,
        [ValidateSet('Default', 'Basic', 'Negotiate', 'NegotiateWithImplicitCredential', 'Credssp', 'Digest', 'Kerberos')]
        [string]$Authentication = @('Credssp', 'Default')[$null -eq $Credential],
        [parameter(ValueFromPipeline)]
        [Alias("FilePath")]
        [object]$ConfigurationFile,
        [hashtable]$Configuration,
        [string[]]$Path = (Get-DbatoolsConfigValue -Name 'Path.SQLServerSetup'),
        [ValidateSet("Default", "All", "Engine", "Tools", "Replication", "FullText", "DataQuality", "PolyBase", "MachineLearning", "AnalysisServices",
            "ReportingServices", "ReportingForSharepoint", "SharepointAddin", "IntegrationServices", "MasterDataServices", "PythonPackages", "RPackages",
            "BackwardsCompatibility", "Connectivity", "ReplayController", "ReplayClient", "SDK", "BIDS", "SSMS")]
        [string[]]$Feature = "Default",
        [ValidateSet("Windows", "Mixed")]
        [string]$AuthenticationMode = "Windows",
        [string]$InstancePath,
        [string]$DataPath,
        [string]$LogPath,
        [string]$TempPath,
        [string]$BackupPath,
        [string]$UpdateSourcePath,
        [string[]]$AdminAccount,
        [int]$Port,
        [int]$Throttle = 50,
        [Alias('PID')]
        [string]$ProductID,
        [string]$AsCollation,
        [string]$SqlCollation,
        [pscredential]$EngineCredential,
        [pscredential]$AgentCredential,
        [pscredential]$ASCredential,
        [pscredential]$ISCredential,
        [pscredential]$RSCredential,
        [pscredential]$FTCredential,
        [pscredential]$PBEngineCredential,
        [string]$SaveConfiguration,
        [switch]$PerformVolumeMaintenanceTasks,
        [switch]$Restart,
        [switch]$NoPendingRenameCheck = (Get-DbatoolsConfigValue -Name 'OS.PendingRename' -Fallback $false),
        [switch]$EnableException
    )
    begin {
        Function Read-IniFile {
            # Reads an ini file from a disk and returns a hashtable with a corresponding structure
            Param (
                $Path
            )
            #Collect config entries from the ini file
            Write-Message -Level Verbose -Message "Reading Ini file from $Path"
            $config = @{ }
            switch -regex -file $Path {
                #Comment
                '^#.*' { continue }
                #Section
                "^\[(.+)\]\s*$" {
                    $section = $matches[1]
                    if (-not $config.$section) {
                        $config.$section = @{ }
                    }
                    continue
                }
                #Item
                "^(.+)=(.+)$" {
                    $name, $value = $matches[1..2]
                    $config.$section.$name = $value.Trim('''"')
                    continue
                }
            }
            return $config
        }
        Function Write-IniFile {
            # Writes a hashtable into a file in a format of an ini file
            Param (
                [hashtable]$Content,
                $Path
            )
            Write-Message -Level Verbose -Message "Writing Ini file to $Path"
            $output = @()
            foreach ($key in $Content.Keys) {
                $output += "[$key]"
                if ($Content.$key -is [hashtable]) {
                    foreach ($sectionKey in $Content.$key.Keys) {
                        $origVal = $Content.$key.$sectionKey
                        if ($origVal -is [array]) {
                            $output += "$sectionKey=`"$($origVal -join ',')`""
                        } else {
                            if ($origVal -is [int]) {
                                $origVal = "$origVal"
                            }
                            if ($origVal -ne $origVal.Trim('"')) {
                                $output += "$sectionKey=$origVal"
                            } else {
                                $output += "$sectionKey=`"$origVal`""
                            }
                        }
                    }
                }
            }
            Set-Content -Path $Path -Value $output -Force
        }
        Function Update-ServiceCredential {
            [Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSAvoidUsingPlainTextForPassword", "")]
            [Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSUseShouldProcessForStateChangingFunctions", "")]
            # updates a service account entry and returns the password as a command line argument
            Param (
                $Node,
                [pscredential]$Credential,
                [string]$AccountName,
                [string]$PasswordName = $AccountName.Replace('SVCACCOUNT', 'SVCPASSWORD')
            )
            if ($Credential) {
                if ($AccountName) {
                    $Node.$AccountName = $Credential.UserName
                }
                if ($Credential.Password.Length -gt 0) {
                    return "/$PasswordName=`"" + $Credential.GetNetworkCredential().Password + '"'
                }
            }
        }
        # defining local vars
        $notifiedCredentials = $false
        $notifiedUnsecure = $false

        # read component names
        $components = Get-Content -Path $Script:PSModuleRoot\bin\dbatools-sqlinstallationcomponents.json -Raw | ConvertFrom-Json
    }
    process {
        if (!$Path) {
            Stop-Function -Message "Path to SQL Server setup folder is not set. Consider running Set-DbatoolsConfig -Name Path.SQLServerSetup -Value '\\path\to\updates' or specify the path in the original command"
            return
        }
        # getting a numeric version for further comparison
        #$canonicVersion = (Get-DbaBuild -MajorVersion $Version).BuildLevel
        [version]$canonicVersion = switch ($Version) {
            2008 { '10.0' }
            2008R2 { '10.50' }
            2012 { '11.0' }
            2014 { '12.0' }
            2016 { '13.0' }
            2017 { '14.0' }
            2019 { '15.0' }
            default {
                Stop-Function -Message "Version $Version is not supported"
                return
            }
        }

        # build feature list
        $featureList = @()
        foreach ($f in $Feature) {
            $featureDef = $components | Where-Object Name -contains $f
            foreach ($fd in $featureDef) {
                if (($fd.MinimumVersion -and $canonicVersion -lt [version]$fd.MinimumVersion) -or ($fd.MaximumVersion -and $canonicVersion -gt [version]$fd.MaximumVersion)) {
                    # exclude Default, All, and Tools, as they are expected to have SSMS components in some cases
                    if ($f -notin 'Default', 'All', 'Tools') {
                        Stop-Function -Message "Feature $f($($fd.Feature)) is not supported on SQL$Version"
                        return
                    }
                } else {
                    $featureList += $fd.Feature
                }
            }
        }

        # auto generate a random password if mixed is chosen and a credential is not provided
        if ($AuthenticationMode -eq "Mixed" -and -not $SaCredential) {
            $secpasswd = Get-RandomPassword -Length 15
            $SaCredential = New-Object System.Management.Automation.PSCredential ("sa", $secpasswd)
        }

        # turn the configuration file into an object so we can access it various ways
        if ($ConfigurationFile) {
            try {
                $ConfigurationFile = Get-Item -Path $ConfigurationFile -ErrorAction Stop
            } catch {
                Stop-Function -Message "Configuration file not found" -ErrorRecord $_
                return
            }
        }

        # check if installation path(s) is a network path and try to access it from the local machine
        Write-ProgressHelper -ExcludePercent -Activity "Looking for setup files" -StepNumber 0 -Message "Checking if installation is available locally"
        $isNetworkPath = $true
        foreach ($p in $Path) { if ($p -notlike '\\*') { $isNetworkPath = $false } }
        if ($isNetworkPath) {
            Write-Message -Level Verbose -Message "Looking for installation files in $($Path) on a local machine"
            try {
                $localSetupFile = Find-SqlInstanceSetup -Version $canonicVersion -Path $Path
            } catch {
                Write-Message -Level Verbose -Message "Failed to access $($Path) on a local machine, ignoring for now"
            }
        }

        $actionPlan = @()
        foreach ($computer in $SqlInstance) {
            $stepCounter = 1
            $totalSteps = 5
            $activity = "Preparing to install SQL Server $Version on $computer"
            # Test elevated console
            $null = Test-ElevationRequirement -ComputerName $computer -Continue
            # notify about credentials once
            if (-not $computer.IsLocalHost -and -not $notifiedCredentials -and -not $Credential -and $isNetworkPath) {
                Write-Message -Level Warning -Message "Explicit -Credential might be required when running agains remote hosts and -Path is a network folder"
                $notifiedCredentials = $true
            }
            # resolve names
            Write-ProgressHelper -TotalSteps $totalSteps -Activity $activity -StepNumber ($stepCounter++) -Message "Resolving computer name"
            $resolvedName = Resolve-DbaNetworkName -ComputerName $computer -Credential $Credential
            if ($computer.IsLocalHost) {
                # Don't add a domain to localhost as this might add a domain that is later not recognized by .IsLocalHost anymore (#6976).
                $fullComputerName = $resolvedName.ComputerName
            } else {
                $fullComputerName = $resolvedName.FullComputerName
            }
            # test if the restart is needed
            Write-ProgressHelper -TotalSteps $totalSteps -Activity $activity -StepNumber ($stepCounter++) -Message "Checking for pending restarts"
            try {
                $restartNeeded = Test-PendingReboot -ComputerName $fullComputerName -Credential $Credential
            } catch {
                Stop-Function -Message "Failed to get reboot status from $fullComputerName" -Continue -ErrorRecord $_
            }
            if ($restartNeeded -and (-not $Restart -or $computer.IsLocalHost)) {
                #Exit the actions loop altogether - nothing can be installed here anyways
                Stop-Function -Message "$computer is pending a reboot. Reboot the computer before proceeding." -Continue
            }
            # test connection
            if ($Credential -and -not ([DbaInstanceParameter]$computer).IsLocalHost) {
                $totalSteps += 1
                Write-ProgressHelper -TotalSteps $totalSteps -Activity $activity -StepNumber ($stepCounter++) -Message "Testing $Authentication protocol"
                Write-Message -Level Verbose -Message "Attempting to test $Authentication protocol for remote connections"
                try {
                    $connectSuccess = Invoke-Command2 -ComputerName $fullComputerName -Credential $Credential -Authentication $Authentication -ScriptBlock { $true } -Raw
                } catch {
                    $connectSuccess = $false
                }
                # if we use CredSSP, we might be able to configure it
                if (-not $connectSuccess -and $Authentication -eq 'Credssp') {
                    $totalSteps += 1
                    Write-ProgressHelper -TotalSteps $totalSteps -Activity $activity -StepNumber ($stepCounter++) -Message "Configuring CredSSP protocol"
                    Write-Message -Level Verbose -Message "Attempting to configure CredSSP for remote connections"
                    try {
                        Initialize-CredSSP -ComputerName $fullComputerName -Credential $Credential -EnableException $true
                        $connectSuccess = Invoke-Command2 -ComputerName $fullComputerName -Credential $Credential -Authentication $Authentication -ScriptBlock { $true } -Raw
                    } catch {
                        $connectSuccess = $false
                        # tell the user why we could not configure CredSSP
                        Write-Message -Level Warning -Message $_
                    }
                }
                # in case we are still not successful, ask the user to use unsecure protocol once
                if (-not $connectSuccess -and -not $notifiedUnsecure) {
                    if ($PSCmdlet.ShouldProcess($fullComputerName, "Primary protocol ($Authentication) failed, sending credentials via potentially unsecure protocol")) {
                        $notifiedUnsecure = $true
                    } else {
                        Stop-Function -Message "Failed to connect to $fullComputerName through $Authentication protocol. No actions will be performed on that computer." -Continue
                    }
                }
            }
            # find installation file
            Write-ProgressHelper -TotalSteps $totalSteps -Activity $activity -StepNumber ($stepCounter++) -Message "Verifying access to setup files"
            $setupFileIsAccessible = $false
            if ($localSetupFile) {
                $testSetupPathParams = @{
                    ComputerName   = $fullComputerName
                    Credential     = $Credential
                    Authentication = $Authentication
                    ScriptBlock    = {
                        Param (
                            [string]$Path
                        )
                        try {
                            return Test-Path $Path
                        } catch {
                            return $false
                        }
                    }
                    ArgumentList   = @($localSetupFile)
                    ErrorAction    = 'Stop'
                    Raw            = $true
                }
                try {
                    $setupFileIsAccessible = Invoke-CommandWithFallback @testSetupPathParams
                } catch {
                    $setupFileIsAccessible = $false
                }
            }
            if ($setupFileIsAccessible) {
                Write-Message -Level Verbose -Message "Setup file $localSetupFile is reachable from remote machine $fullComputerName"
                $setupFile = $localSetupFile
            } else {
                Write-Message -Level Verbose -Message "Looking for installation files in $($Path) on remote machine $fullComputerName"
                $findSetupParams = @{
                    ComputerName   = $fullComputerName
                    Credential     = $Credential
                    Authentication = $Authentication
                    Version        = $canonicVersion
                    Path           = $Path
                }
                try {
                    $setupFile = Find-SqlInstanceSetup @findSetupParams
                } catch {
                    Stop-Function -Message "Failed to enumerate files in $Path" -ErrorRecord $_ -Continue
                }
            }
            if (-not $setupFile) {
                Stop-Function -Message "Failed to find setup file for SQL$Version in $Path on $fullComputerName" -Continue
            }
            Write-ProgressHelper -TotalSteps $totalSteps -Activity $activity -StepNumber ($stepCounter++) -Message "Generating a configuration file"
            $instance = if ($InstanceName) { $InstanceName } else { $computer.InstanceName }
            # checking if we need to modify port after the installation
            $portNumber = if ($Port) { $Port } elseif ($computer.Port -in 0, 1433) { $null } else { $computer.Port }
            $mainKey = if ($canonicVersion -ge '11.0') { "OPTIONS" } else { "SQLSERVER2008" }
            if (Test-Bound -ParameterName ConfigurationFile) {
                try {
                    $config = Read-IniFile -Path $ConfigurationFile
                } catch {
                    Stop-Function -Message "Failed to read config file $ConfigurationFile" -ErrorRecord $_
                }
            } elseif ($Configuration.ACTION) {
                # build minimal config if a custom ACTION is provided
                $config = @{
                    $mainKey = @{
                        INSTANCENAME = $instance
                        FEATURES     = $featureList
                        QUIET        = "True"
                    }
                }
                # To support failover cluster instance:
                if ($Configuration.ACTION -in 'AddNode', 'RemoveNode') {
                    $config.$mainKey.Remove('FEATURES')
                }
            } else {
                # determine a default user to assign sqladmin permissions
                if ($Credential) {
                    $defaultAdminAccount = $Credential.UserName
                } else {
                    if ($env:USERDOMAIN) {
                        $defaultAdminAccount = "$env:USERDOMAIN\$env:USERNAME"
                    } else {
                        if ($computer.IsLocalHost) {
                            $defaultAdminAccount = "$($resolvedName.ComputerName)\$env:USERNAME"
                        } else {
                            $defaultAdminAccount = $env:USERNAME
                        }
                    }
                }
                # determine browser startup
                if ($instance -eq 'MSSQLSERVER') { $browserStartup = 'Manual' }
                else { $browserStartup = 'Automatic' }
                # build generic config based on parameters
                $config = @{
                    $mainKey = @{
                        ACTION                = "Install"
                        AGTSVCSTARTUPTYPE     = "Automatic"
                        BROWSERSVCSTARTUPTYPE = $browserStartup
                        ENABLERANU            = "False"
                        ERRORREPORTING        = "False"
                        FEATURES              = $featureList
                        FILESTREAMLEVEL       = "0"
                        HELP                  = "False"
                        INDICATEPROGRESS      = "False"
                        INSTANCEID            = $instance
                        INSTANCENAME          = $instance
                        ISSVCSTARTUPTYPE      = "Automatic"
                        QUIET                 = "True"
                        QUIETSIMPLE           = "False"
                        SQLSVCSTARTUPTYPE     = "Automatic"
                        SQLSYSADMINACCOUNTS   = $defaultAdminAccount
                        SQMREPORTING          = "False"
                        TCPENABLED            = "1"
                        UPDATEENABLED         = "False"
                        X86                   = "False"
                    }
                }
            }
            $configNode = $config.$mainKey
            if (-not $configNode) {
                Stop-Function -Message "Incorrect configuration file. Main node $mainKey not found."
                return
            }
            $execParams = @()
            # collation-specific parameters
            if ($AsCollation) {
                $configNode.ASCOLLATION = $AsCollation
            }
            if ($SqlCollation) {
                $configNode.SQLCOLLATION = $SqlCollation
            }
            # feature-specific parameters
            # Python
            foreach ($pythonFeature in 'SQL_INST_MPY', 'SQL_SHARED_MPY', 'AdvancedAnalytics') {
                if ($pythonFeature -in $featureList) {
                    $execParams += '/IACCEPTPYTHONLICENSETERMS'
                    break
                }
            }
            # R
            foreach ($rFeature in 'SQL_INST_MR', 'SQL_SHARED_MR', 'AdvancedAnalytics') {
                if ($rFeature -in $featureList) {
                    $execParams += '/IACCEPTROPENLICENSETERMS '
                    break
                }
            }
            # Reporting Services
            if ('RS' -in $featureList) {
                if (-Not $configNode.RSINSTALLMODE) { $configNode.RSINSTALLMODE = "DefaultNativeMode" }
                if (-Not $configNode.RSSVCSTARTUPTYPE) { $configNode.RSSVCSTARTUPTYPE = "Automatic" }
            }
            # version-specific stuff
            if ($canonicVersion -gt '10.0') {
                $execParams += '/IACCEPTSQLSERVERLICENSETERMS'
            }
            if ($canonicVersion -ge '13.0' -and ($configNode.ACTION -in 'Install', 'CompleteImage', 'Rebuilddatabase', 'InstallFailoverCluster', 'CompleteFailoverCluster') -and (-not $configNode.SQLTEMPDBFILECOUNT)) {
                # configure the number of cores
                $cpuInfo = Get-DbaCmObject -ComputerName $fullComputerName -Credential $Credential -ClassName Win32_processor -EnableException:$EnableException
                # trying to read NumberOfLogicalProcessors property. If it's not available, read NumberOfCores
                try {
                    [int]$cores = $cpuInfo | Measure-Object NumberOfLogicalProcessors -Sum -ErrorAction Stop | Select-Object -ExpandProperty sum
                } catch {
                    [int]$cores = $cpuInfo | Measure-Object NumberOfCores -Sum | Select-Object -ExpandProperty sum
                }
                if ($cores -gt 8) {
                    $cores = 8
                }
                if ($cores) {
                    $configNode.SQLTEMPDBFILECOUNT = $cores
                }
            }
            # Apply custom configuration keys if provided
            if ($Configuration) {
                foreach ($key in $Configuration.Keys) {
                    if ($key -eq "SQLUSERDBDATADIR") {
                        # fix for our book
                        $key = "SQLUSERDBDIR"
                        $configNode.$key = [string]$Configuration."SQLUSERDBDATADIR"
                    } else {
                        $configNode.$key = [string]$Configuration.$key
                    }
                    if ($key -eq 'UpdateSource' -and $configNode.$key -and $Configuration.Keys -notcontains 'UPDATEENABLED') {
                        #enable updates since now we have a source
                        $configNode.UPDATEENABLED = "True"
                    }
                }
            }

            # Now apply credentials
            $execParams += Update-ServiceCredential -Node $configNode -Credential $EngineCredential -AccountName SQLSVCACCOUNT
            $execParams += Update-ServiceCredential -Node $configNode -Credential $AgentCredential -AccountName AGTSVCACCOUNT
            $execParams += Update-ServiceCredential -Node $configNode -Credential $ASCredential -AccountName ASSVCACCOUNT
            $execParams += Update-ServiceCredential -Node $configNode -Credential $ISCredential -AccountName ISSVCACCOUNT
            $execParams += Update-ServiceCredential -Node $configNode -Credential $RSCredential -AccountName RSSVCACCOUNT
            $execParams += Update-ServiceCredential -Node $configNode -Credential $FTCredential -AccountName FTSVCACCOUNT
            $execParams += Update-ServiceCredential -Node $configNode -Credential $PBEngineCredential -AccountName PBENGSVCACCOUNT -PasswordName PBDMSSVCPASSWORD
            $execParams += Update-ServiceCredential -Credential $SaCredential -PasswordName SAPWD
            # And root folders and other variables
            if (Test-Bound -ParameterName InstancePath) {
                $configNode.INSTANCEDIR = $InstancePath
            }
            if (Test-Bound -ParameterName DataPath) {
                $configNode.SQLUSERDBDIR = $DataPath
            }
            if (Test-Bound -ParameterName LogPath) {
                $configNode.SQLUSERDBLOGDIR = $LogPath
            }
            if (Test-Bound -ParameterName TempPath) {
                $configNode.SQLTEMPDBDIR = $TempPath
            }
            if (Test-Bound -ParameterName BackupPath) {
                $configNode.SQLBACKUPDIR = $BackupPath
            }
            if (Test-Bound -ParameterName AdminAccount) {
                $configNode.SQLSYSADMINACCOUNTS = ($AdminAccount | ForEach-Object { '"{0}"' -f $_ }) -join ' '
            }
            if (Test-Bound -ParameterName UpdateSourcePath) {
                $configNode.UPDATESOURCE = $UpdateSourcePath
                $configNode.UPDATEENABLED = "True"
            }
            # PID
            if (Test-Bound -ParameterName ProductID) {
                $configNode.PID = $ProductID
            }
            # Authentication
            if ($AuthenticationMode -eq 'Mixed') {
                $configNode.SECURITYMODE = "SQL"
            }

            # save config file
            $tempdir = Get-DbatoolsConfigValue -FullName path.dbatoolstemp
            $configFile = "$tempdir\Configuration_$($fullComputerName)_$instance_$version.ini"
            try {
                Write-IniFile -Content $config -Path $configFile
            } catch {
                Stop-Function -Message "Failed to write config file to $configFile" -ErrorRecord $_
            }
            if ($PSCmdlet.ShouldProcess($fullComputerName, "Install $Version from $setupFile")) {
                $actionPlan += @{
                    ComputerName                  = $fullComputerName
                    InstanceName                  = $instance
                    Port                          = $portNumber
                    InstallationPath              = $setupFile
                    ConfigurationPath             = $configFile
                    ArgumentList                  = $execParams
                    Restart                       = $Restart
                    Version                       = $canonicVersion
                    Configuration                 = $config
                    SaveConfiguration             = $SaveConfiguration
                    SaCredential                  = $SaCredential
                    PerformVolumeMaintenanceTasks = $PerformVolumeMaintenanceTasks
                    Credential                    = $Credential
                    NoPendingRenameCheck          = $NoPendingRenameCheck
                    EnableException               = $EnableException
                }
            }
            Write-Progress -Activity $activity -Complete
        }
        # we need to know if authentication was explicitly defined
        $authBound = Test-Bound Authentication
        # wrapper for parallel advanced install
        $installAction = {
            $installSplat = $_
            if ($authBound) {
                $installSplat.Authentication = $Authentication
            }
            Invoke-DbaAdvancedInstall @installSplat
        }
        # check how many computers we are looking at and decide upon parallelism
        if ($actionPlan.Count -eq 1) {
            $actionPlan | ForEach-Object -Process $installAction
        } elseif ($actionPlan.Count -ge 2) {
            $invokeParallelSplat = @{
                ScriptBlock = $installAction
                Throttle    = $Throttle
                Activity    = "Installing SQL Server $Version on $($actionPlan.Count) computers"
                Status      = "Running the installation"
                ObjectName  = 'computers'
            }
            $actionPlan | Invoke-Parallel -ImportModules -ImportVariables @invokeParallelSplat
        }
    }
}

# SIG # Begin signature block
# MIIjYAYJKoZIhvcNAQcCoIIjUTCCI00CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCA8z50MPeJ8WZpS
# L4Z82XY1KhATio1dfUPxLQcfDP5TcaCCHVkwggUaMIIEAqADAgECAhADBbuGIbCh
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
# BgorBgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCB2RwZEDPiLQm9llDLFjtHC0fId
# cvohWPR+XV9G0BqTODANBgkqhkiG9w0BAQEFAASCAQB9UPO7zeUhHTR5i9QF+B76
# 5opz8Lw5KxhXQ7w4kgXXMKMsCVjHY5FdqBbSL7szZ5VjaPdq2Gl6wA6QuEQs0H5R
# /y758sEeKFfiVnCFLS3E5oKvzpwY//LhqwHCPcnYuahyA6qLFRY9ovoQotBvMMVR
# QJcjeYrZmxHvcEx+ooHDMGZUyZp1uBFAkgtKcauVnUcZxIR23aCNmpUhP5M/6Gr6
# 0H32tpIaPMb9Gqo8R18+/JKyq0bRHp3O47E941/mZ918MWCINMFMzhyMX/LTBF9s
# pnsu/JeG3M/XXhccDBDGsNTZBcT/DyI73hK28t47Eqs1aHp5SJc0LcPHZBI4JAm9
# oYIDIDCCAxwGCSqGSIb3DQEJBjGCAw0wggMJAgEBMHcwYzELMAkGA1UEBhMCVVMx
# FzAVBgNVBAoTDkRpZ2lDZXJ0LCBJbmMuMTswOQYDVQQDEzJEaWdpQ2VydCBUcnVz
# dGVkIEc0IFJTQTQwOTYgU0hBMjU2IFRpbWVTdGFtcGluZyBDQQIQDE1pckuU+jwq
# Sj0pB4A9WjANBglghkgBZQMEAgEFAKBpMBgGCSqGSIb3DQEJAzELBgkqhkiG9w0B
# BwEwHAYJKoZIhvcNAQkFMQ8XDTIyMTExNzA4NTYzOFowLwYJKoZIhvcNAQkEMSIE
# IKKE4eoQ8+9SmNlkvDnempbwYkAssCGKNX1/09sCzOK/MA0GCSqGSIb3DQEBAQUA
# BIICAAB4oHCTPTWm6efR+9iAplX0vY2LfXdSwEsRixYkUx3TJhxwEDmSPgGgz42g
# L7lBqQjc+3RiExDcq8QzMZdqM1EjIz8RjGGxvsrph2p6AlHeoNHkQ2zmC/cU9G5B
# WVJuc/yVqtjxLhQLyh9smJQ/eDJTEbEfXj4NfKSd0SmD7v0uRtLrZ8wVxCSvKXO7
# gXKs8j0hpIagFDQ8fmkh1ZxvCImlL2tvL4C9nu1s6oV+LkTuZVMpejCEv0Jd1+CL
# jHeqbc/JDfbW97Kae71W7tIeOO50Z1pQ8cBE6PL7ylJAmP3JfUX9Afu5SMMch4kd
# 0ffRDEMVmsMwXPjlSaiSV/zERiz19GNi4vKWF3wqPIwzLLYdJiBRZnVyzrkeeoDj
# 9BupgFhFEYhz+zRA85KyC/2SHWDRmNx2B2+W9JiDPlBimcRZQBLwA0j7Mond0ntw
# ieOZmrF26DVPLverHnrTIK/B26h4xQbZOiWQhYGU/IpR/2bdg13i0fr2Yr509UYz
# Ur/xi5zUXGyhnknF6bf0yY77UNlFyzfDwAJHgHku2K7EeLhAee24MjfruvTYiY9t
# iF2z873G793BdV6qzOdIi/uJs6hea3eLwJdohvbekpdWCFR08f0+NWfUne7adcSb
# eEo7hXw4/KIMB2MSKb7fvB7XV1XoWIK0caX4wdLwS4s9o564
# SIG # End signature block
