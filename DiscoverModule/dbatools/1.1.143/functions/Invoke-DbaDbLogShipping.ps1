function Invoke-DbaDbLogShipping {
    <#
    .SYNOPSIS
        Invoke-DbaDbLogShipping sets up log shipping for one or more databases

    .DESCRIPTION
        Invoke-DbaDbLogShipping helps to easily set up log shipping for one or more databases.

        This function will make a lot of decisions for you assuming you want default values like a daily interval for the schedules with a 15 minute interval on the day.
        There are some settings that cannot be made by the function and they need to be prepared before the function is executed.

        The following settings need to be made before log shipping can be initiated:
        - Backup destination (the folder and the privileges)
        - Copy destination (the folder and the privileges)

        * Privileges
        Make sure your agent service on both the primary and the secondary instance is an Active Directory account.
        Also have the credentials ready to set the folder permissions

        ** Network share
        The backup destination needs to be shared and have the share privileges of FULL CONTROL to Everyone.

        ** NTFS permissions
        The backup destination must have at least read/write permissions for the primary instance agent account.
        The backup destination must have at least read permissions for the secondary instance agent account.
        The copy destination must have at least read/write permission for the secondary instance agent account.

    .PARAMETER SourceSqlInstance
        Source SQL Server instance which contains the databases to be log shipped.
        You must have sysadmin access and server version must be SQL Server version 2000 or greater.

    .PARAMETER DestinationSqlInstance
        Destination SQL Server instance which contains the databases to be log shipped.
        You must have sysadmin access and server version must be SQL Server version 2000 or greater.

    .PARAMETER SourceSqlCredential
        Login to the target instance using alternative credentials. Accepts PowerShell credentials (Get-Credential).

        Windows Authentication, SQL Server Authentication, Active Directory - Password, and Active Directory - Integrated are all supported.

        For MFA support, please use Connect-DbaInstance.

    .PARAMETER SourceCredential
        Login to the target instance using alternative credentials. Accepts PowerShell credentials (Get-Credential).

        Windows Authentication, SQL Server Authentication, Active Directory - Password, and Active Directory - Integrated are all supported.

        For MFA support, please use Connect-DbaInstance.

    .PARAMETER DestinationSqlCredential
        Login to the target instance using alternative credentials. Accepts PowerShell credentials (Get-Credential).

        Windows Authentication, SQL Server Authentication, Active Directory - Password, and Active Directory - Integrated are all supported.

        For MFA support, please use Connect-DbaInstance.

    .PARAMETER DestinationCredential
        Login to the target instance using alternative credentials. Accepts PowerShell credentials (Get-Credential).

        Windows Authentication, SQL Server Authentication, Active Directory - Password, and Active Directory - Integrated are all supported.

        For MFA support, please use Connect-DbaInstance.

    .PARAMETER Database
        Database to set up log shipping for.

    .PARAMETER SharedPath
        The backup unc path to place the backup files. This is the root directory.
        A directory with the name of the database will be created in this path.

    .PARAMETER LocalPath
        If the backup path is locally for the source server you can also set this value.

    .PARAMETER BackupJob
        Name of the backup that will be created in the SQL Server agent.
        The parameter works as a prefix where the name of the database will be added to the backup job name.
        The default is "LSBackup_[databasename]"

    .PARAMETER BackupRetention
        The backup retention period in minutes. Default is 4320 / 72 hours

    .PARAMETER BackupSchedule
        Name of the backup schedule created for the backup job.
        The parameter works as a prefix where the name of the database will be added to the backup job schedule name.
        Default is "LSBackupSchedule_[databasename]"

    .PARAMETER BackupScheduleDisabled
        Parameter to set the backup schedule to disabled upon creation.
        By default the schedule is enabled.

    .PARAMETER BackupScheduleFrequencyType
        A value indicating when a job is to be executed.
        Allowed values are "Daily", "AgentStart", "IdleComputer"

    .PARAMETER BackupScheduleFrequencyInterval
        The number of type periods to occur between each execution of the backup job.

    .PARAMETER BackupScheduleFrequencySubdayType
        Specifies the units for the sub-day FrequencyInterval.
        Allowed values are "Time", "Seconds", "Minutes", "Hours"

    .PARAMETER BackupScheduleFrequencySubdayInterval
        The number of sub-day type periods to occur between each execution of the backup job.

    .PARAMETER BackupScheduleFrequencyRelativeInterval
        A job's occurrence of FrequencyInterval in each month, if FrequencyInterval is 32 (monthlyrelative).

    .PARAMETER BackupScheduleFrequencyRecurrenceFactor
        The number of weeks or months between the scheduled execution of a job. FrequencyRecurrenceFactor is used only if FrequencyType is 8, "Weekly", 16, "Monthly", 32 or "MonthlyRelative".

    .PARAMETER BackupScheduleStartDate
        The date on which execution of a job can begin.

    .PARAMETER BackupScheduleEndDate
        The date on which execution of a job can stop.

    .PARAMETER BackupScheduleStartTime
        The time on any day to begin execution of a job. Format HHMMSS / 24 hour clock.
        Example: '010000' for 01:00:00 AM.
        Example: '140000' for 02:00:00 PM.

    .PARAMETER BackupScheduleEndTime
        The time on any day to end execution of a job. Format HHMMSS / 24 hour clock.
        Example: '010000' for 01:00:00 AM.
        Example: '140000' for 02:00:00 PM.

    .PARAMETER BackupThreshold
        Is the length of time, in minutes, after the last backup before a threshold alert error is raised.
        The default is 60.

    .PARAMETER CompressBackup
        Do the backups need to be compressed. By default the backups are not compressed.

    .PARAMETER CopyDestinationFolder
        The path to copy the transaction log backup files to. This is the root directory.
        A directory with the name of the database will be created in this path.

    .PARAMETER CopyJob
        Name of the copy job that will be created in the SQL Server agent.
        The parameter works as a prefix where the name of the database will be added to the copy job name.
        The default is "LSBackup_[databasename]"

    .PARAMETER CopyRetention
        The copy retention period in minutes. Default is 4320 / 72 hours

    .PARAMETER CopySchedule
        Name of the backup schedule created for the copy job.
        The parameter works as a prefix where the name of the database will be added to the copy job schedule name.
        Default is "LSCopy_[DestinationServerName]_[DatabaseName]"

    .PARAMETER CopyScheduleDisabled
        Parameter to set the copy schedule to disabled upon creation.
        By default the schedule is enabled.

    .PARAMETER CopyScheduleFrequencyType
        A value indicating when a job is to be executed.
        Allowed values are "Daily", "AgentStart", "IdleComputer"

    .PARAMETER CopyScheduleFrequencyInterval
        The number of type periods to occur between each execution of the copy job.

    .PARAMETER CopyScheduleFrequencySubdayType
        Specifies the units for the subday FrequencyInterval.
        Allowed values are "Time", "Seconds", "Minutes", "Hours"

    .PARAMETER CopyScheduleFrequencySubdayInterval
        The number of subday type periods to occur between each execution of the copy job.

    .PARAMETER CopyScheduleFrequencyRelativeInterval
        A job's occurrence of FrequencyInterval in each month, if FrequencyInterval is 32 (monthlyrelative).

    .PARAMETER CopyScheduleFrequencyRecurrenceFactor
        The number of weeks or months between the scheduled execution of a job. FrequencyRecurrenceFactor is used only if FrequencyType is 8, "Weekly", 16, "Monthly", 32 or "MonthlyRelative".

    .PARAMETER CopyScheduleStartDate
        The date on which execution of a job can begin.

    .PARAMETER CopyScheduleEndDate
        The date on which execution of a job can stop.

    .PARAMETER CopyScheduleStartTime
        The time on any day to begin execution of a job. Format HHMMSS / 24 hour clock.
        Example: '010000' for 01:00:00 AM.
        Example: '140000' for 02:00:00 PM.

    .PARAMETER CopyScheduleEndTime
        The time on any day to end execution of a job. Format HHMMSS / 24 hour clock.
        Example: '010000' for 01:00:00 AM.
        Example: '140000' for 02:00:00 PM.

    .PARAMETER DisconnectUsers
        If this parameter is set in combinations of standby the users will be disconnected during restore.

    .PARAMETER FullBackupPath
        Path to an existing full backup. Use this when an existing backup needs to used to initialize the database on the secondary instance.

    .PARAMETER GenerateFullBackup
        If the database is not initialized on the secondary instance it can be done by creating a new full backup and
        restore it for you.

    .PARAMETER HistoryRetention
        Is the length of time in minutes in which the history is retained.
        The default value is 14420

    .PARAMETER NoRecovery
        If this parameter is set the database will be in recovery mode. The database will not be readable.
        This setting is default.

    .PARAMETER NoInitialization
        If this parameter is set the secondary database will not be initialized.
        The database needs to be on the secondary instance in recovery mode.

    .PARAMETER PrimaryMonitorServer
        Is the name of the monitor server for the primary server.
        The default is the name of the primary sql server.

    .PARAMETER PrimaryMonitorCredential
        Allows you to login to enter a secure credential. Only needs to be used when the PrimaryMonitorServerSecurityMode is 0 or "sqlserver"
        To use: $scred = Get-Credential, then pass $scred object to the -PrimaryMonitorCredential parameter.

    .PARAMETER PrimaryMonitorServerSecurityMode
        The security mode used to connect to the monitor server for the primary server. Allowed values are 0, "sqlserver", 1, "windows"
        The default is 1 or Windows.

    .PARAMETER PrimaryThresholdAlertEnabled
        Enables the Threshold alert for the primary database

    .PARAMETER RestoreDataFolder
        Folder to be used to restore the database data files. Only used when parameter GenerateFullBackup or UseExistingFullBackup are set.
        If the parameter is not set the default data folder of the secondary instance will be used.
        If the folder is set but doesn't exist we will try to create the folder.

    .PARAMETER RestoreLogFolder
        Folder to be used to restore the database log files. Only used when parameter GenerateFullBackup or UseExistingFullBackup are set.
        If the parameter is not set the default transaction log folder of the secondary instance will be used.
        If the folder is set but doesn't exist we will try to create the folder.

    .PARAMETER RestoreDelay
        In case a delay needs to be set for the restore.
        The default is 0.

    .PARAMETER RestoreAlertThreshold
        The amount of minutes after which an alert will be raised is no restore has taken place.
        The default is 45 minutes.

    .PARAMETER RestoreJob
        Name of the restore job that will be created in the SQL Server agent.
        The parameter works as a prefix where the name of the database will be added to the restore job name.
        The default is "LSRestore_[databasename]"

    .PARAMETER RestoreRetention
        The backup retention period in minutes. Default is 4320 / 72 hours

    .PARAMETER RestoreSchedule
        Name of the backup schedule created for the restore job.
        The parameter works as a prefix where the name of the database will be added to the restore job schedule name.
        Default is "LSRestore_[DestinationServerName]_[DatabaseName]"

    .PARAMETER RestoreScheduleDisabled
        Parameter to set the restore schedule to disabled upon creation.
        By default the schedule is enabled.

    .PARAMETER RestoreScheduleFrequencyType
        A value indicating when a job is to be executed.
        Allowed values are "Daily", "AgentStart", "IdleComputer"

    .PARAMETER RestoreScheduleFrequencyInterval
        The number of type periods to occur between each execution of the restore job.

    .PARAMETER RestoreScheduleFrequencySubdayType
        Specifies the units for the subday FrequencyInterval.
        Allowed values are "Time", "Seconds", "Minutes", "Hours"

    .PARAMETER RestoreScheduleFrequencySubdayInterval
        The number of subday type periods to occur between each execution of the restore job.

    .PARAMETER RestoreScheduleFrequencyRelativeInterval
        A job's occurrence of FrequencyInterval in each month, if FrequencyInterval is 32 (monthlyrelative).

    .PARAMETER RestoreScheduleFrequencyRecurrenceFactor
        The number of weeks or months between the scheduled execution of a job. FrequencyRecurrenceFactor is used only if FrequencyType is 8, "Weekly", 16, "Monthly", 32 or "MonthlyRelative".

    .PARAMETER RestoreScheduleStartDate
        The date on which execution of a job can begin.

    .PARAMETER RestoreScheduleEndDate
        The date on which execution of a job can stop.

    .PARAMETER RestoreScheduleStartTime
        The time on any day to begin execution of a job. Format HHMMSS / 24 hour clock.
        Example: '010000' for 01:00:00 AM.
        Example: '140000' for 02:00:00 PM.

    .PARAMETER RestoreScheduleEndTime
        The time on any day to end execution of a job. Format HHMMSS / 24 hour clock.
        Example: '010000' for 01:00:00 AM.
        Example: '140000' for 02:00:00 PM.

    .PARAMETER RestoreThreshold
        The number of minutes allowed to elapse between restore operations before an alert is generated.
        The default value = 45

    .PARAMETER SecondaryDatabasePrefix
        The secondary database can be renamed to include a prefix.

    .PARAMETER SecondaryDatabaseSuffix
        The secondary database can be renamed to include a suffix.

    .PARAMETER SecondaryMonitorServer
        Is the name of the monitor server for the secondary server.
        The default is the name of the secondary sql server.

    .PARAMETER SecondaryMonitorCredential
        Allows you to login to enter a secure credential. Only needs to be used when the SecondaryMonitorServerSecurityMode is 0 or "sqlserver"
        To use: $scred = Get-Credential, then pass $scred object to the -SecondaryMonitorCredential parameter.

    .PARAMETER SecondaryMonitorServerSecurityMode
        The security mode used to connect to the monitor server for the secondary server. Allowed values are 0, "sqlserver", 1, "windows"
        The default is 1 or Windows.

    .PARAMETER SecondaryThresholdAlertEnabled
        Enables the Threshold alert for the secondary database

    .PARAMETER Standby
        If this parameter is set the database will be set to standby mode making the database readable.
        If not set the database will be in recovery mode.

    .PARAMETER StandbyDirectory
        Directory to place the standby file(s) in

    .PARAMETER UseExistingFullBackup
        If the database is not initialized on the secondary instance it can be done by selecting an existing full backup
        and restore it for you.

    .PARAMETER UseBackupFolder
        This enables the user to specify a specific backup folder containing one or more backup files to initialize the database on the secondary instance.

    .PARAMETER WhatIf
        Shows what would happen if the command were to run. No actions are actually performed.

    .PARAMETER Confirm
        Prompts you for confirmation before executing any changing operations within the command.

    .PARAMETER EnableException
        Use this switch to disable any kind of verbose messages

    .PARAMETER Force
        The force parameter will ignore some errors in the parameters and assume defaults.
        It will also remove the any present schedules with the same name for the specific job.

    .NOTES
        Tags: LogShipping
        Author: Sander Stad (@sqlstad), sqlstad.nl

        Website: https://dbatools.io
        Copyright: (c) 2018 by dbatools, licensed under MIT
        License: MIT https://opensource.org/licenses/MIT

    .LINK
        https://dbatools.io/Invoke-DbaDbLogShipping

    .EXAMPLE
        PS C:\> $params = @{
        >> SourceSqlInstance = 'sql1'
        >> DestinationSqlInstance = 'sql2'
        >> Database = 'db1'
        >> SharedPath= '\\sql1\logshipping'
        >> LocalPath= 'D:\Data\logshipping'
        >> BackupScheduleFrequencyType = 'daily'
        >> BackupScheduleFrequencyInterval = 1
        >> CompressBackup = $true
        >> CopyScheduleFrequencyType = 'daily'
        >> CopyScheduleFrequencyInterval = 1
        >> GenerateFullBackup = $true
        >> RestoreScheduleFrequencyType = 'daily'
        >> RestoreScheduleFrequencyInterval = 1
        >> SecondaryDatabaseSuffix = 'LS'
        >> CopyDestinationFolder = '\\sql2\logshippingdest'
        >> Force = $true
        >> }
        >>
        PS C:\> Invoke-DbaDbLogShipping @params

        Sets up log shipping for database "db1" with the backup path to a network share allowing local backups.
        It creates daily schedules for the backup, copy and restore job with all the defaults to be executed every 15 minutes daily.
        The secondary database will be called "db1_LS".

    .EXAMPLE
        PS C:\> $params = @{
        >> SourceSqlInstance = 'sql1'
        >> DestinationSqlInstance = 'sql2'
        >> Database = 'db1'
        >> SharedPath= '\\sql1\logshipping'
        >> GenerateFullBackup = $true
        >> Force = $true
        >> }
        >>
        PS C:\> Invoke-DbaDbLogShipping @params

        Sets up log shipping with all defaults except that a backup file is generated.
        The script will show a message that the copy destination has not been supplied and asks if you want to use the default which would be the backup directory of the secondary server with the folder "logshipping" i.e. "D:\SQLBackup\Logshiping".

    #>
    [CmdletBinding(DefaultParameterSetName = "Default", SupportsShouldProcess, ConfirmImpact = "Medium")]

    param(
        [parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [Alias("SourceServerInstance", "SourceSqlServerSqlServer", "Source")]
        [DbaInstanceParameter]$SourceSqlInstance,
        [parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [Alias("DestinationServerInstance", "DestinationSqlServer", "Destination")]
        [DbaInstanceParameter[]]$DestinationSqlInstance,
        [System.Management.Automation.PSCredential]
        $SourceSqlCredential,
        [System.Management.Automation.PSCredential]
        $SourceCredential,
        [System.Management.Automation.PSCredential]
        $DestinationSqlCredential,
        [System.Management.Automation.PSCredential]
        $DestinationCredential,
        [Parameter(Mandatory, ValueFromPipeline)]
        [object[]]$Database,
        [parameter(Mandatory)]
        [Alias("BackupNetworkPath")]
        [string]$SharedPath,
        [Alias("BackupLocalPath")]
        [string]$LocalPath,
        [string]$BackupJob,
        [int]$BackupRetention,
        [string]$BackupSchedule,
        [switch]$BackupScheduleDisabled,
        [ValidateSet("Daily", "Weekly", "AgentStart", "IdleComputer")]
        [object]$BackupScheduleFrequencyType,
        [object[]]$BackupScheduleFrequencyInterval,
        [ValidateSet('Time', 'Seconds', 'Minutes', 'Hours')]
        [object]$BackupScheduleFrequencySubdayType,
        [int]$BackupScheduleFrequencySubdayInterval,
        [ValidateSet('Unused', 'First', 'Second', 'Third', 'Fourth', 'Last')]
        [object]$BackupScheduleFrequencyRelativeInterval,
        [int]$BackupScheduleFrequencyRecurrenceFactor,
        [string]$BackupScheduleStartDate,
        [string]$BackupScheduleEndDate,
        [string]$BackupScheduleStartTime,
        [string]$BackupScheduleEndTime,
        [int]$BackupThreshold,
        [switch]$CompressBackup,
        [string]$CopyDestinationFolder,
        [string]$CopyJob,
        [int]$CopyRetention,
        [string]$CopySchedule,
        [switch]$CopyScheduleDisabled,
        [ValidateSet("Daily", "Weekly", "AgentStart", "IdleComputer")]
        [object]$CopyScheduleFrequencyType,
        [object[]]$CopyScheduleFrequencyInterval,
        [ValidateSet('Time', 'Seconds', 'Minutes', 'Hours')]
        [object]$CopyScheduleFrequencySubdayType,
        [int]$CopyScheduleFrequencySubdayInterval,
        [ValidateSet('Unused', 'First', 'Second', 'Third', 'Fourth', 'Last')]
        [object]$CopyScheduleFrequencyRelativeInterval,
        [int]$CopyScheduleFrequencyRecurrenceFactor,
        [string]$CopyScheduleStartDate,
        [string]$CopyScheduleEndDate,
        [string]$CopyScheduleStartTime,
        [string]$CopyScheduleEndTime,
        [switch]$DisconnectUsers,
        [string]$FullBackupPath,
        [switch]$GenerateFullBackup,
        [int]$HistoryRetention,
        [switch]$NoRecovery,
        [switch]$NoInitialization,
        [string]$PrimaryMonitorServer,
        [System.Management.Automation.PSCredential]
        $PrimaryMonitorCredential,
        [ValidateSet(0, "sqlserver", 1, "windows")]
        [object]$PrimaryMonitorServerSecurityMode,
        [switch]$PrimaryThresholdAlertEnabled,
        [string]$RestoreDataFolder,
        [string]$RestoreLogFolder,
        [int]$RestoreDelay,
        [int]$RestoreAlertThreshold,
        [string]$RestoreJob,
        [int]$RestoreRetention,
        [string]$RestoreSchedule,
        [switch]$RestoreScheduleDisabled,
        [ValidateSet("Daily", "Weekly", "AgentStart", "IdleComputer")]
        [object]$RestoreScheduleFrequencyType,
        [object[]]$RestoreScheduleFrequencyInterval,
        [ValidateSet('Time', 'Seconds', 'Minutes', 'Hours')]
        [object]$RestoreScheduleFrequencySubdayType,
        [int]$RestoreScheduleFrequencySubdayInterval,
        [ValidateSet('Unused', 'First', 'Second', 'Third', 'Fourth', 'Last')]
        [object]$RestoreScheduleFrequencyRelativeInterval,
        [int]$RestoreScheduleFrequencyRecurrenceFactor,
        [string]$RestoreScheduleStartDate,
        [string]$RestoreScheduleEndDate,
        [string]$RestoreScheduleStartTime,
        [string]$RestoreScheduleEndTime,
        [int]$RestoreThreshold,
        [string]$SecondaryDatabasePrefix,
        [string]$SecondaryDatabaseSuffix,
        [string]$SecondaryMonitorServer,
        [System.Management.Automation.PSCredential]
        $SecondaryMonitorCredential,
        [ValidateSet(0, "sqlserver", 1, "windows")]
        [object]$SecondaryMonitorServerSecurityMode,
        [switch]$SecondaryThresholdAlertEnabled,
        [switch]$Standby,
        [string]$StandbyDirectory,
        [switch]$UseExistingFullBackup,
        [string]$UseBackupFolder,
        [switch]$Force,
        [switch]$EnableException
    )

    begin {
        if ($Force) { $ConfirmPreference = 'none' }

        Write-Message -Message "Started log shipping for $SourceSqlInstance to $DestinationSqlInstance" -Level Verbose

        # Try connecting to the instance
        try {
            $sourceServer = Connect-DbaInstance -SqlInstance $SourceSqlInstance -SqlCredential $SourceSqlCredential
        } catch {
            Stop-Function -Message "Failure" -Category ConnectionError -ErrorRecord $_ -Target $SourceSqlInstance
            return
        }


        # Check the instance if it is a named instance
        $SourceServerName, $SourceInstanceName = $SourceSqlInstance.FullName.Split("\")

        if ($null -eq $SourceInstanceName) {
            $SourceInstanceName = "MSSQLSERVER"
        }

        # Set up regex strings for several checks
        $RegexDate = '(?<!\d)(?:(?:(?:1[6-9]|[2-9]\d)?\d{2})(?:(?:(?:0[13578]|1[02])31)|(?:(?:0[1,3-9]|1[0-2])(?:29|30)))|(?:(?:(?:(?:1[6-9]|[2-9]\d)?(?:0[48]|[2468][048]|[13579][26])|(?:(?:16|[2468][048]|[3579][26])00)))0229)|(?:(?:1[6-9]|[2-9]\d)?\d{2})(?:(?:0?[1-9])|(?:1[0-2]))(?:0?[1-9]|1\d|2[0-8]))(?!\d)'
        $RegexTime = '^(?:(?:([01]?\d|2[0-3]))?([0-5]?\d))?([0-5]?\d)$'
        $RegexUnc = '^\\(?:\\[^<>:`"/\\|?*]+)+$'


        # Check the connection timeout
        if ($SourceServer.ConnectionContext.StatementTimeout -ne 0) {
            $SourceServer.ConnectionContext.StatementTimeout = 0
            Write-Message -Message "Connection timeout of $SourceServer is set to 0" -Level Verbose
        }

        # Check the backup network path
        Write-Message -Message "Testing backup network path $SharedPath" -Level Verbose
        if ((Test-DbaPath -Path $SharedPath -SqlInstance $SourceSqlInstance -SqlCredential $SourceCredential) -ne $true) {
            Stop-Function -Message "Backup network path $SharedPath is not valid or can't be reached." -Target $SourceSqlInstance
            return
        } elseif ($SharedPath -notmatch $RegexUnc) {
            Stop-Function -Message "Backup network path $SharedPath has to be in the form of \\server\share." -Target $SourceSqlInstance
            return
        }

        # Check the backup compression
        if ($SourceServer.Version.Major -gt 9) {
            if ($CompressBackup) {
                Write-Message -Message "Setting backup compression to 1." -Level Verbose
                [bool]$BackupCompression = 1
            } else {
                $backupServerSetting = (Get-DbaSpConfigure -SqlInstance $SourceSqlInstance -ConfigName DefaultBackupCompression).ConfiguredValue
                Write-Message -Message "Setting backup compression to default server setting $backupServerSetting." -Level Verbose
                [bool]$BackupCompression = $backupServerSetting
            }
        } else {
            Write-Message -Message "Source server $SourceServer does not support backup compression" -Level Verbose
        }

        # Check the database parameter
        if ($Database) {
            foreach ($db in $Database) {
                if ($db -notin $SourceServer.Databases.Name) {
                    Stop-Function -Message "Database $db cannot be found on instance $SourceSqlInstance" -Target $SourceSqlInstance
                }

                $DatabaseCollection = $SourceServer.Databases | Where-Object { $_.Name -in $Database }
            }
        } else {
            Stop-Function -Message "Please supply a database to set up log shipping for" -Target $SourceSqlInstance -Continue
        }

        # Set the database mode
        if ($Standby) {
            $DatabaseStatus = 1
            Write-Message -Message "Destination database status set to STANDBY" -Level Verbose
        } else {
            $DatabaseStatus = 0
            Write-Message -Message "Destination database status set to NO RECOVERY" -Level Verbose
        }

        # Setting defaults
        if (-not $BackupRetention) {
            $BackupRetention = 4320
            Write-Message -Message "Backup retention set to $BackupRetention" -Level Verbose
        }
        if (-not $BackupThreshold) {
            $BackupThreshold = 60
            Write-Message -Message "Backup Threshold set to $BackupThreshold" -Level Verbose
        }
        if (-not $CopyRetention) {
            $CopyRetention = 4320
            Write-Message -Message "Copy retention set to $CopyRetention" -Level Verbose
        }
        if (-not $HistoryRetention) {
            $HistoryRetention = 14420
            Write-Message -Message "History retention set to $HistoryRetention" -Level Verbose
        }
        if (-not $RestoreAlertThreshold) {
            $RestoreAlertThreshold = 45
            Write-Message -Message "Restore alert Threshold set to $RestoreAlertThreshold" -Level Verbose
        }
        if (-not $RestoreDelay) {
            $RestoreDelay = 0
            Write-Message -Message "Restore delay set to $RestoreDelay" -Level Verbose
        }
        if (-not $RestoreRetention) {
            $RestoreRetention = 4320
            Write-Message -Message "Restore retention set to $RestoreRetention" -Level Verbose
        }
        if (-not $RestoreThreshold) {
            $RestoreThreshold = 45
            Write-Message -Message "Restore Threshold set to $RestoreThreshold" -Level Verbose
        }
        if (-not $PrimaryMonitorServerSecurityMode) {
            $PrimaryMonitorServerSecurityMode = 1
            Write-Message -Message "Primary monitor server security mode set to $PrimaryMonitorServerSecurityMode" -Level Verbose
        }
        if (-not $SecondaryMonitorServerSecurityMode) {
            $SecondaryMonitorServerSecurityMode = 1
            Write-Message -Message "Secondary monitor server security mode set to $SecondaryMonitorServerSecurityMode" -Level Verbose
        }
        if (-not $BackupScheduleFrequencyType) {
            $BackupScheduleFrequencyType = "Daily"
            Write-Message -Message "Backup frequency type set to $BackupScheduleFrequencyType" -Level Verbose
        }
        if (-not $BackupScheduleFrequencyInterval) {
            $BackupScheduleFrequencyInterval = "EveryDay"
            Write-Message -Message "Backup frequency interval set to $BackupScheduleFrequencyInterval" -Level Verbose
        }
        if (-not $BackupScheduleFrequencySubdayType) {
            $BackupScheduleFrequencySubdayType = "Minutes"
            Write-Message -Message "Backup frequency subday type set to $BackupScheduleFrequencySubdayType" -Level Verbose
        }
        if (-not $BackupScheduleFrequencySubdayInterval) {
            $BackupScheduleFrequencySubdayInterval = 15
            Write-Message -Message "Backup frequency subday interval set to $BackupScheduleFrequencySubdayInterval" -Level Verbose
        }
        if (-not $BackupScheduleFrequencyRelativeInterval) {
            $BackupScheduleFrequencyRelativeInterval = "Unused"
            Write-Message -Message "Backup frequency relative interval set to $BackupScheduleFrequencyRelativeInterval" -Level Verbose
        }
        if (-not $BackupScheduleFrequencyRecurrenceFactor) {
            $BackupScheduleFrequencyRecurrenceFactor = 0
            Write-Message -Message "Backup frequency recurrence factor set to $BackupScheduleFrequencyRecurrenceFactor" -Level Verbose
        }
        if (-not $CopyScheduleFrequencyType) {
            $CopyScheduleFrequencyType = "Daily"
            Write-Message -Message "Copy frequency type set to $CopyScheduleFrequencyType" -Level Verbose
        }
        if (-not $CopyScheduleFrequencyInterval) {
            $CopyScheduleFrequencyInterval = "EveryDay"
            Write-Message -Message "Copy frequency interval set to $CopyScheduleFrequencyInterval" -Level Verbose
        }
        if (-not $CopyScheduleFrequencySubdayType) {
            $CopyScheduleFrequencySubdayType = "Minutes"
            Write-Message -Message "Copy frequency subday type set to $CopyScheduleFrequencySubdayType" -Level Verbose
        }
        if (-not $CopyScheduleFrequencySubdayInterval) {
            $CopyScheduleFrequencySubdayInterval = 15
            Write-Message -Message "Copy frequency subday interval set to $CopyScheduleFrequencySubdayInterval" -Level Verbose
        }
        if (-not $CopyScheduleFrequencyRelativeInterval) {
            $CopyScheduleFrequencyRelativeInterval = "Unused"
            Write-Message -Message "Copy frequency relative interval set to $CopyScheduleFrequencyRelativeInterval" -Level Verbose
        }
        if (-not $CopyScheduleFrequencyRecurrenceFactor) {
            $CopyScheduleFrequencyRecurrenceFactor = 0
            Write-Message -Message "Copy frequency recurrence factor set to $CopyScheduleFrequencyRecurrenceFactor" -Level Verbose
        }
        if (-not $RestoreScheduleFrequencyType) {
            $RestoreScheduleFrequencyType = "Daily"
            Write-Message -Message "Restore frequency type set to $RestoreScheduleFrequencyType" -Level Verbose
        }
        if (-not $RestoreScheduleFrequencyInterval) {
            $RestoreScheduleFrequencyInterval = "EveryDay"
            Write-Message -Message "Restore frequency interval set to $RestoreScheduleFrequencyInterval" -Level Verbose
        }
        if (-not $RestoreScheduleFrequencySubdayType) {
            $RestoreScheduleFrequencySubdayType = "Minutes"
            Write-Message -Message "Restore frequency subday type set to $RestoreScheduleFrequencySubdayType" -Level Verbose
        }
        if (-not $RestoreScheduleFrequencySubdayInterval) {
            $RestoreScheduleFrequencySubdayInterval = 15
            Write-Message -Message "Restore frequency subday interval set to $RestoreScheduleFrequencySubdayInterval" -Level Verbose
        }
        if (-not $RestoreScheduleFrequencyRelativeInterval) {
            $RestoreScheduleFrequencyRelativeInterval = "Unused"
            Write-Message -Message "Restore frequency relative interval set to $RestoreScheduleFrequencyRelativeInterval" -Level Verbose
        }
        if (-not $RestoreScheduleFrequencyRecurrenceFactor) {
            $RestoreScheduleFrequencyRecurrenceFactor = 0
            Write-Message -Message "Restore frequency recurrence factor set to $RestoreScheduleFrequencyRecurrenceFactor" -Level Verbose
        }

        # Checking for contradicting variables
        if ($NoInitialization -and ($GenerateFullBackup -or $UseExistingFullBackup)) {
            Stop-Function -Message "Cannot use -NoInitialization with -GenerateFullBackup or -UseExistingFullBackup" -Target $DestinationSqlInstance
            return
        }

        if ($UseBackupFolder -and ($GenerateFullBackup -or $NoInitialization -or $UseExistingFullBackup)) {
            Stop-Function -Message "Cannot use -UseBackupFolder with -GenerateFullBackup, -NoInitialization or -UseExistingFullBackup" -Target $DestinationSqlInstance
            return
        }

        # Check the subday interval
        if (($BackupScheduleFrequencySubdayType -in 2, "Seconds", 4, "Minutes") -and (-not ($BackupScheduleFrequencySubdayInterval -ge 1 -or $BackupScheduleFrequencySubdayInterval -le 59))) {
            Stop-Function -Message "Backup subday interval $BackupScheduleFrequencySubdayInterval must be between 1 and 59 when subday type is 2, 'Seconds', 4 or 'Minutes'" -Target $SourceSqlInstance
            return
        } elseif (($BackupScheduleFrequencySubdayType -in 8, "Hours") -and (-not ($BackupScheduleFrequencySubdayInterval -ge 1 -and $BackupScheduleFrequencySubdayInterval -le 23))) {
            Stop-Function -Message "Backup Subday interval $BackupScheduleFrequencySubdayInterval must be between 1 and 23 when subday type is 8 or 'Hours" -Target $SourceSqlInstance
            return
        }

        # Check the subday interval
        if (($CopyScheduleFrequencySubdayType -in 2, "Seconds", 4, "Minutes") -and (-not ($CopyScheduleFrequencySubdayInterval -ge 1 -or $CopyScheduleFrequencySubdayInterval -le 59))) {
            Stop-Function -Message "Copy subday interval $CopyScheduleFrequencySubdayInterval must be between 1 and 59 when subday type is 2, 'Seconds', 4 or 'Minutes'" -Target $DestinationSqlInstance
            return
        } elseif (($CopyScheduleFrequencySubdayType -in 8, "Hours") -and (-not ($CopyScheduleFrequencySubdayInterval -ge 1 -and $CopyScheduleFrequencySubdayInterval -le 23))) {
            Stop-Function -Message "Copy subday interval $CopyScheduleFrequencySubdayInterval must be between 1 and 23 when subday type is 8 or 'Hours'" -Target $DestinationSqlInstance
            return
        }

        # Check the subday interval
        if (($RestoreScheduleFrequencySubdayType -in 2, "Seconds", 4, "Minutes") -and (-not ($RestoreScheduleFrequencySubdayInterval -ge 1 -or $RestoreScheduleFrequencySubdayInterval -le 59))) {
            Stop-Function -Message "Restore subday interval $RestoreScheduleFrequencySubdayInterval must be between 1 and 59 when subday type is 2, 'Seconds', 4 or 'Minutes'" -Target $DestinationSqlInstance
            return
        } elseif (($RestoreScheduleFrequencySubdayType -in 8, "Hours") -and (-not ($RestoreScheduleFrequencySubdayInterval -ge 1 -and $RestoreScheduleFrequencySubdayInterval -le 23))) {
            Stop-Function -Message "Restore subday interval $RestoreScheduleFrequencySubdayInterval must be between 1 and 23 when subday type is 8 or 'Hours" -Target $DestinationSqlInstance
            return
        }

        # Check the backup start date
        if (-not $BackupScheduleStartDate) {
            $BackupScheduleStartDate = (Get-Date -format "yyyyMMdd")
            Write-Message -Message "Backup start date set to $BackupScheduleStartDate" -Level Verbose
        } else {
            if ($BackupScheduleStartDate -notmatch $RegexDate) {
                Stop-Function -Message "Backup start date $BackupScheduleStartDate needs to be a valid date with format yyyyMMdd" -Target $SourceSqlInstance
                return
            }
        }

        # Check the back start time
        if (-not $BackupScheduleStartTime) {
            $BackupScheduleStartTime = '000000'
            Write-Message -Message "Backup start time set to $BackupScheduleStartTime" -Level Verbose
        } elseif ($BackupScheduleStartTime -notmatch $RegexTime) {
            Stop-Function -Message  "Backup start time $BackupScheduleStartTime needs to match between '000000' and '235959'" -Target $SourceSqlInstance
            return
        }

        # Check the back end time
        if (-not $BackupScheduleEndTime) {
            $BackupScheduleEndTime = '235959'
            Write-Message -Message "Backup end time set to $BackupScheduleEndTime" -Level Verbose
        } elseif ($BackupScheduleStartTime -notmatch $RegexTime) {
            Stop-Function -Message  "Backup end time $BackupScheduleStartTime needs to match between '000000' and '235959'" -Target $SourceSqlInstance
            return
        }

        # Check the backup end date
        if (-not $BackupScheduleEndDate) {
            $BackupScheduleEndDate = '99991231'
        } elseif ($BackupScheduleEndDate -notmatch $RegexDate) {
            Stop-Function -Message "Backup end date $BackupScheduleEndDate needs to be a valid date with format yyyyMMdd" -Target $SourceSqlInstance
            return
        }

        # Check the copy start date
        if (-not $CopyScheduleStartDate) {
            $CopyScheduleStartDate = (Get-Date -format "yyyyMMdd")
            Write-Message -Message "Copy start date set to $CopyScheduleStartDate" -Level Verbose
        } else {
            if ($CopyScheduleStartDate -notmatch $RegexDate) {
                Stop-Function -Message "Copy start date $CopyScheduleStartDate needs to be a valid date with format yyyyMMdd" -Target $SourceSqlInstance
                return
            }
        }

        # Check the copy end date
        if (-not $CopyScheduleEndDate) {
            $CopyScheduleEndDate = '99991231'
        } elseif ($CopyScheduleEndDate -notmatch $RegexDate) {
            Stop-Function -Message "Copy end date $CopyScheduleEndDate needs to be a valid date with format yyyyMMdd" -Target $SourceSqlInstance
            return
        }

        # Check the copy start time
        if (-not $CopyScheduleStartTime) {
            $CopyScheduleStartTime = '000000'
            Write-Message -Message "Copy start time set to $CopyScheduleStartTime" -Level Verbose
        } elseif ($CopyScheduleStartTime -notmatch $RegexTime) {
            Stop-Function -Message  "Copy start time $CopyScheduleStartTime needs to match between '000000' and '235959'" -Target $SourceSqlInstance
            return
        }

        # Check the copy end time
        if (-not $CopyScheduleEndTime) {
            $CopyScheduleEndTime = '235959'
            Write-Message -Message "Copy end time set to $CopyScheduleEndTime" -Level Verbose
        } elseif ($CopyScheduleEndTime -notmatch $RegexTime) {
            Stop-Function -Message  "Copy end time $CopyScheduleEndTime needs to match between '000000' and '235959'" -Target $SourceSqlInstance
            return
        }

        # Check the restore start date
        if (-not $RestoreScheduleStartDate) {
            $RestoreScheduleStartDate = (Get-Date -format "yyyyMMdd")
            Write-Message -Message "Restore start date set to $RestoreScheduleStartDate" -Level Verbose
        } else {
            if ($RestoreScheduleStartDate -notmatch $RegexDate) {
                Stop-Function -Message "Restore start date $RestoreScheduleStartDate needs to be a valid date with format yyyyMMdd" -Target $SourceSqlInstance
                return
            }
        }

        # Check the restore end date
        if (-not $RestoreScheduleEndDate) {
            $RestoreScheduleEndDate = '99991231'
        } elseif ($RestoreScheduleEndDate -notmatch $RegexDate) {
            Stop-Function -Message "Restore end date $RestoreScheduleEndDate needs to be a valid date with format yyyyMMdd" -Target $SourceSqlInstance
            return
        }

        # Check the restore start time
        if (-not $RestoreScheduleStartTime) {
            $RestoreScheduleStartTime = '000000'
            Write-Message -Message "Restore start time set to $RestoreScheduleStartTime" -Level Verbose
        } elseif ($RestoreScheduleStartTime -notmatch $RegexTime) {
            Stop-Function -Message  "Restore start time $RestoreScheduleStartTime needs to match between '000000' and '235959'" -Target $SourceSqlInstance
            return
        }

        # Check the restore end time
        if (-not $RestoreScheduleEndTime) {
            $RestoreScheduleEndTime = '235959'
            Write-Message -Message "Restore end time set to $RestoreScheduleEndTime" -Level Verbose
        } elseif ($RestoreScheduleEndTime -notmatch $RegexTime) {
            Stop-Function -Message  "Restore end time $RestoreScheduleEndTime needs to match between '000000' and '235959'" -Target $SourceSqlInstance
            return
        }
    }

    process {

        if (Test-FunctionInterrupt) { return }

        foreach ($destInstance in $DestinationSqlInstance) {

            $setupResult = "Success"
            $comment = ""

            # Try connecting to the instance
            try {
                $destinationServer = Connect-DbaInstance -SqlInstance $destInstance -SqlCredential $DestinationSqlCredential
            } catch {
                Stop-Function -Message "Failure" -Category ConnectionError -ErrorRecord $_ -Target $destInstance -Continue
            }

            $DestinationServerName, $DestinationInstanceName = $destInstance.FullName.Split("\")

            if ($null -eq $DestinationInstanceName) {
                $DestinationInstanceName = "MSSQLSERVER"
            }

            $IsDestinationLocal = $false

            # Check if it's local or remote
            if ($DestinationServerName -in ".", "localhost", $env:ServerName, "127.0.0.1") {
                $IsDestinationLocal = $true
            }

            # Check the instance names and the database settings
            if (($SourceSqlInstance -eq $destInstance) -and (-not $SecondaryDatabasePrefix -or $SecondaryDatabaseSuffix)) {
                $setupResult = "Failed"
                $comment = "The destination database is the same as the source"
                Stop-Function -Message "The destination database is the same as the source`nPlease enter a prefix or suffix using -SecondaryDatabasePrefix or -SecondaryDatabaseSuffix." -Target $SourceSqlInstance
                return
            }

            if ($DestinationServer.ConnectionContext.StatementTimeout -ne 0) {
                $DestinationServer.ConnectionContext.StatementTimeout = 0
                Write-Message -Message "Connection timeout of $DestinationServer is set to 0" -Level Verbose
            }

            # Check the copy destination
            if (-not $CopyDestinationFolder) {
                # Make a default copy destination by retrieving the backup folder and adding a directory
                $CopyDestinationFolder = "$($DestinationServer.Settings.BackupDirectory)\Logshipping"

                # Check to see if the path already exists
                Write-Message -Message "Testing copy destination path $CopyDestinationFolder" -Level Verbose
                if (Test-DbaPath -Path $CopyDestinationFolder -SqlInstance $destInstance -SqlCredential $DestinationCredential) {
                    Write-Message -Message "Copy destination $CopyDestinationFolder already exists" -Level Verbose
                } else {
                    # Check if force is being used
                    if (-not $Force) {
                        # Set up the confirm part
                        $message = "The copy destination is missing. Do you want to use the default $($CopyDestinationFolder)?"
                        $choiceYes = New-Object System.Management.Automation.Host.ChoiceDescription "&Yes", "Answer Yes."
                        $choiceNo = New-Object System.Management.Automation.Host.ChoiceDescription "&No", "Answer No."
                        $options = [System.Management.Automation.Host.ChoiceDescription[]]($choiceYes, $choiceNo)
                        $result = $host.ui.PromptForChoice($title, $message, $options, 0)

                        # Check the result from the confirm
                        switch ($result) {
                            # If yes
                            0 {
                                # Try to create the new directory
                                try {
                                    # If the destination server is remote and the credential is set
                                    if (-not $IsDestinationLocal -and $DestinationCredential) {
                                        Invoke-Command2 -ComputerName $DestinationServerName -Credential $DestinationCredential -ScriptBlock {
                                            Write-Message -Message "Creating copy destination folder $CopyDestinationFolder" -Level Verbose
                                            New-Item -Path $CopyDestinationFolder -ItemType Directory -Credential $DestinationCredential -Force:$Force | Out-Null
                                        }
                                    }
                                    # If the server is local and the credential is set
                                    elseif ($DestinationCredential) {
                                        Invoke-Command2 -Credential $DestinationCredential -ScriptBlock {
                                            Write-Message -Message "Creating copy destination folder $CopyDestinationFolder" -Level Verbose
                                            New-Item -Path $CopyDestinationFolder -ItemType Directory -Credential $DestinationCredential -Force:$Force | Out-Null
                                        }
                                    }
                                    # If the server is local and the credential is not set
                                    else {
                                        Write-Message -Message "Creating copy destination folder $CopyDestinationFolder" -Level Verbose
                                        New-Item -Path $CopyDestinationFolder -Force:$Force -ItemType Directory | Out-Null
                                    }
                                    Write-Message -Message "Copy destination $CopyDestinationFolder created." -Level Verbose
                                } catch {
                                    $setupResult = "Failed"
                                    $comment = "Something went wrong creating the copy destination folder"
                                    Stop-Function -Message "Something went wrong creating the copy destination folder $CopyDestinationFolder. `n$_" -Target $destInstance -ErrorRecord $_
                                    return
                                }
                            }
                            1 {
                                $setupResult = "Failed"
                                $comment = "Copy destination is a mandatory parameter"
                                Stop-Function -Message "Copy destination is a mandatory parameter. Please make sure the value is entered." -Target $destInstance
                                return
                            }
                        } # switch
                    } # if not force
                    else {
                        # Try to create the copy destination on the local server
                        try {
                            Write-Message -Message "Creating copy destination folder $CopyDestinationFolder" -Level Verbose
                            New-Item $CopyDestinationFolder -ItemType Directory -Credential $DestinationCredential -Force:$Force | Out-Null
                            Write-Message -Message "Copy destination $CopyDestinationFolder created." -Level Verbose
                        } catch {
                            $setupResult = "Failed"
                            $comment = "Something went wrong creating the copy destination folder"
                            Stop-Function -Message "Something went wrong creating the copy destination folder $CopyDestinationFolder. `n$_" -Target $destInstance -ErrorRecord $_
                            return
                        }
                    } # else not force
                } # if test path copy destination
            } # if not copy destination

            Write-Message -Message "Testing copy destination path $CopyDestinationFolder" -Level Verbose
            if ((Test-DbaPath -Path $CopyDestinationFolder -SqlInstance $destInstance -SqlCredential $DestinationCredential) -ne $true) {
                $setupResult = "Failed"
                $comment = "Copy destination folder $CopyDestinationFolder is not valid or can't be reached"
                Stop-Function -Message "Copy destination folder $CopyDestinationFolder is not valid or can't be reached." -Target $destInstance
                return
            } elseif ($CopyDestinationFolder.StartsWith("\\") -and $CopyDestinationFolder -notmatch $RegexUnc) {
                $setupResult = "Failed"
                $comment = "Copy destination folder $CopyDestinationFolder has to be in the form of \\server\share"
                Stop-Function -Message "Copy destination folder $CopyDestinationFolder has to be in the form of \\server\share." -Target $destInstance
                return
            }

            if (-not ($SecondaryDatabasePrefix -or $SecondaryDatabaseSuffix) -and ($SourceServer.Name -eq $DestinationServer.Name) -and ($SourceServer.InstanceName -eq $DestinationServer.InstanceName)) {
                if ($Force) {
                    $SecondaryDatabaseSuffix = "_LS"
                } else {
                    $setupResult = "Failed"
                    $comment = "Destination database is the same as source database"
                    Stop-Function -Message "Destination database is the same as source database.`nPlease check the secondary server, database prefix or suffix or use -Force to set the secondary database using a suffix." -Target $SourceSqlInstance
                    return
                }
            }

            # Check if standby is being used
            if ($Standby) {
                # Check the stand-by directory
                if ($StandbyDirectory) {
                    # Check if the path is reachable for the destination server
                    if ((Test-DbaPath -Path $StandbyDirectory -SqlInstance $destInstance -SqlCredential $DestinationCredential) -ne $true) {
                        $setupResult = "Failed"
                        $comment = "The directory $StandbyDirectory cannot be reached by the destination instance"
                        Stop-Function -Message "The directory $StandbyDirectory cannot be reached by the destination instance. Please check the permission and credentials." -Target $destInstance
                        return
                    }
                } elseif (-not $StandbyDirectory -and $Force) {
                    $StandbyDirectory = $destInstance.BackupDirectory
                    Write-Message -Message "Stand-by directory was not set. Setting it to $StandbyDirectory" -Level Verbose
                } else {
                    $setupResult = "Failed"
                    $comment = "Please set the parameter -StandbyDirectory when using -Standby"
                    Stop-Function -Message "Please set the parameter -StandbyDirectory when using -Standby" -Target $SourceSqlInstance
                    return
                }
            }

            # Loop through each of the databases
            foreach ($db in $DatabaseCollection) {

                # Check the status of the database
                if ($db.RecoveryModel -ne 'Full') {
                    $setupResult = "Failed"
                    $comment = "Database $db is not in FULL recovery mode"

                    Stop-Function -Message  "Database $db is not in FULL recovery mode" -Target $SourceSqlInstance -Continue
                }

                # Set the intital destination database
                $SecondaryDatabase = $db.Name

                # Set the database prefix
                if ($SecondaryDatabasePrefix) {
                    $SecondaryDatabase = "$SecondaryDatabasePrefix$($db.Name)"
                }

                # Set the database suffix
                if ($SecondaryDatabaseSuffix) {
                    $SecondaryDatabase += $SecondaryDatabaseSuffix
                }

                # Check is the database is already initialized a check if the database exists on the secondary instance
                if ($NoInitialization -and ($DestinationServer.Databases.Name -notcontains $SecondaryDatabase)) {
                    $setupResult = "Failed"
                    $comment = "Database $SecondaryDatabase needs to be initialized before log shipping setting can continue"

                    Stop-Function -Message "Database $SecondaryDatabase needs to be initialized before log shipping setting can continue." -Target $SourceSqlInstance -Continue
                }

                # Check the local backup path
                if ($LocalPath) {
                    if ($LocalPath.EndsWith("\")) {
                        $DatabaseLocalPath = "$LocalPath$($db.Name)"
                    } else {
                        $DatabaseLocalPath = "$LocalPath\$($db.Name)"
                    }
                } else {
                    $LocalPath = $SharedPath

                    if ($LocalPath.EndsWith("\")) {
                        $DatabaseLocalPath = "$LocalPath$($db.Name)"
                    } else {
                        $DatabaseLocalPath = "$LocalPath\$($db.Name)"
                    }
                }
                Write-Message -Message "Backup local path set to $DatabaseLocalPath." -Level Verbose

                # Setting the backup network path for the database
                if ($SharedPath.EndsWith("\")) {
                    $DatabaseSharedPath = "$SharedPath$($db.Name)"
                } else {
                    $DatabaseSharedPath = "$SharedPath\$($db.Name)"
                }
                Write-Message -Message "Backup network path set to $DatabaseSharedPath." -Level Verbose


                # Checking if the database network path exists
                if ($setupResult -ne 'Failed') {
                    Write-Message -Message "Testing database backup network path $DatabaseSharedPath" -Level Verbose
                    if ((Test-DbaPath -Path $DatabaseSharedPath -SqlInstance $SourceSqlInstance -SqlCredential $SourceCredential) -ne $true) {
                        # To to create the backup directory for the database
                        try {
                            Write-Message -Message "Database backup network path $DatabaseSharedPath not found. Trying to create it.." -Level Verbose

                            Invoke-Command2 -Credential $SourceCredential -ScriptBlock {
                                Write-Message -Message "Creating backup folder $DatabaseSharedPath" -Level Verbose
                                $null = New-Item -Path $DatabaseSharedPath -ItemType Directory -Credential $SourceCredential -Force:$Force
                            }
                        } catch {
                            $setupResult = "Failed"
                            $comment = "Something went wrong creating the backup directory"

                            Stop-Function -Message "Something went wrong creating the backup directory" -ErrorRecord $_ -Target $SourceSqlInstance -Continue
                        }
                    }
                }

                # Check if the backup job name is set
                if ($BackupJob) {
                    $DatabaseBackupJob = "$($BackupJob)$($db.Name)"
                } else {
                    $DatabaseBackupJob = "LSBackup_$($db.Name)"
                }
                Write-Message -Message "Backup job name set to $DatabaseBackupJob" -Level Verbose

                # Check if the backup job schedule name is set
                if ($BackupSchedule) {
                    $DatabaseBackupSchedule = "$($BackupSchedule)$($db.Name)"
                } else {
                    $DatabaseBackupSchedule = "LSBackupSchedule_$($db.Name)"
                }
                Write-Message -Message "Backup job schedule name set to $DatabaseBackupSchedule" -Level Verbose

                # Check if secondary database is present on secondary instance
                if (-not $Force -and -not $NoInitialization -and ($DestinationServer.Databases[$SecondaryDatabase].Status -ne 'Restoring') -and ($DestinationServer.Databases.Name -contains $SecondaryDatabase)) {
                    $setupResult = "Failed"
                    $comment = "Secondary database already exists on instance"

                    Stop-Function -Message "Secondary database already exists on instance $destInstance." -ErrorRecord $_ -Target $destInstance -Continue
                }

                # Check if the secondary database needs to be initialized
                if ($setupResult -ne 'Failed') {
                    if (-not $NoInitialization) {
                        # Check if the secondary database exists on the secondary instance
                        if ($DestinationServer.Databases.Name -notcontains $SecondaryDatabase) {
                            # Check if force is being used and no option to generate the full backup is set
                            if ($Force -and -not ($GenerateFullBackup -or $UseExistingFullBackup)) {
                                # Set the option to generate a full backup
                                Write-Message -Message "Set option to initialize secondary database with full backup" -Level Verbose
                                $GenerateFullBackup = $true
                            } elseif (-not $Force -and -not $GenerateFullBackup -and -not $UseExistingFullBackup -and -not $UseBackupFolder) {
                                # Set up the confirm part
                                $message = "The database $SecondaryDatabase does not exist on instance $destInstance. `nDo you want to initialize it by generating a full backup?"
                                $choiceYes = New-Object System.Management.Automation.Host.ChoiceDescription "&Yes", "Answer Yes."
                                $choiceNo = New-Object System.Management.Automation.Host.ChoiceDescription "&No", "Answer No."
                                $options = [System.Management.Automation.Host.ChoiceDescription[]]($choiceYes, $choiceNo)
                                $result = $host.ui.PromptForChoice($title, $message, $options, 0)

                                # Check the result from the confirm
                                switch ($result) {
                                    # If yes
                                    0 {
                                        # Set the option to generate a full backup
                                        Write-Message -Message "Set option to initialize secondary database with full backup." -Level Verbose
                                        $GenerateFullBackup = $true
                                    }
                                    1 {
                                        $setupResult = "Failed"
                                        $comment = "The database is not initialized on the secondary instance"

                                        Stop-Function -Message "The database is not initialized on the secondary instance. `nPlease initialize the database on the secondary instance, use -GenerateFullbackup or use -Force." -Target $destInstance
                                        return
                                    }
                                } # switch
                            }
                        }
                    }
                }


                # Check the parameters for initialization of the secondary database
                if (-not $NoInitialization -and ($GenerateFullBackup -or $UseExistingFullBackup -or $UseBackupFolder)) {
                    # Check if the restore data and log folder are set
                    if ($setupResult -ne 'Failed') {
                        if ($RestoreDataFolder) {
                            $DatabaseRestoreDataFolder = $RestoreDataFolder
                        } else {
                            Write-Message -Message "Restore data folder is not set. Using server default." -Level Verbose
                            $DatabaseRestoreDataFolder = $DestinationServer.DefaultFile
                        }
                        Write-Message -Message "Restore data folder is set to $DatabaseRestoreDataFolder" -Level Verbose

                        if ($RestoreLogFolder) {
                            $DatabaseRestoreLogFolder = $RestoreLogFolder
                        } else {
                            Write-Message -Message "Restore log folder is not set. Using server default." -Level Verbose
                            $DatabaseRestoreLogFolder = $DestinationServer.DefaultLog
                        }
                        Write-Message -Message "Restore log folder is set to $DatabaseRestoreLogFolder" -Level Verbose

                        # Check if the restore data folder exists
                        Write-Message -Message "Testing database restore data path $DatabaseRestoreDataFolder" -Level Verbose
                        if ((Test-DbaPath  -Path $DatabaseRestoreDataFolder -SqlInstance $destInstance -SqlCredential $DestinationCredential) -ne $true) {
                            if ($PSCmdlet.ShouldProcess($DestinationServerName, "Creating database restore data folder $DatabaseRestoreDataFolder on $DestinationServerName")) {
                                # Try creating the data folder
                                try {
                                    Invoke-Command2 -Credential $DestinationCredential -ScriptBlock {
                                        Write-Message -Message "Creating data folder $DatabaseRestoreDataFolder" -Level Verbose
                                        $null = New-Item -Path $DatabaseRestoreDataFolder -ItemType Directory -Credential $DestinationCredential -Force:$Force
                                    }
                                } catch {
                                    $setupResult = "Failed"
                                    $comment = "Something went wrong creating the restore data directory"
                                    Stop-Function -Message "Something went wrong creating the restore data directory" -ErrorRecord $_ -Target $SourceSqlInstance -Continue
                                }
                            }
                        }

                        # Check if the restore log folder exists
                        Write-Message -Message "Testing database restore log path $DatabaseRestoreLogFolder" -Level Verbose
                        if ((Test-DbaPath  -Path $DatabaseRestoreLogFolder -SqlInstance $destInstance -SqlCredential $DestinationCredential) -ne $true) {
                            if ($PSCmdlet.ShouldProcess($DestinationServerName, "Creating database restore log folder $DatabaseRestoreLogFolder on $DestinationServerName")) {
                                # Try creating the log folder
                                try {
                                    Write-Message -Message "Restore log folder $DatabaseRestoreLogFolder not found. Trying to create it.." -Level Verbose

                                    Invoke-Command2 -Credential $DestinationCredential -ScriptBlock {
                                        Write-Message -Message "Restore log folder $DatabaseRestoreLogFolder not found. Trying to create it.." -Level Verbose
                                        $null = New-Item -Path $DatabaseRestoreLogFolder -ItemType Directory -Credential $DestinationCredential -Force:$Force
                                    }
                                } catch {
                                    $setupResult = "Failed"
                                    $comment = "Something went wrong creating the restore log directory"
                                    Stop-Function -Message "Something went wrong creating the restore log directory" -ErrorRecord $_ -Target $SourceSqlInstance -Continue
                                }
                            }
                        }
                    }

                    # Check if the full backup path can be reached
                    if ($setupResult -ne 'Failed') {
                        if ($FullBackupPath) {
                            Write-Message -Message "Testing full backup path $FullBackupPath" -Level Verbose
                            if ((Test-DbaPath -Path $FullBackupPath -SqlInstance $destInstance -SqlCredential $DestinationCredential) -ne $true) {
                                $setupResult = "Failed"
                                $comment = "The path to the full backup could not be reached"
                                Stop-Function -Message ("The path to the full backup could not be reached. Check the path and/or the crdential") -ErrorRecord $_ -Target $destInstance -Continue
                            }

                            $BackupPath = $FullBackupPath
                        } elseif ($UseBackupFolder.Length -ge 1) {
                            Write-Message -Message "Testing backup folder $UseBackupFolder" -Level Verbose
                            if ((Test-DbaPath -Path $UseBackupFolder -SqlInstance $destInstance -SqlCredential $DestinationCredential) -ne $true) {
                                $setupResult = "Failed"
                                $comment = "The path to the backup folder could not be reached"
                                Stop-Function -Message ("The path to the backup folder could not be reached. Check the path and/or the crdential") -ErrorRecord $_ -Target $destInstance -Continue
                            }

                            $BackupPath = $UseBackupFolder
                        } elseif ($UseExistingFullBackup) {
                            Write-Message -Message "No path to the full backup is set. Trying to retrieve the last full backup for $db from $SourceSqlInstance" -Level Verbose

                            # Get the last full backup
                            $LastBackup = Get-DbaDbBackupHistory -SqlInstance $SourceSqlInstance -Database $($db.Name) -LastFull -SqlCredential $SourceSqlCredential

                            # Check if there was a last backup
                            if ($null -ne $LastBackup) {
                                # Test the path to the backup
                                Write-Message -Message "Testing last backup path $(($LastBackup[-1]).Path[-1])" -Level Verbose
                                if ((Test-DbaPath -Path ($LastBackup[-1]).Path[-1] -SqlInstance $SourceSqlInstance -SqlCredential $SourceCredential) -ne $true) {
                                    $setupResult = "Failed"
                                    $comment = "The full backup could not be found"
                                    Stop-Function -Message "The full backup could not be found on $($LastBackup.Path). Check path and/or credentials" -ErrorRecord $_ -Target $destInstance -Continue
                                }
                                # Check if the source for the last full backup is remote and the backup is on a shared location
                                elseif (($LastBackup.Computername -ne $SourceServerName) -and (($LastBackup[-1]).Path[-1].StartsWith('\\') -eq $false)) {
                                    $setupResult = "Failed"
                                    $comment = "The last full backup is not located on shared location"
                                    Stop-Function -Message "The last full backup is not located on shared location. `n$($_.Exception.Message)" -ErrorRecord $_ -Target $destInstance -Continue
                                } else {
                                    #$FullBackupPath = $LastBackup.Path
                                    $BackupPath = $LastBackup.Path
                                    Write-Message -Message "Full backup found for $db. Path $BackupPath" -Level Verbose
                                }
                            } else {
                                Write-Message -Message "No Full backup found for $db." -Level Verbose
                            }
                        }
                    }
                }

                # Set the copy destination folder to include the database name
                if ($CopyDestinationFolder.EndsWith("\")) {
                    $DatabaseCopyDestinationFolder = "$CopyDestinationFolder$($db.Name)"
                } else {
                    $DatabaseCopyDestinationFolder = "$CopyDestinationFolder\$($db.Name)"
                }
                Write-Message -Message "Copy destination folder set to $DatabaseCopyDestinationFolder." -Level Verbose

                # Check if the copy job name is set
                if ($CopyJob) {
                    $DatabaseCopyJob = "$($CopyJob)$($db.Name)"
                } else {
                    $DatabaseCopyJob = "LSCopy_$($SourceServerName)_$($db.Name)"
                }
                Write-Message -Message "Copy job name set to $DatabaseCopyJob" -Level Verbose

                # Check if the copy job schedule name is set
                if ($CopySchedule) {
                    $DatabaseCopySchedule = "$($CopySchedule)$($db.Name)"
                } else {
                    $DatabaseCopySchedule = "LSCopySchedule_$($SourceServerName)_$($db.Name)"
                    Write-Message -Message "Copy job schedule name set to $DatabaseCopySchedule" -Level Verbose
                }

                # Check if the copy destination folder exists
                if ($setupResult -ne 'Failed') {
                    Write-Message -Message "Testing database copy destination path $DatabaseCopyDestinationFolder" -Level Verbose
                    if ((Test-DbaPath -Path $DatabaseCopyDestinationFolder -SqlInstance $destInstance -SqlCredential $DestinationCredential) -ne $true) {
                        if ($PSCmdlet.ShouldProcess($DestinationServerName, "Creating copy destination folder on $DestinationServerName")) {
                            try {
                                Invoke-Command2 -Credential $DestinationCredential -ScriptBlock {
                                    Write-Message -Message "Copy destination folder $DatabaseCopyDestinationFolder not found. Trying to create it.. ." -Level Verbose
                                    $null = New-Item -Path $DatabaseCopyDestinationFolder -ItemType Directory -Credential $DestinationCredential -Force:$Force
                                }
                            } catch {
                                $setupResult = "Failed"
                                $comment = "Something went wrong creating the database copy destination folder"
                                Stop-Function -Message "Something went wrong creating the database copy destination folder. `n$($_.Exception.Message)" -ErrorRecord $_ -Target $DestinationServerName -Continue
                            }
                        }
                    }
                }

                # Check if the restore job name is set
                if ($RestoreJob) {
                    $DatabaseRestoreJob = "$($RestoreJob)$($db.Name)"
                } else {
                    $DatabaseRestoreJob = "LSRestore_$($SourceServerName)_$($db.Name)"
                }
                Write-Message -Message "Restore job name set to $DatabaseRestoreJob" -Level Verbose

                # Check if the restore job schedule name is set
                if ($RestoreSchedule) {
                    $DatabaseRestoreSchedule = "$($RestoreSchedule)$($db.Name)"
                } else {
                    $DatabaseRestoreSchedule = "LSRestoreSchedule_$($SourceServerName)_$($db.Name)"
                }
                Write-Message -Message "Restore job schedule name set to $DatabaseRestoreSchedule" -Level Verbose

                # If the database needs to be backed up first
                if ($setupResult -ne 'Failed') {
                    if ($GenerateFullBackup) {
                        if ($PSCmdlet.ShouldProcess($SourceSqlInstance, "Backing up database $db")) {

                            Write-Message -Message "Generating full backup." -Level Verbose
                            Write-Message -Message "Backing up database $db to $DatabaseSharedPath" -Level Verbose

                            try {
                                $Timestamp = Get-Date -format "yyyyMMddHHmmss"

                                $LastBackup = Backup-DbaDatabase -SqlInstance $SourceSqlInstance `
                                    -SqlCredential $SourceSqlCredential `
                                    -BackupDirectory $DatabaseSharedPath `
                                    -BackupFileName "FullBackup_$($db.Name)_PreLogShipping_$Timestamp.bak" `
                                    -Database $($db.Name) `
                                    -Type Full

                                Write-Message -Message "Backup completed." -Level Verbose

                                # Get the last full backup path
                                #$FullBackupPath = $LastBackup.BackupPath
                                $BackupPath = $LastBackup.BackupPath

                                Write-Message -Message "Backup is located at $BackupPath" -Level Verbose
                            } catch {
                                $setupResult = "Failed"
                                $comment = "Something went wrong generating the full backup"
                                Stop-Function -Message "Something went wrong generating the full backup" -ErrorRecord $_ -Target $DestinationServerName -Continue
                            }
                        }
                    }
                }

                # Check of the MonitorServerSecurityMode value is of type string and set the integer value
                if ($PrimaryMonitorServerSecurityMode -notin 0, 1) {
                    $PrimaryMonitorServerSecurityMode = switch ($PrimaryMonitorServerSecurityMode) {
                        "SQLSERVER" { 0 } "WINDOWS" { 1 } default { 1 }
                    }
                }

                # Check the primary monitor server
                if ($Force -and (-not $PrimaryMonitorServer -or [string]$PrimaryMonitorServer -eq '' -or $null -eq $PrimaryMonitorServer)) {
                    Write-Message -Message "Setting monitor server for primary server to $SourceSqlInstance." -Level Verbose
                    $PrimaryMonitorServer = $SourceSqlInstance
                }

                # Check the PrimaryMonitorServerSecurityMode if it's SQL Server authentication
                if ($PrimaryMonitorServerSecurityMode -eq 0) {
                    if ($PrimaryMonitorServerLogin) {
                        $setupResult = "Failed"
                        $comment = "The PrimaryMonitorServerLogin cannot be empty"
                        Stop-Function -Message "The PrimaryMonitorServerLogin cannot be empty when using SQL Server authentication." -Target $SourceSqlInstance -Continue
                    }

                    if ($PrimaryMonitorServerPassword) {
                        $setupResult = "Failed"
                        $comment = "The PrimaryMonitorServerPassword cannot be empty"
                        Stop-Function -Message "The PrimaryMonitorServerPassword cannot be empty when using SQL Server authentication." -Target $ -Continue
                    }
                }

                # Check of the SecondaryMonitorServerSecurityMode value is of type string and set the integer value
                if ($SecondaryMonitorServerSecurityMode -notin 0, 1) {
                    $SecondaryMonitorServerSecurityMode = switch ($SecondaryMonitorServerSecurityMode) {
                        "SQLSERVER" { 0 } "WINDOWS" { 1 } default { 1 }
                    }
                }

                # Check the secondary monitor server
                if ($Force -and (-not $SecondaryMonitorServer -or [string]$SecondaryMonitorServer -eq '' -or $null -eq $SecondaryMonitorServer)) {
                    Write-Message -Message "Setting secondary monitor server for $destInstance to $SourceSqlInstance." -Level Verbose
                    $SecondaryMonitorServer = $SourceSqlInstance
                }

                # Check the MonitorServerSecurityMode if it's SQL Server authentication
                if ($SecondaryMonitorServerSecurityMode -eq 0) {
                    if ($SecondaryMonitorServerLogin) {
                        $setupResult = "Failed"
                        $comment = "The SecondaryMonitorServerLogin cannot be empty"
                        Stop-Function -Message "The SecondaryMonitorServerLogin cannot be empty when using SQL Server authentication." -Target $SourceSqlInstance -Continue
                    }

                    if ($SecondaryMonitorServerPassword) {
                        $setupResult = "Failed"
                        $comment = "The SecondaryMonitorServerPassword cannot be empty"
                        Stop-Function -Message "The SecondaryMonitorServerPassword cannot be empty when using SQL Server authentication." -Target $SourceSqlInstance -Continue
                    }
                }

                # Now that all the checks have been done we can start with the fun stuff !

                # Restore the full backup
                if ($setupResult -ne 'Failed') {
                    if ($PSCmdlet.ShouldProcess($destInstance, "Restoring database $db to $SecondaryDatabase on $destInstance")) {
                        if ($GenerateFullBackup -or $UseExistingFullBackup -or $UseBackupFolder) {
                            try {
                                Write-Message -Message "Start database restore" -Level Verbose
                                if ($NoRecovery -or (-not $Standby)) {
                                    if ($Force) {
                                        $null = Restore-DbaDatabase -SqlInstance $destInstance `
                                            -SqlCredential $DestinationSqlCredential `
                                            -Path $BackupPath `
                                            -DestinationFilePrefix $SecondaryDatabasePrefix `
                                            -DestinationFileSuffix $SecondaryDatabaseSuffix `
                                            -DestinationDataDirectory $DatabaseRestoreDataFolder `
                                            -DestinationLogDirectory $DatabaseRestoreLogFolder `
                                            -DatabaseName $SecondaryDatabase `
                                            -DirectoryRecurse `
                                            -NoRecovery `
                                            -WithReplace
                                    } else {
                                        $null = Restore-DbaDatabase -SqlInstance $destInstance `
                                            -SqlCredential $DestinationSqlCredential `
                                            -Path $BackupPath `
                                            -DestinationFilePrefix $SecondaryDatabasePrefix `
                                            -DestinationFileSuffix $SecondaryDatabaseSuffix `
                                            -DestinationDataDirectory $DatabaseRestoreDataFolder `
                                            -DestinationLogDirectory $DatabaseRestoreLogFolder `
                                            -DatabaseName $SecondaryDatabase `
                                            -DirectoryRecurse `
                                            -NoRecovery
                                    }
                                }

                                # If the database needs to be in standby
                                if ($Standby) {
                                    # Setup the path to the standby file
                                    $StandbyDirectory = "$DatabaseCopyDestinationFolder"

                                    # Check if credentials need to be used
                                    if ($DestinationSqlCredential) {
                                        $null = Restore-DbaDatabase -SqlInstance $destInstance `
                                            -SqlCredential $DestinationSqlCredential `
                                            -Path $BackupPath `
                                            -DestinationFilePrefix $SecondaryDatabasePrefix `
                                            -DestinationFileSuffix $SecondaryDatabaseSuffix `
                                            -DestinationDataDirectory $DatabaseRestoreDataFolder `
                                            -DestinationLogDirectory $DatabaseRestoreLogFolder `
                                            -DatabaseName $SecondaryDatabase `
                                            -DirectoryRecurse `
                                            -StandbyDirectory $StandbyDirectory
                                    } else {
                                        $null = Restore-DbaDatabase -SqlInstance $destInstance `
                                            -Path $BackupPath `
                                            -DestinationFilePrefix $SecondaryDatabasePrefix `
                                            -DestinationFileSuffix $SecondaryDatabaseSuffix `
                                            -DestinationDataDirectory $DatabaseRestoreDataFolder `
                                            -DestinationLogDirectory $DatabaseRestoreLogFolder `
                                            -DatabaseName $SecondaryDatabase `
                                            -DirectoryRecurse `
                                            -StandbyDirectory $StandbyDirectory
                                    }
                                }
                            } catch {
                                $setupResult = "Failed"
                                $comment = "Something went wrong restoring the secondary database"
                                Stop-Function -Message "Something went wrong restoring the secondary database" -ErrorRecord $_ -Target $SourceSqlInstance -Continue
                            }

                            Write-Message -Message "Restore completed." -Level Verbose
                        }
                    }
                }

                #region Set up log shipping on the primary instance
                # Set up log shipping on the primary instance
                if ($setupResult -ne 'Failed') {
                    if ($PSCmdlet.ShouldProcess($SourceSqlInstance, "Configuring logshipping for primary database $db on $SourceSqlInstance")) {
                        try {

                            Write-Message -Message "Configuring logshipping for primary database" -Level Verbose

                            New-DbaLogShippingPrimaryDatabase -SqlInstance $SourceSqlInstance `
                                -SqlCredential $SourceSqlCredential `
                                -Database $($db.Name) `
                                -BackupDirectory $DatabaseLocalPath `
                                -BackupJob $DatabaseBackupJob `
                                -BackupRetention $BackupRetention `
                                -BackupShare $DatabaseSharedPath `
                                -BackupThreshold $BackupThreshold `
                                -CompressBackup:$BackupCompression `
                                -HistoryRetention $HistoryRetention `
                                -MonitorServer $PrimaryMonitorServer `
                                -MonitorServerSecurityMode $PrimaryMonitorServerSecurityMode `
                                -MonitorCredential $PrimaryMonitorCredential `
                                -ThresholdAlertEnabled:$PrimaryThresholdAlertEnabled `
                                -Force:$Force

                            # Check if the backup job needs to be enabled or disabled
                            if ($BackupScheduleDisabled) {
                                $null = Set-DbaAgentJob -SqlInstance $SourceSqlInstance -SqlCredential $SourceSqlCredential -Job $DatabaseBackupJob -Disabled
                                Write-Message -Message "Disabling backup job $DatabaseBackupJob" -Level Verbose
                            } else {
                                $null = Set-DbaAgentJob -SqlInstance $SourceSqlInstance -SqlCredential $SourceSqlCredential -Job $DatabaseBackupJob -Enabled
                                Write-Message -Message "Enabling backup job $DatabaseBackupJob" -Level Verbose
                            }

                            Write-Message -Message "Create backup job schedule $DatabaseBackupSchedule" -Level Verbose

                            #Variable $BackupJobSchedule marked as unused by PSScriptAnalyzer replaced with $null for catching output
                            $null = New-DbaAgentSchedule -SqlInstance $SourceSqlInstance `
                                -SqlCredential $SourceSqlCredential `
                                -Job $DatabaseBackupJob `
                                -Schedule $DatabaseBackupSchedule `
                                -FrequencyType $BackupScheduleFrequencyType `
                                -FrequencyInterval $BackupScheduleFrequencyInterval `
                                -FrequencySubdayType $BackupScheduleFrequencySubdayType `
                                -FrequencySubdayInterval $BackupScheduleFrequencySubdayInterval `
                                -FrequencyRelativeInterval $BackupScheduleFrequencyRelativeInterval `
                                -FrequencyRecurrenceFactor $BackupScheduleFrequencyRecurrenceFactor `
                                -StartDate $BackupScheduleStartDate `
                                -EndDate $BackupScheduleEndDate `
                                -StartTime $BackupScheduleStartTime `
                                -EndTime $BackupScheduleEndTime `
                                -Force:$Force

                            Write-Message -Message "Configuring logshipping from primary to secondary database." -Level Verbose

                            New-DbaLogShippingPrimarySecondary -SqlInstance $SourceSqlInstance `
                                -SqlCredential $SourceSqlCredential `
                                -PrimaryDatabase $($db.Name) `
                                -SecondaryDatabase $SecondaryDatabase `
                                -SecondaryServer $destInstance `
                                -SecondarySqlCredential $DestinationSqlCredential
                        } catch {
                            $setupResult = "Failed"
                            $comment = "Something went wrong setting up log shipping for primary instance"
                            Stop-Function -Message "Something went wrong setting up log shipping for primary instance" -ErrorRecord $_ -Target $SourceSqlInstance -Continue
                        }
                    }
                }
                #endregion Set up log shipping on the primary instance

                #region Set up log shipping on the secondary instance
                # Set up log shipping on the secondary instance
                if ($setupResult -ne 'Failed') {
                    if ($PSCmdlet.ShouldProcess($destInstance, "Configuring logshipping for secondary database $SecondaryDatabase on $destInstance")) {
                        try {

                            Write-Message -Message "Configuring logshipping from secondary database $SecondaryDatabase to primary database $db." -Level Verbose

                            New-DbaLogShippingSecondaryPrimary -SqlInstance $destInstance `
                                -SqlCredential $DestinationSqlCredential `
                                -BackupSourceDirectory $DatabaseSharedPath `
                                -BackupDestinationDirectory $DatabaseCopyDestinationFolder `
                                -CopyJob $DatabaseCopyJob `
                                -FileRetentionPeriod $BackupRetention `
                                -MonitorServer $SecondaryMonitorServer `
                                -MonitorServerSecurityMode $SecondaryMonitorServerSecurityMode `
                                -MonitorCredential $SecondaryMonitorCredential `
                                -PrimaryServer $SourceSqlInstance `
                                -PrimaryDatabase $($db.Name) `
                                -RestoreJob $DatabaseRestoreJob `
                                -Force:$Force

                            Write-Message -Message "Create copy job schedule $DatabaseCopySchedule" -Level Verbose
                            #Variable $CopyJobSchedule marked as unused by PSScriptAnalyzer replaced with $null for catching output
                            $null = New-DbaAgentSchedule -SqlInstance $destInstance `
                                -SqlCredential $DestinationSqlCredential `
                                -Job $DatabaseCopyJob `
                                -Schedule $DatabaseCopySchedule `
                                -FrequencyType $CopyScheduleFrequencyType `
                                -FrequencyInterval $CopyScheduleFrequencyInterval `
                                -FrequencySubdayType $CopyScheduleFrequencySubdayType `
                                -FrequencySubdayInterval $CopyScheduleFrequencySubdayInterval `
                                -FrequencyRelativeInterval $CopyScheduleFrequencyRelativeInterval `
                                -FrequencyRecurrenceFactor $CopyScheduleFrequencyRecurrenceFactor `
                                -StartDate $CopyScheduleStartDate `
                                -EndDate $CopyScheduleEndDate `
                                -StartTime $CopyScheduleStartTime `
                                -EndTime $CopyScheduleEndTime `
                                -Force:$Force

                            Write-Message -Message "Create restore job schedule $DatabaseRestoreSchedule" -Level Verbose

                            #Variable $RestoreJobSchedule marked as unused by PSScriptAnalyzer replaced with $null for catching output
                            $null = New-DbaAgentSchedule -SqlInstance $destInstance `
                                -SqlCredential $DestinationSqlCredential `
                                -Job $DatabaseRestoreJob `
                                -Schedule $DatabaseRestoreSchedule `
                                -FrequencyType $RestoreScheduleFrequencyType `
                                -FrequencyInterval $RestoreScheduleFrequencyInterval `
                                -FrequencySubdayType $RestoreScheduleFrequencySubdayType `
                                -FrequencySubdayInterval $RestoreScheduleFrequencySubdayInterval `
                                -FrequencyRelativeInterval $RestoreScheduleFrequencyRelativeInterval `
                                -FrequencyRecurrenceFactor $RestoreScheduleFrequencyRecurrenceFactor `
                                -StartDate $RestoreScheduleStartDate `
                                -EndDate $RestoreScheduleEndDate `
                                -StartTime $RestoreScheduleStartTime `
                                -EndTime $RestoreScheduleEndTime `
                                -Force:$Force

                            Write-Message -Message "Configuring logshipping for secondary database." -Level Verbose

                            New-DbaLogShippingSecondaryDatabase -SqlInstance $destInstance `
                                -SqlCredential $DestinationSqlCredential `
                                -SecondaryDatabase $SecondaryDatabase `
                                -PrimaryServer $SourceSqlInstance `
                                -PrimaryDatabase $($db.Name) `
                                -RestoreDelay $RestoreDelay `
                                -RestoreMode $DatabaseStatus `
                                -DisconnectUsers:$DisconnectUsers `
                                -RestoreThreshold $RestoreThreshold `
                                -ThresholdAlertEnabled:$SecondaryThresholdAlertEnabled `
                                -HistoryRetention $HistoryRetention `
                                -MonitorServer $SecondaryMonitorServer `
                                -MonitorServerSecurityMode $SecondaryMonitorServerSecurityMode `
                                -MonitorCredential $SecondaryMonitorCredential

                            # Check if the copy job needs to be enabled or disabled
                            if ($CopyScheduleDisabled) {
                                $null = Set-DbaAgentJob -SqlInstance $destInstance -SqlCredential $DestinationSqlCredential -Job $DatabaseCopyJob -Disabled
                            } else {
                                $null = Set-DbaAgentJob -SqlInstance $destInstance -SqlCredential $DestinationSqlCredential -Job $DatabaseCopyJob -Enabled
                            }

                            # Check if the restore job needs to be enabled or disabled
                            if ($RestoreScheduleDisabled) {
                                $null = Set-DbaAgentJob -SqlInstance $destInstance -SqlCredential $DestinationSqlCredential -Job $DatabaseRestoreJob -Disabled
                            } else {
                                $null = Set-DbaAgentJob -SqlInstance $destInstance -SqlCredential $DestinationSqlCredential -Job $DatabaseRestoreJob -Enabled
                            }

                        } catch {
                            $setupResult = "Failed"
                            $comment = "Something went wrong setting up log shipping for secondary instance"
                            Stop-Function -Message "Something went wrong setting up log shipping for secondary instance.`n$($_.Exception.Message)" -ErrorRecord $_ -Target $destInstance -Continue
                        }
                    }
                }
                #endregion Set up log shipping on the secondary instance

                Write-Message -Message "Completed configuring log shipping for database $db" -Level Verbose

                [PSCustomObject]@{
                    PrimaryInstance   = $SourceServer.DomainInstanceName
                    SecondaryInstance = $DestinationServer.DomainInstanceName
                    PrimaryDatabase   = $($db.Name)
                    SecondaryDatabase = $SecondaryDatabase
                    Result            = $setupResult
                    Comment           = $comment
                }

            } # for each database
        } # end for each destination server
    } # end process
    end {
        Write-Message -Message "Finished setting up log shipping." -Level Verbose
    }
}

# SIG # Begin signature block
# MIIjYAYJKoZIhvcNAQcCoIIjUTCCI00CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCBB2GQyKEyaVK2n
# fYvc3iQ/RHpl7pzTHq2QPrUhKXMedqCCHVkwggUaMIIEAqADAgECAhADBbuGIbCh
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
# BgorBgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCBjCiJqP3mJDCHIXFZEe289pbeC
# n/HeQTnzTXNYBG/ZHDANBgkqhkiG9w0BAQEFAASCAQB5Lgo+acsqbMgjwHd8YIaD
# VMXxb8ehsJ/Og0z2t+q5nF3Er1n8HsUJYygh+ulLsVQzj8Z3knld79GF99U1jrsP
# 9OrCOXeB78lf05+ynj3p3I9jTAJt4XfFihuAsgapWfAORNvDIe6yh92pNNc4gc2E
# I1FOymc0xXE8mBtXd7HUv2FBrhpi5w0NrTXCMgsT+rdj6pFrtO9P7lAAzR2wCea+
# 78wXPyaeS459DzhUeqTBsm92ccKjywbs2xvY4QvdGCt1mNgxS37UYMqzf0HHCWYa
# pmQFqjVaBDmSqCeIiVVhRlrik15csWbQPNYr0swOwcLF9hPOxgOqrR4PGPUXs6L6
# oYIDIDCCAxwGCSqGSIb3DQEJBjGCAw0wggMJAgEBMHcwYzELMAkGA1UEBhMCVVMx
# FzAVBgNVBAoTDkRpZ2lDZXJ0LCBJbmMuMTswOQYDVQQDEzJEaWdpQ2VydCBUcnVz
# dGVkIEc0IFJTQTQwOTYgU0hBMjU2IFRpbWVTdGFtcGluZyBDQQIQDE1pckuU+jwq
# Sj0pB4A9WjANBglghkgBZQMEAgEFAKBpMBgGCSqGSIb3DQEJAzELBgkqhkiG9w0B
# BwEwHAYJKoZIhvcNAQkFMQ8XDTIyMTExNzA4NTY0M1owLwYJKoZIhvcNAQkEMSIE
# IArg9emwl+4/mBMHeNJBc71W9W3Qu7cDrJbX6i1/+FnlMA0GCSqGSIb3DQEBAQUA
# BIICAG+rgWz7lV59v/VBGz2hm4GLahO/D6SRSzciydOL8zXulBQW9MKj+AV/ajWo
# Q+7Mw2YQ/spQEMx9TNISZRLOAtf7Q6oFTGmxljAsPV9Tg+5PnbucmYjbjUd61tVT
# syrArFi2L8rtmfJKzlrX6Yu131U/5gXVgDhyc5SBe4fJLU7l2FHsCSkh+ziZ8gmR
# B2MAtaJ0kdJcT/VxCpy5BUfcfwwODLouU/EOvTpkCDvVsqPanC1vXhQVtkBaFWio
# Hk+VRfJJpiwpe1IXDLsno/DlVqE51tDfG0Rr6WBw4qyjg3SxomsE1DK77kvjkRtK
# YvuCMPMLi+Do/I5gSqng4/fDBrIHm964MxGmlCSiv2vyi16JMEU3K/FlTYe7WEUv
# ZSgzM7vWdPtpMa2Oi8NIvDds5/Z9Eyq8y6j5DxQiG8ufbR7CODg0Z6WheEJClFS9
# jVks8qMKJgXeDvcTb22QuOHr85W7wY7Hu2J5VdfgfwCEGLl0zQ2ZVfzlla0rrJdM
# sBPiwqFkZmjBVYYoK94o0nSj8Aogc0zks+MGhKjdAMcY+TYekTwI/rUds5w7pAaj
# 5d8idalsoPUsLiCGvik447BiaGMtmC5I+bK83b3k6QKxjCjbdjm4egNEo1J+BjME
# MhQWZf6VTdeO5tsaDjIrWRe7iX4EVZfQXX3Lf28TgWRRAT23
# SIG # End signature block
