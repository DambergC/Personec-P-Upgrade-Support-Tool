function New-DbaAgentSchedule {
    <#
    .SYNOPSIS
        New-DbaAgentSchedule creates a new schedule in the msdb database.

    .DESCRIPTION
        New-DbaAgentSchedule will help create a new schedule for a job.
        If the job parameter is not supplied the schedule will not be attached to a job.

    .PARAMETER SqlInstance
        The target SQL Server instance or instances. You must have sysadmin access and server version must be SQL Server version 2000 or greater.

    .PARAMETER SqlCredential
        Login to the target instance using alternative credentials. Accepts PowerShell credentials (Get-Credential).

        Windows Authentication, SQL Server Authentication, Active Directory - Password, and Active Directory - Integrated are all supported.

        For MFA support, please use Connect-DbaInstance.

    .PARAMETER Job
        The name of the job that has the schedule.

    .PARAMETER Schedule
        The name of the schedule.

    .PARAMETER Disabled
        Set the schedule to disabled. Default is enabled

    .PARAMETER FrequencyType
        A value indicating when a job is to be executed.

        Allowed values: 'Once', 'OneTime', 'Daily', 'Weekly', 'Monthly', 'MonthlyRelative', 'AgentStart', 'AutoStart', 'IdleComputer', 'OnIdle'

        The following synonyms provide flexibility to the allowed values for this function parameter:
        Once=OneTime
        AgentStart=AutoStart
        IdleComputer=OnIdle

        If force is used the default will be "Once".

    .PARAMETER FrequencyInterval
        The days that a job is executed

        Allowed values for FrequencyType 'Daily': EveryDay or a number between 1 and 365.
        Allowed values for FrequencyType 'Weekly': Sunday, Monday, Tuesday, Wednesday, Thursday, Friday, Saturday, Weekdays, Weekend or EveryDay.
        Allowed values for FrequencyType 'Monthly': Numbers 1 to 31 for each day of the month.

        If "Weekdays", "Weekend" or "EveryDay" is used it over writes any other value that has been passed before.

        If force is used the default will be 1.

    .PARAMETER FrequencySubdayType
        Specifies the units for the subday FrequencyInterval.

        Allowed values: 'Once', 'Time', 'Seconds', 'Second', 'Minutes', 'Minute', 'Hours', 'Hour'

        The following synonyms provide flexibility to the allowed values for this function parameter:
        Once=Time
        Seconds=Second
        Minutes=Minute
        Hours=Hour

    .PARAMETER FrequencySubdayInterval
        The number of subday type periods to occur between each execution of a job.

    .PARAMETER FrequencyRelativeInterval
        A job's occurrence of FrequencyInterval in each month, if FrequencyInterval is 32 (monthlyrelative).

        Allowed values: First, Second, Third, Fourth or Last

    .PARAMETER FrequencyRecurrenceFactor
        The number of weeks or months between the scheduled execution of a job.

        FrequencyRecurrenceFactor is used only if FrequencyType is "Weekly", "Monthly" or "MonthlyRelative".

    .PARAMETER StartDate
        The date on which execution of a job can begin.

        If force is used the start date will be the current day

    .PARAMETER EndDate
        The date on which execution of a job can stop.

        If force is used the end date will be '9999-12-31'

    .PARAMETER StartTime
        The time on any day to begin execution of a job. Format HHMMSS / 24 hour clock.
        Example: '010000' for 01:00:00 AM.
        Example: '140000' for 02:00:00 PM.

        If force is used the start time will be '00:00:00'

    .PARAMETER EndTime
        The time on any day to end execution of a job. Format HHMMSS / 24 hour clock.
        Example: '010000' for 01:00:00 AM.
        Example: '140000' for 02:00:00 PM.

        If force is used the start time will be '23:59:59'

    .PARAMETER WhatIf
        Shows what would happen if the command were to run. No actions are actually performed.

    .PARAMETER Confirm
        Prompts you for confirmation before executing any changing operations within the command.

    .PARAMETER Force
        The force parameter will ignore some errors in the parameters and assume defaults.
        It will also remove the any present schedules with the same name for the specific job.

    .PARAMETER EnableException
        By default, when something goes wrong we try to catch it, interpret it and give you a friendly warning message.
        This avoids overwhelming you with "sea of red" exceptions, but is inconvenient because it basically disables advanced scripting.
        Using this switch turns this "nice by default" feature off and enables you to catch exceptions with your own try/catch.

    .NOTES
        Tags: Agent, Job, JobStep
        Author: Sander Stad (@sqlstad), sqlstad.nl

        Website: https://dbatools.io
        Copyright: (c) 2018 by dbatools, licensed under MIT
        License: MIT https://opensource.org/licenses/MIT

    .LINK
        https://dbatools.io/New-DbaAgentSchedule

    .EXAMPLE
        PS C:\> New-DbaAgentSchedule -SqlInstance sql01 -Schedule DailyAt6 -FrequencyType Daily -StartTime "060000" -Force

        Creates a schedule that runs jobs every day at 6 in the morning. It assumes default values for the start date, start time, end date and end time due to -Force.

    .EXAMPLE
        PS C:\> New-DbaAgentSchedule -SqlInstance localhost\SQL2016 -Schedule daily -FrequencyType Daily -FrequencyInterval Everyday -Force

        Creates a schedule with a daily frequency every day. It assumes default values for the start date, start time, end date and end time due to -Force.

    .EXAMPLE
        PS C:\> New-DbaAgentSchedule -SqlInstance sstad-pc -Schedule MonthlyTest -FrequencyType Monthly -FrequencyInterval 10 -FrequencyRecurrenceFactor 1 -Force

        Create a schedule with a monhtly frequency occuring every 10th of the month. It assumes default values for the start date, start time, end date and end time due to -Force.

    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = "Low")]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSUseOutputTypeCorrectly", "", Justification = "PSSA Rule Ignored by BOH")]
    param (
        [parameter(Mandatory, ValueFromPipeline)]
        [DbaInstanceParameter[]]$SqlInstance,
        [System.Management.Automation.PSCredential]
        $SqlCredential,
        [object[]]$Job,
        [object]$Schedule,
        [switch]$Disabled,
        [ValidateSet('Once', 'OneTime', 'Daily', 'Weekly', 'Monthly', 'MonthlyRelative', 'AgentStart', 'AutoStart', 'IdleComputer', 'OnIdle')]
        [object]$FrequencyType,
        [object[]]$FrequencyInterval,
        [ValidateSet('Once', 'Time', 'Seconds', 'Second', 'Minutes', 'Minute', 'Hours', 'Hour')]
        [object]$FrequencySubdayType,
        [int]$FrequencySubdayInterval,
        [ValidateSet('Unused', 'First', 'Second', 'Third', 'Fourth', 'Last')]
        [object]$FrequencyRelativeInterval,
        [int]$FrequencyRecurrenceFactor,
        [string]$StartDate,
        [string]$EndDate,
        [string]$StartTime,
        [string]$EndTime,
        [switch]$Force,
        [switch]$EnableException
    )

    begin {
        if ($Force) { $ConfirmPreference = 'none' }

        if ($FrequencyType -eq "Daily" -and -not $FrequencyInterval) {
            $FrequencyInterval = 1
        }

        # if a Schedule is not provided there is no much point
        if (-not $Schedule) {
            Stop-Function -Message "A schedule was not provided! Please provide a schedule name."
            return
        }

        [int]$interval = 0

        # Translate FrequencyType value from string to the integer value
        [int]$FrequencyType =
        switch ($FrequencyType) {
            "Once" { 1 }
            "OneTime" { 1 }
            "Daily" { 4 }
            "Weekly" { 8 }
            "Monthly" { 16 }
            "MonthlyRelative" { 32 }
            "AgentStart" { 64 }
            "AutoStart" { 64 }
            "IdleComputer" { 128 }
            "OnIdle" { 128 }
            default { 1 }
        }

        # Translate FrequencySubdayType value from string to the integer value
        [int]$FrequencySubdayType =
        switch ($FrequencySubdayType) {
            "Once" { 1 }
            "Time" { 1 }
            "Seconds" { 2 }
            "Second" { 2 }
            "Minutes" { 4 }
            "Minute" { 4 }
            "Hours" { 8 }
            "Hour" { 8 }
            default { 1 }
        }

        # Check if the relative FrequencyInterval value is of type string and set the integer value
        [int]$FrequencyRelativeInterval =
        switch ($FrequencyRelativeInterval) {
            "First" { 1 }
            "Second" { 2 }
            "Third" { 4 }
            "Fourth" { 8 }
            "Last" { 16 }
            "Unused" { 0 }
            default { 0 }
        }

        # Check if the interval for daily frequency is valid
        if (($FrequencyType -eq 4) -and ($FrequencyInterval -lt 1 -or $FrequencyInterval -ge 365) -and (-not ($FrequencyInterval -eq "EveryDay")) -and (-not $Force)) {
            Stop-Function -Message "The daily frequency type requires a frequency interval to be between 1 and 365 or 'EveryDay'." -Target $SqlInstance
            return
        }

        # Check if the recurrence factor is set for weekly or monthly interval
        if (($FrequencyType -in (16, 8)) -and $FrequencyRecurrenceFactor -lt 1) {
            if ($Force) {
                $FrequencyRecurrenceFactor = 1
                Write-Message -Message "Recurrence factor not set for weekly or monthly interval. Setting it to $FrequencyRecurrenceFactor." -Level Verbose
            } else {
                Stop-Function -Message "The recurrence factor $FrequencyRecurrenceFactor (parameter FrequencyRecurrenceFactor) needs to be at least one when using a weekly or monthly interval." -Target $SqlInstance
                return
            }
        }

        # Check the subday interval
        if (($FrequencySubdayType -in 2, "Seconds", 4, "Minutes") -and (-not ($FrequencySubdayInterval -ge 1 -or $FrequencySubdayInterval -le 59))) {
            Stop-Function -Message "Subday interval $FrequencySubdayInterval must be between 1 and 59 when subday type is 'Seconds' or 'Minutes'" -Target $SqlInstance
            return
        } elseif (($FrequencySubdayType -eq 8, "Hours") -and (-not ($FrequencySubdayInterval -ge 1 -and $FrequencySubdayInterval -le 23))) {
            Stop-Function -Message "Subday interval $FrequencySubdayInterval must be between 1 and 23 when subday type is 'Hours'" -Target $SqlInstance
            return
        }

        # If the FrequencyInterval is set for the daily FrequencyType
        if ($FrequencyType -eq 4) {
            # Create the interval to hold the value(s)
            [int]$interval = 1

            if ($FrequencyInterval -and $FrequencyInterval[0].GetType().Name -eq 'Int32') {
                $interval = $FrequencyInterval[0]
            }
        }

        # If the FrequencyInterval is set for the weekly FrequencyType
        if ($FrequencyType -in 8, 'Weekly') {
            # Create the interval to hold the value(s)
            [int]$interval = 0

            # Loop through the array
            foreach ($item in $FrequencyInterval) {

                switch ($item) {
                    "Sunday" { $interval += 1 }
                    "Monday" { $interval += 2 }
                    "Tuesday" { $interval += 4 }
                    "Wednesday" { $interval += 8 }
                    "Thursday" { $interval += 16 }
                    "Friday" { $interval += 32 }
                    "Saturday" { $interval += 64 }
                    "Weekdays" { $interval = 62 }
                    "Weekend" { $interval = 65 }
                    "EveryDay" { $interval = 127 }
                    1 { $interval += 1 }
                    2 { $interval += 2 }
                    4 { $interval += 4 }
                    8 { $interval += 8 }
                    16 { $interval += 16 }
                    32 { $interval += 32 }
                    64 { $interval += 64 }
                    62 { $interval = 62 }
                    65 { $interval = 65 }
                    127 { $interval = 127 }
                    default { $interval = 0 }
                }
            }
        }

        # If the FrequencyInterval is set for the monthly FrequencyInterval
        if ($FrequencyType -in 16, 'Monthly') {
            # Create the interval to hold the value(s)
            [int]$interval = 0

            # Loop through the array
            foreach ($item in $FrequencyInterval) {
                switch ($item) {
                    { [int]$_ -ge 1 -and [int]$_ -le 31 } { $interval = [int]$item }
                }
            }
        }

        # If the FrequencyInterval is set for the relative monthly FrequencyInterval
        if ($FrequencyType -eq 32) {
            # Create the interval to hold the value(s)
            [int]$interval = 0

            # Loop through the array
            foreach ($item in $FrequencyInterval) {
                switch ($item) {
                    "Sunday" { $interval += 1 }
                    "Monday" { $interval += 2 }
                    "Tuesday" { $interval += 3 }
                    "Wednesday" { $interval += 4 }
                    "Thursday" { $interval += 5 }
                    "Friday" { $interval += 6 }
                    "Saturday" { $interval += 7 }
                    "Day" { $interval += 8 }
                    "Weekday" { $interval += 9 }
                    "WeekendDay" { $interval += 10 }
                    1 { $interval += 1 }
                    2 { $interval += 2 }
                    3 { $interval += 3 }
                    4 { $interval += 4 }
                    5 { $interval += 5 }
                    6 { $interval += 6 }
                    7 { $interval += 7 }
                    8 { $interval += 8 }
                    9 { $interval += 9 }
                    10 { $interval += 10 }
                }
            }
        }

        # Check if the interval is valid for the frequency
        if ($FrequencyType -eq 0) {
            if ($Force) {
                Write-Message -Message "Parameter FrequencyType must be set to at least [Once]. Setting it to 'Once'." -Level Warning
                $FrequencyType = 1
            } else {
                Stop-Function -Message "Parameter FrequencyType must be set to at least [Once]" -Target $SqlInstance
                return
            }
        }

        # Check if the interval is valid for the frequency
        if (($FrequencyType -in 4, 8, 32) -and ($interval -lt 1)) {
            if ($Force) {
                Write-Message -Message "Parameter FrequencyInterval must be provided for a recurring schedule. Setting it to first day of the week." -Level Warning
                $interval = 1
            } else {
                Stop-Function -Message "Parameter FrequencyInterval must be provided for a recurring schedule." -Target $SqlInstance
                return
            }
        }

        # Setup the regex
        $RegexDate = '(?<!\d)(?:(?:(?:1[6-9]|[2-9]\d)?\d{2})(?:(?:(?:0[13578]|1[02])31)|(?:(?:0[1,3-9]|1[0-2])(?:29|30)))|(?:(?:(?:(?:1[6-9]|[2-9]\d)?(?:0[48]|[2468][048]|[13579][26])|(?:(?:16|[2468][048]|[3579][26])00)))0229)|(?:(?:1[6-9]|[2-9]\d)?\d{2})(?:(?:0?[1-9])|(?:1[0-2]))(?:0?[1-9]|1\d|2[0-8]))(?!\d)'
        $RegexTime = '^(?:(?:([01]?\d|2[0-3]))?([0-5]?\d))?([0-5]?\d)$'

        # Check the start date
        if (-not $StartDate -and $Force) {
            $StartDate = Get-Date -Format 'yyyyMMdd'
            Write-Message -Message "Start date was not set. Force is being used. Setting it to $StartDate" -Level Verbose
        } elseif (-not $StartDate) {
            Stop-Function -Message "Please enter a start date or use -Force to use defaults." -Target $SqlInstance
            return
        } elseif ($StartDate -notmatch $RegexDate) {
            Stop-Function -Message "Start date $StartDate needs to be a valid date with format yyyyMMdd" -Target $SqlInstance
            return
        }

        # Check the end date
        if (-not $EndDate -and $Force) {
            $EndDate = '99991231'
            Write-Message -Message "End date was not set. Force is being used. Setting it to $EndDate" -Level Verbose
        } elseif (-not $EndDate) {
            Stop-Function -Message "Please enter an end date or use -Force to use defaults." -Target $SqlInstance
            return
        }

        elseif ($EndDate -notmatch $RegexDate) {
            Stop-Function -Message "End date $EndDate needs to be a valid date with format yyyyMMdd" -Target $SqlInstance
            return
        } elseif ($EndDate -lt $StartDate) {
            Stop-Function -Message "End date $EndDate cannot be before start date $StartDate" -Target $SqlInstance
            return
        }

        # Check the start time
        if (-not $StartTime -and $Force) {
            $StartTime = '000000'
            Write-Message -Message "Start time was not set. Force is being used. Setting it to $StartTime" -Level Verbose
        } elseif (-not $StartTime) {
            Stop-Function -Message "Please enter a start time or use -Force to use defaults." -Target $SqlInstance
            return
        } elseif ($StartTime -notmatch $RegexTime) {
            Stop-Function -Message "Start time $StartTime needs to match between '000000' and '235959'" -Target $SqlInstance
            return
        }

        # Check the end time
        if (-not $EndTime -and $Force) {
            $EndTime = '235959'
            Write-Message -Message "End time was not set. Force is being used. Setting it to $EndTime" -Level Verbose
        } elseif (-not $EndTime) {
            Stop-Function -Message "Please enter an end time or use -Force to use defaults." -Target $SqlInstance
            return
        } elseif ($EndTime -notmatch $RegexTime) {
            Stop-Function -Message "End time $EndTime needs to match between '000000' and '235959'" -Target $SqlInstance
            return
        }

        #Format dates and times
        if ($StartDate) {
            $StartDate = $StartDate.Insert(6, '-').Insert(4, '-')
        }
        if ($EndDate) {
            $EndDate = $EndDate.Insert(6, '-').Insert(4, '-')
        }
        if ($StartTime) {
            $StartTime = $StartTime.Insert(4, ':').Insert(2, ':')
        }
        if ($EndTime) {
            $EndTime = $EndTime.Insert(4, ':').Insert(2, ':')
        }
    }

    process {
        if (Test-FunctionInterrupt) { return }

        foreach ($instance in $SqlInstance) {
            try {
                $server = Connect-DbaInstance -SqlInstance $instance -SqlCredential $SqlCredential
            } catch {
                Stop-Function -Message "Failure" -Category ConnectionError -ErrorRecord $_ -Target $instance -Continue
            }

            # Check if the jobs parameter is set
            if ($Job) {
                # Loop through each of the jobs
                foreach ($j in $Job) {

                    # Check if the job exists
                    if ($Server.JobServer.Jobs.Name -notcontains $j) {
                        Write-Message -Message "Job $j doesn't exists on $instance" -Level Warning
                    } else {
                        # Create the job schedule object
                        try {
                            # Get the job
                            $smoJob = $Server.JobServer.Jobs[$j]

                            # Check if schedule already exists with the same name
                            if ($Server.JobServer.JobSchedules.Name -contains $Schedule) {
                                # Check if force is set which will remove the other schedule
                                if ($Force) {
                                    if ($PSCmdlet.ShouldProcess($instance, "Removing the schedule $Schedule on $instance")) {
                                        # Removing schedule
                                        Remove-DbaAgentSchedule -SqlInstance $instance -SqlCredential $SqlCredential -Schedule $Schedule -Force:$Force -Confirm:$false
                                    }
                                } else {
                                    Stop-Function -Message "Schedule $Schedule already exists for job $j on instance $instance" -Target $instance -ErrorRecord $_ -Continue
                                }
                            }

                            # Create the job schedule
                            $JobSchedule = New-Object Microsoft.SqlServer.Management.Smo.Agent.JobSchedule($smoJob, $Schedule)

                        } catch {
                            Stop-Function -Message "Something went wrong creating the job schedule $Schedule for job $j." -Target $instance -ErrorRecord $_ -Continue
                        }

                        #region job schedule options
                        if ($Disabled) {
                            Write-Message -Message "Setting job schedule to disabled" -Level Verbose
                            $JobSchedule.IsEnabled = $false
                        } else {
                            Write-Message -Message "Setting job schedule to enabled" -Level Verbose
                            $JobSchedule.IsEnabled = $true
                        }

                        if ($interval -ge 0) {
                            Write-Message -Message "Setting job schedule frequency interval to $interval" -Level Verbose
                            $JobSchedule.FrequencyInterval = $interval
                        }

                        if ($FrequencyType -ge 1) {
                            Write-Message -Message "Setting job schedule frequency to $FrequencyType" -Level Verbose
                            $JobSchedule.FrequencyTypes = $FrequencyType
                        }

                        if ($FrequencySubdayType -ge 1) {
                            Write-Message -Message "Setting job schedule frequency subday type to $FrequencySubdayType" -Level Verbose
                            $JobSchedule.FrequencySubDayTypes = $FrequencySubdayType
                        }

                        if ($FrequencySubdayInterval -ge 1) {
                            Write-Message -Message "Setting job schedule frequency subday interval to $FrequencySubdayInterval" -Level Verbose
                            $JobSchedule.FrequencySubDayInterval = $FrequencySubdayInterval
                        }

                        if (($FrequencyRelativeInterval -ge 1) -and ($FrequencyType -eq 32)) {
                            Write-Message -Message "Setting job schedule frequency relative interval to $FrequencyRelativeInterval" -Level Verbose
                            $JobSchedule.FrequencyRelativeIntervals = $FrequencyRelativeInterval
                        }

                        if (($FrequencyRecurrenceFactor -ge 1) -and ($FrequencyType -in 8, 16, 32)) {
                            Write-Message -Message "Setting job schedule frequency recurrence factor to $FrequencyRecurrenceFactor" -Level Verbose
                            $JobSchedule.FrequencyRecurrenceFactor = $FrequencyRecurrenceFactor
                        }

                        if ($StartDate) {
                            Write-Message -Message "Setting job schedule start date to $StartDate" -Level Verbose
                            $JobSchedule.ActiveStartDate = $StartDate
                        }

                        if ($EndDate) {
                            Write-Message -Message "Setting job schedule end date to $EndDate" -Level Verbose
                            $JobSchedule.ActiveEndDate = $EndDate
                        }

                        if ($StartTime) {
                            Write-Message -Message "Setting job schedule start time to $StartTime" -Level Verbose
                            $JobSchedule.ActiveStartTimeOfDay = $StartTime
                        }

                        if ($EndTime) {
                            Write-Message -Message "Setting job schedule end time to $EndTime" -Level Verbose
                            $JobSchedule.ActiveEndTimeOfDay = $EndTime
                        }
                        #endregion job schedule options

                        # Create the schedule
                        if ($PSCmdlet.ShouldProcess($SqlInstance, "Adding the schedule $Schedule to job $j on $instance")) {
                            try {
                                Write-Message -Message "Adding the schedule $Schedule to job $j" -Level Verbose
                                #$JobSchedule
                                $JobSchedule.Create()

                                Write-Message -Message "Job schedule created with UID $($JobSchedule.ScheduleUid)" -Level Verbose
                            } catch {
                                Stop-Function -Message "Something went wrong adding the schedule" -Target $instance -ErrorRecord $_ -Continue

                            }

                            Add-TeppCacheItem -SqlInstance $server -Type schedule -Name $Schedule

                            # Output the job schedule
                            Get-DbaAgentSchedule -SqlInstance $server -ScheduleUid $JobSchedule.ScheduleUid
                        }
                    }
                } # foreach object job
            } # end if job
            else {
                # Create the schedule
                $JobSchedule = New-Object Microsoft.SqlServer.Management.Smo.Agent.JobSchedule($Server.JobServer, $Schedule)

                #region job schedule options
                if ($Disabled) {
                    Write-Message -Message "Setting job schedule to disabled" -Level Verbose
                    $JobSchedule.IsEnabled = $false
                } else {
                    Write-Message -Message "Setting job schedule to enabled" -Level Verbose
                    $JobSchedule.IsEnabled = $true
                }

                if ($interval -ge 1) {
                    Write-Message -Message "Setting job schedule frequency interval to $interval" -Level Verbose
                    $JobSchedule.FrequencyInterval = $interval
                }

                if ($FrequencyType -ge 1) {
                    Write-Message -Message "Setting job schedule frequency to $FrequencyType" -Level Verbose
                    $JobSchedule.FrequencyTypes = $FrequencyType
                }

                if ($FrequencySubdayType -ge 1) {
                    Write-Message -Message "Setting job schedule frequency subday type to $FrequencySubdayType" -Level Verbose
                    $JobSchedule.FrequencySubDayTypes = $FrequencySubdayType
                }

                if ($FrequencySubdayInterval -ge 1) {
                    Write-Message -Message "Setting job schedule frequency subday interval to $FrequencySubdayInterval" -Level Verbose
                    $JobSchedule.FrequencySubDayInterval = $FrequencySubdayInterval
                }

                if (($FrequencyRelativeInterval -ge 1) -and ($FrequencyType -eq 32)) {
                    Write-Message -Message "Setting job schedule frequency relative interval to $FrequencyRelativeInterval" -Level Verbose
                    $JobSchedule.FrequencyRelativeIntervals = $FrequencyRelativeInterval
                }

                if (($FrequencyRecurrenceFactor -ge 1) -and ($FrequencyType -in 8, 16, 32)) {
                    Write-Message -Message "Setting job schedule frequency recurrence factor to $FrequencyRecurrenceFactor" -Level Verbose
                    $JobSchedule.FrequencyRecurrenceFactor = $FrequencyRecurrenceFactor
                }

                if ($StartDate) {
                    Write-Message -Message "Setting job schedule start date to $StartDate" -Level Verbose
                    $JobSchedule.ActiveStartDate = $StartDate
                }

                if ($EndDate) {
                    Write-Message -Message "Setting job schedule end date to $EndDate" -Level Verbose
                    $JobSchedule.ActiveEndDate = $EndDate
                }

                if ($StartTime) {
                    Write-Message -Message "Setting job schedule start time to $StartTime" -Level Verbose
                    $JobSchedule.ActiveStartTimeOfDay = $StartTime
                }

                if ($EndTime) {
                    Write-Message -Message "Setting job schedule end time to $EndTime" -Level Verbose
                    $JobSchedule.ActiveEndTimeOfDay = $EndTime
                }

                # Create the schedule
                if ($PSCmdlet.ShouldProcess($SqlInstance, "Adding the schedule $schedule on $instance")) {
                    try {
                        Write-Message -Message "Adding the schedule $JobSchedule on instance $instance" -Level Verbose

                        $JobSchedule.Create()

                        Write-Message -Message "Job schedule created with UID $($JobSchedule.ScheduleUid)" -Level Verbose
                    } catch {
                        Stop-Function -Message "Something went wrong adding the schedule." -Target $instance -ErrorRecord $_ -Continue
                    }

                    Add-TeppCacheItem -SqlInstance $server -Type schedule -Name $Schedule

                    # Output the job schedule
                    Get-DbaAgentSchedule -SqlInstance $server -ScheduleUid $JobSchedule.ScheduleUid
                }
            }
        } # foreach object instance
    } #process

    end {
        if (Test-FunctionInterrupt) { return }
        Write-Message -Message "Finished creating job schedule(s)." -Level Verbose
    }
}
# SIG # Begin signature block
# MIIjYAYJKoZIhvcNAQcCoIIjUTCCI00CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCBNBlorwtYsh72m
# sSLsbjlNUbpeqQGKUO6CyxdT1Z5+o6CCHVkwggUaMIIEAqADAgECAhADBbuGIbCh
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
# BgorBgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCAwvFOM545D+zZNCNwL1TRI918U
# vD2elev07ckuG0UpnzANBgkqhkiG9w0BAQEFAASCAQA/t3RxKKhjns5FdDy1ht7f
# NpOjF7qu/+OHg6hwYmw7M6HZTht0swyTqVFVw5jUcACHuJKZxz52z1xYaU+SP888
# b4ibBXOIV4/voh75WjbejUfv1cjEidZ5qaNKS1Z0jHOHk4R/BAmXq/TRpYaFmcbA
# UVq8Zg7Y7OJBFjt8lIGl3jptKe0EASs26Aa5HjiECf8+Vi3U3oUyjCreuMVFWM2y
# QS+KpkCiIPDe8Z1gjPsZDyNklEA1TC6K9fXetlNgcrUrxijFcFkpwn9/sMEv5pgd
# jvrc6f25Vn+z8dt3kZCGgIFTjMja0B/ZpRHO8d2F9wOW3DWJNLbwIY6K5QGZOhTu
# oYIDIDCCAxwGCSqGSIb3DQEJBjGCAw0wggMJAgEBMHcwYzELMAkGA1UEBhMCVVMx
# FzAVBgNVBAoTDkRpZ2lDZXJ0LCBJbmMuMTswOQYDVQQDEzJEaWdpQ2VydCBUcnVz
# dGVkIEc0IFJTQTQwOTYgU0hBMjU2IFRpbWVTdGFtcGluZyBDQQIQDE1pckuU+jwq
# Sj0pB4A9WjANBglghkgBZQMEAgEFAKBpMBgGCSqGSIb3DQEJAzELBgkqhkiG9w0B
# BwEwHAYJKoZIhvcNAQkFMQ8XDTIyMTExNzA4NTY1MFowLwYJKoZIhvcNAQkEMSIE
# IGNyNkTQRJINuc6fGSZ7LFS4FS9aMJa1jwAkTTd2r221MA0GCSqGSIb3DQEBAQUA
# BIICACxbIuYSw69WjI8aM7nCU5auP6RePaJ3o9tzJpHFQ5lh4NwYTU995QrIyoBq
# rYjZn49FnLQp+W21xvDCyW7qiHFTNvZ31B0mUnsPsSX+TuQ1GYHPRPgtLvJPFZvP
# PHwKNzbmIdeFmf/7sUqjo294Mt6F7YrhDoDTtco7XplJudcCBNkQCelIqYtkMX0g
# 6yjItuO1SCdfHeJ8Qu3Huf8n5gWcyO2bLzsFfp8VIgmQ+5GfVbG9VKLUSYiNlWEJ
# 05WfUKJ8QShz6l1TvHxMneUxTmhap5c6B2aVLtT1tDgGowIlK6vhtPWuSGN+mKK+
# 1/nmdhbuRgm1ATohGwnmDF8HxghXw6fZXug6ipa7m9gl+vH8vYWtfuIWqL1Xu/sb
# Xo9mIcrzO+rbe4WFp+rqzt9c0nCRCOv6qyJY99Hmvx3D/ILxUGsQyKe6SRvrgXBo
# +PXsXOvcu9+ykaNdA+ON27hzPVOrvBs9ahDfOxKah+60/bNI7+s8iSX2K/Azdy4T
# rgRw5KEZYsWLbDuGCEddyZWWlZ07NuFLF4EIlmyvUaHIAxUvyjWsNIP3VamK63VJ
# yVbJz1EV6mAk2oKoBVZ9goc+EQFilyHc4i81//n2YCMR1xMqCE17mCQ7VrcndM5V
# +vTzJodvG9MT+QXz4YiXI9vDSx7ZlsGmXrTAzt7x7cBj8UI4
# SIG # End signature block
