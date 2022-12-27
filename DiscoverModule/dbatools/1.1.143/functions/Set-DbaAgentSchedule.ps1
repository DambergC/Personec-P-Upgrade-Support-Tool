function Set-DbaAgentSchedule {
    <#
    .SYNOPSIS
        Set-DbaAgentSchedule updates a schedule in the msdb database.

    .DESCRIPTION
        Set-DbaAgentSchedule will help update a schedule for a job. It does not attach the schedule to a job.

    .PARAMETER SqlInstance
        The target SQL Server instance or instances. You must have sysadmin access and server version must be SQL Server version 2000 or greater.

    .PARAMETER SqlCredential
        Login to the target instance using alternative credentials. Accepts PowerShell credentials (Get-Credential).

        Windows Authentication, SQL Server Authentication, Active Directory - Password, and Active Directory - Integrated are all supported.

        For MFA support, please use Connect-DbaInstance.

    .PARAMETER Job
        The name of the job that has the schedule.

    .PARAMETER ScheduleName
        The name of the schedule.

    .PARAMETER NewName
        The new name for the schedule.

    .PARAMETER Enabled
        Set the schedule to enabled.

    .PARAMETER Disabled
        Set the schedule to disabled.

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
        Allowed values are 1, 'Once', 'Time', 2, 'Seconds', 'Second', 4, 'Minutes', 'Minute', 8, 'Hours', 'Hour'

    .PARAMETER FrequencySubdayInterval
        The number of subday type periods to occur between each execution of a job.

    .PARAMETER FrequencyRelativeInterval
        A job's occurrence of FrequencyInterval in each month, if FrequencyType is 32 (MonthlyRelative).

    .PARAMETER FrequencyRecurrenceFactor
        The number of weeks or months between the scheduled execution of a job. FrequencyRecurrenceFactor is used only if FrequencyType is 8, "Weekly", 16, "Monthly", 32 or "MonthlyRelative".

    .PARAMETER StartDate
        The date on which execution of a job can begin.

    .PARAMETER EndDate
        The date on which execution of a job can stop.

    .PARAMETER StartTime
        The time on any day to begin execution of a job. Format HHMMSS / 24 hour clock.
        Example: '010000' for 01:00:00 AM.
        Example: '140000' for 02:00:00 PM.

    .PARAMETER EndTime
        The time on any day to end execution of a job. Format HHMMSS / 24 hour clock.
        Example: '010000' for 01:00:00 AM.
        Example: '140000' for 02:00:00 PM.

    .PARAMETER WhatIf
        Shows what would happen if the command were to run. No actions are actually performed.

    .PARAMETER Confirm
        Prompts you for confirmation before executing any changing operations within the command.

    .PARAMETER EnableException
        By default, when something goes wrong we try to catch it, interpret it and give you a friendly warning message.
        This avoids overwhelming you with "sea of red" exceptions, but is inconvenient because it basically disables advanced scripting.
        Using this switch turns this "nice by default" feature off and enables you to catch exceptions with your own try/catch.

    .PARAMETER Force
        The force parameter will ignore some errors in the parameters and assume defaults.
        It will also remove the any present schedules with the same name for the specific job.

    .NOTES
        Tags: Agent, Job, JobStep
        Author: Sander Stad (@sqlstad, sqlstad.nl)

        Website: https://dbatools.io
        Copyright: (c) 2018 by dbatools, licensed under MIT
        License: MIT https://opensource.org/licenses/MIT

    .LINK
        https://dbatools.io/Set-DbaAgentSchedule

    .EXAMPLE
        PS C:\> Set-DbaAgentSchedule -SqlInstance sql1 -Job Job1 -ScheduleName daily -Enabled

        Changes the schedule for Job1 with the name 'daily' to enabled

    .EXAMPLE
        PS C:\> Set-DbaAgentSchedule -SqlInstance sql1 -Job Job1 -ScheduleName daily -NewName weekly -FrequencyType Weekly -FrequencyInterval Monday, Wednesday, Friday

        Changes the schedule for Job1 with the name daily to have a new name weekly

    .EXAMPLE
        PS C:\> Set-DbaAgentSchedule -SqlInstance sql1 -Job Job1, Job2, Job3 -ScheduleName daily -StartTime '230000'

        Changes the start time of the schedule for Job1 to 11 PM for multiple jobs

    .EXAMPLE
        PS C:\> Set-DbaAgentSchedule -SqlInstance sql1, sql2, sql3 -Job Job1 -ScheduleName daily -Enabled

        Changes the schedule for Job1 with the name daily to enabled on multiple servers

    .EXAMPLE
        PS C:\> sql1, sql2, sql3 | Set-DbaAgentSchedule -Job Job1 -ScheduleName daily -Enabled

        Changes the schedule for Job1 with the name 'daily' to enabled on multiple servers using pipe line

    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = "Low")]
    param (
        [parameter(Mandatory, ValueFromPipeline)]
        [DbaInstanceParameter[]]$SqlInstance,
        [PSCredential]$SqlCredential,
        [Parameter(Mandatory, ValueFromPipeline)]
        [ValidateNotNullOrEmpty()]
        [object[]]$Job,
        [Parameter(Mandatory, ValueFromPipeline)]
        [ValidateNotNullOrEmpty()]
        [string]$ScheduleName,
        [string]$NewName,
        [switch]$Enabled,
        [switch]$Disabled,
        [ValidateSet('Once', 'OneTime', 'Daily', 'Weekly', 'Monthly', 'MonthlyRelative', 'AgentStart', 'AutoStart', 'IdleComputer', 'OnIdle', 1, 4, 8, 16, 32, 64, 128)]
        [object]$FrequencyType,
        [object[]]$FrequencyInterval,
        [ValidateSet(1, 'Once', 'Time', 2, 'Seconds', 'Second', 4, 'Minutes', 'Minute', 8, 'Hours', 'Hour')]
        [object]$FrequencySubdayType,
        [int]$FrequencySubdayInterval,
        [ValidateSet('Unused', 'First', 'Second', 'Third', 'Fourth', 'Last')]
        [object]$FrequencyRelativeInterval,
        [int]$FrequencyRecurrenceFactor,
        [string]$StartDate,
        [string]$EndDate,
        [string]$StartTime,
        [string]$EndTime,
        [switch]$EnableException,
        [switch]$Force
    )

    begin {
        if ($Force) { $ConfirmPreference = 'none' }

        # Check of the FrequencyType value is of type string and set the integer value
        if ($FrequencyType -notin 1, 4, 8, 16, 32, 64, 128) {
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
        }

        # Check of the FrequencySubdayType value is of type string and set the integer value
        if ($FrequencySubdayType -notin 0, 1, 2, 4, 8) {
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
                default { 0 }
            }
        }

        # Check if the interval for daily frequency is valid
        if (($FrequencyType -in 4) -and ($FrequencyInterval -lt 1 -or $FrequencyInterval -ge 365) -and (-not ($FrequencyInterval -eq "EveryDay")) -and (-not $Force)) {
            Stop-Function -Message "The daily frequency type requires a frequency interval to be between 1 and 365 or 'EveryDay'." -Target $SqlInstance
            return
        }

        # Check if the recurrence factor is set for weekly or monthly interval
        if ($FrequencyRecurrenceFactor -and ($FrequencyType -in 8, 16) -and $FrequencyRecurrenceFactor -lt 1) {
            if ($Force) {
                $FrequencyRecurrenceFactor = 1
                Write-Message -Message "Recurrence factor not set for weekly or monthly interval. Setting it to $FrequencyRecurrenceFactor." -Level Verbose
            } else {
                Stop-Function -Message "The recurrence factor $FrequencyRecurrenceFactor needs to be at least on when using a weekly or monthly interval." -Target $SqlInstance
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

        # Check of the FrequencyInterval value is of type string and set the integer value
        if (($null -ne $FrequencyType)) {
            # Create the interval to hold the value(s)
            [int]$Interval = 0

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
                # Loop through the array
                foreach ($Item in $FrequencyInterval) {
                    switch ($Item) {
                        "Sunday" { $Interval += 1 }
                        "Monday" { $Interval += 2 }
                        "Tuesday" { $Interval += 4 }
                        "Wednesday" { $Interval += 8 }
                        "Thursday" { $Interval += 16 }
                        "Friday" { $Interval += 32 }
                        "Saturday" { $Interval += 64 }
                        "Weekdays" { $Interval = 62 }
                        "Weekend" { $Interval = 65 }
                        "EveryDay" { $Interval = 127 }
                        1 { $Interval += 1 }
                        2 { $Interval += 2 }
                        4 { $Interval += 4 }
                        8 { $Interval += 8 }
                        16 { $Interval += 16 }
                        32 { $Interval += 32 }
                        64 { $Interval += 64 }
                        62 { $Interval = 62 }
                        65 { $Interval = 65 }
                        127 { $Interval = 127 }
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
            if ($FrequencyType -in 32, 'MonthlyRelative') {
                # Loop through the array
                foreach ($Item in $FrequencyInterval) {
                    switch ($Item) {
                        "Sunday" { $Interval += 1 }
                        "Monday" { $Interval += 2 }
                        "Tuesday" { $Interval += 3 }
                        "Wednesday" { $Interval += 4 }
                        "Thursday" { $Interval += 5 }
                        "Friday" { $Interval += 6 }
                        "Saturday" { $Interval += 7 }
                        "Day" { $Interval += 8 }
                        "Weekday" { $Interval += 9 }
                        "WeekendDay" { $Interval += 10 }
                        1 { $Interval += 1 }
                        2 { $Interval += 2 }
                        3 { $Interval += 3 }
                        4 { $Interval += 4 }
                        5 { $Interval += 5 }
                        6 { $Interval += 6 }
                        7 { $Interval += 7 }
                        8 { $Interval += 8 }
                        9 { $Interval += 9 }
                        10 { $Interval += 10 }
                    }
                }
            }
        }

        # Check of the relative FrequencyInterval value is of type string and set the integer value
        if (($FrequencyRelativeInterval -notin 1, 2, 4, 8, 16) -and ($null -ne $FrequencyRelativeInterval)) {
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
        }

        # Setup the regex
        $RegexDate = '(?<!\d)(?:(?:(?:1[6-9]|[2-9]\d)?\d{2})(?:(?:(?:0[13578]|1[02])31)|(?:(?:0[1,3-9]|1[0-2])(?:29|30)))|(?:(?:(?:(?:1[6-9]|[2-9]\d)?(?:0[48]|[2468][048]|[13579][26])|(?:(?:16|[2468][048]|[3579][26])00)))0229)|(?:(?:1[6-9]|[2-9]\d)?\d{2})(?:(?:0?[1-9])|(?:1[0-2]))(?:0?[1-9]|1\d|2[0-8]))(?!\d)'
        $RegexTime = '^(?:(?:([01]?\d|2[0-3]))?([0-5]?\d))?([0-5]?\d)$'

        # Check the start date
        if ($StartDate -and ($StartDate -notmatch $RegexDate)) {
            Stop-Function -Message "Start date $StartDate needs to be a valid date with format yyyyMMdd" -Target $SqlInstance
            return
        }

        # Check the end date
        if ($EndDate -and ($EndDate -notmatch $RegexDate)) {
            Stop-Function -Message "End date $EndDate needs to be a valid date with format yyyyMMdd" -Target $SqlInstance
            return
        } elseif ($EndDate -lt $StartDate) {
            Stop-Function -Message "End date $EndDate cannot be before start date $StartDate" -Target $SqlInstance
            return
        }

        # Check the start time
        if ($StartTime -and ($StartTime -notmatch $RegexTime)) {
            Stop-Function -Message "Start time $StartTime needs to match between '000000' and '235959'" -Target $SqlInstance
            return
        }

        # Check the end time
        if ($EndTime -and ($EndTime -notmatch $RegexTime)) {
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

            foreach ($j in $Job) {
                # Check if the job exists
                if ($server.JobServer.Jobs.Name -notcontains $j) {
                    Write-Message -Message "Job $j doesn't exists on $instance" -Level Warning
                } else {
                    # Check if the job schedule exists
                    if ($server.JobServer.Jobs[$j].JobSchedules.Name -notcontains $ScheduleName) {
                        Stop-Function -Message "Schedule $ScheduleName doesn't exists for job $j on $instance" -Target $instance -Continue
                    } else {
                        # Get the job schedule
                        # If for some reason the there are multiple schedules with the same name, the first on is chosen
                        $JobSchedule = $server.JobServer.Jobs[$j].JobSchedules[$ScheduleName][0]

                        # Set the frequency interval to make up for newly created schedules without an interval
                        if ($JobSchedule.FrequencyInterval -eq 0 -and $Interval -lt 1) {
                            $Interval = 1
                        }

                        #region job step options
                        # Setting the options for the job schedule
                        if ($NewName) {
                            if ($Pscmdlet.ShouldProcess($server, "Setting job schedule $ScheduleName Name to $NewName")) {
                                $JobSchedule.Rename($NewName)
                            }
                        }

                        if ($Enabled) {
                            Write-Message -Message "Setting job schedule to enabled for schedule $ScheduleName" -Level Verbose
                            $JobSchedule.IsEnabled = $true
                        }

                        if ($Disabled) {
                            Write-Message -Message "Setting job schedule to disabled for schedule $ScheduleName" -Level Verbose
                            $JobSchedule.IsEnabled = $false
                        }

                        if ($FrequencyType -ge 1) {
                            Write-Message -Message "Setting job schedule frequency to $FrequencyType for schedule $ScheduleName" -Level Verbose
                            $JobSchedule.FrequencyTypes = $FrequencyType
                        }

                        if ($Interval -ge 1) {
                            Write-Message -Message "Setting job schedule frequency interval to $Interval for schedule $ScheduleName" -Level Verbose
                            $JobSchedule.FrequencyInterval = $Interval
                        }

                        if ($FrequencySubdayType -ge 1) {
                            Write-Message -Message "Setting job schedule frequency subday type to $FrequencySubdayType for schedule $ScheduleName" -Level Verbose
                            $JobSchedule.FrequencySubDayTypes = $FrequencySubdayType
                        }

                        if ($FrequencySubdayInterval -ge 1) {
                            Write-Message -Message "Setting job schedule frequency subday interval to $FrequencySubdayInterval for schedule $ScheduleName" -Level Verbose
                            $JobSchedule.FrequencySubDayInterval = $FrequencySubdayInterval
                        }

                        if (($FrequencyRelativeInterval -ge 1) -and ($FrequencyType -eq 32)) {
                            Write-Message -Message "Setting job schedule frequency relative interval to $FrequencyRelativeInterval for schedule $ScheduleName" -Level Verbose
                            $JobSchedule.FrequencyRelativeIntervals = $FrequencyRelativeInterval
                        }

                        if (($FrequencyRecurrenceFactor -ge 1) -and ($FrequencyType -in 8, 16, 32)) {
                            Write-Message -Message "Setting job schedule frequency recurrence factor to $FrequencyRecurrenceFactor for schedule $ScheduleName" -Level Verbose
                            $JobSchedule.FrequencyRecurrenceFactor = $FrequencyRecurrenceFactor
                        }

                        if ($StartDate) {
                            Write-Message -Message "Setting job schedule start date to $StartDate for schedule $ScheduleName" -Level Verbose
                            $JobSchedule.ActiveStartDate = $StartDate
                        }

                        if ($EndDate) {
                            Write-Message -Message "Setting job schedule end date to $EndDate for schedule $ScheduleName" -Level Verbose
                            $JobSchedule.ActiveEndDate = $EndDate
                        }

                        if ($StartTime) {
                            Write-Message -Message "Setting job schedule start time to $StartTime for schedule $ScheduleName" -Level Verbose
                            $JobSchedule.ActiveStartTimeOfDay = $StartTime
                        }

                        if ($EndTime) {
                            Write-Message -Message "Setting job schedule end time to $EndTime for schedule $ScheduleName" -Level Verbose
                            $JobSchedule.ActiveEndTimeOfDay = $EndTime
                        }
                        #endregion job step options

                        # Execute the query
                        if ($PSCmdlet.ShouldProcess($instance, "Committing changes for schedule $ScheduleName for job $j on $instance")) {
                            try {
                                # Excute the query and save the result
                                Write-Message -Message "Committing changes for schedule $ScheduleName for job $j" -Level Verbose

                                $JobSchedule.Alter()

                                # Return updated schedule
                                Get-DbaAgentSchedule -SqlInstance $server -ScheduleUid $JobSchedule.ScheduleUid
                            } catch {
                                Stop-Function -Message "Something went wrong changing the schedule" -Target $instance -ErrorRecord $_ -Continue
                                return
                            }
                        }
                    }
                }
            } # foreach object job
        } # foreach object instance
    } # process

    end {
        if (Test-FunctionInterrupt) { return }
        Write-Message -Message "Finished changing the job schedule(s)" -Level Verbose
    }
}
# SIG # Begin signature block
# MIIjYAYJKoZIhvcNAQcCoIIjUTCCI00CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCC0XlVzoKQhyJ3G
# a2CLQa1NAVQAbuGbezrxrJ0v+pdhCqCCHVkwggUaMIIEAqADAgECAhADBbuGIbCh
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
# BgorBgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCD/Taa34IfR7DwCsbCXstBXAZcT
# Iheg3dAKaBUAXfpqSjANBgkqhkiG9w0BAQEFAASCAQAJSz3R20LZX9PQYfPHI/KZ
# kDiBPpiMvEFkZlLDHZJ4hPO+GjEbxPloPM3B5MzNM9XE01nWWPQvkiC6JzCSEDD4
# cRslZCJrMg8oCqFum04+hFpJxWEVHxAtliQ3k7GeqvUgP5e3SaQc3p8HB9zTv5Bo
# Ajd5xBN0tJ7Jhn9AjRDTcA0S4icELa1gb5zAoEU0kHWrJCqVw9SJEmOKI+T33Wlm
# y6I6gGHg6FBRXm3GoEHQKSZ/58J7De2ExkdW727iaNcIH1EBMlupgVcxxIEbgVli
# +keMwQ+UhA8QckWPV8gXp/yJQoWNIlugj9j4YVBjZ1BKbFXam9ElVNhCWA2dw3x3
# oYIDIDCCAxwGCSqGSIb3DQEJBjGCAw0wggMJAgEBMHcwYzELMAkGA1UEBhMCVVMx
# FzAVBgNVBAoTDkRpZ2lDZXJ0LCBJbmMuMTswOQYDVQQDEzJEaWdpQ2VydCBUcnVz
# dGVkIEc0IFJTQTQwOTYgU0hBMjU2IFRpbWVTdGFtcGluZyBDQQIQDE1pckuU+jwq
# Sj0pB4A9WjANBglghkgBZQMEAgEFAKBpMBgGCSqGSIb3DQEJAzELBgkqhkiG9w0B
# BwEwHAYJKoZIhvcNAQkFMQ8XDTIyMTExNzA4NTcyOFowLwYJKoZIhvcNAQkEMSIE
# IJXVpT6la/9ctUBlzxij5Ny+G4a1Gujh+/k5yY3Wb2DMMA0GCSqGSIb3DQEBAQUA
# BIICAGREvr76eAWKLm1EqRxXXOkV2MNTAQgB/wybUEs+py3rfUbSHuOGbSD2NPC7
# 8vPa5sPPWDJuDh0CbLcBUzQgeXxcHal/npGSnrfP8i4/K1lYCEInem0+VWvpBW2j
# 8Frdu1ier0uzxkilnXj6WOcng7PiLR6P/JGK6ajXVbW2BHLs1uEKXwjeolWTPh3U
# URPA6U+Hz0hfvsR14YcrzAyg40SY/iacVaXSYJFOFPCkbPJtR5orflg0leG7ikFM
# s/YjeLkGk+ewuhIZ7Qfx6TnZm+1SVExRtQAVXm1Lzoh40WNIKtXoWV4CKU6fJlsN
# AKP5QA3aybFbBKDtDG9KNzoC/AwvZ+6sRNN3vKdSuQF7rOLAjGXwLqjkyW7YY0E5
# ZM/nz2zVBY57ZOLmHHC5R1yCjgAb+GEYgar/1PKI7I63z5UQ1LVMTyliAfUECbLr
# KElOEO8IE/r+34MkiDzkJc3+Qc8se1QCLsTOJPYQgUlaPA2ppuGf+SCddbvQtCqU
# 0oQLpjwkBvvi9+Wp2EDvTfcIEy41gaJgt10j6+ZUPtNDAjI56qn1t5CdSU3TMzju
# z5NC7vAl8CjsYdg1/Swq63aaCZbHHEDVY2346KHLybGtBBB34xJcpWe9CLsnwmtM
# fcNrCdzzTxfO8hRBMssCCKbQnG3fNnDkfZAgdnBdE7Uof8Xt
# SIG # End signature block
