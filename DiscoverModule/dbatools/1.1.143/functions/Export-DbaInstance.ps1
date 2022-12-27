function Export-DbaInstance {
    <#
    .SYNOPSIS
        Exports SQL Server *ALL* database restore scripts, logins, database mail profiles/accounts, credentials, SQL Agent objects, linked servers,
        Central Management Server objects, server configuration settings (sp_configure), user objects in systems databases,
        system triggers and backup devices from one SQL Server to another.

    .DESCRIPTION
        Export-DbaInstance consolidates most of the export scripts in dbatools into one command.

        This is useful when you're looking to Export entire instances. It less flexible than using the underlying functions.
        Think of it as an easy button. Unless an -Exclude is specified, it exports:

        All database 'restore from backup' scripts.  Note: if a database does not have a backup the 'restore from backup' script won't be generated.
        All logins.
        All database mail objects.
        All credentials.
        All objects within the Job Server (SQL Agent).
        All linked servers.
        All groups and servers within Central Management Server.
        All SQL Server configuration objects (everything in sp_configure).
        All user objects in system databases.
        All system triggers.
        All system backup devices.
        All Audits.
        All Endpoints.
        All Extended Events.
        All Policy Management objects.
        All Resource Governor objects.
        All Server Audit Specifications.
        All Custom Errors (User Defined Messages).
        All Server Roles.
        All Availability Groups.
        All OLEDB Providers.

        The exported files are written to a folder with a naming convention of "machinename$instance-yyyyMMddHHmmss".

        This command supports the following use cases related to the output files:

        1. Export files to a new timestamped folder. This is the default behavior and results in a simple historical archive within the local filesystem.
        2. Export files to an existing folder and overwrite pre-existing files. This can be accomplished using the -Force parameter.
        This results in a single folder location with the latest exported files. These files can then be checked into a source control system if needed.

        For more granular control, please use one of the -Exclude parameters and use the other functions available within the dbatools module.

    .PARAMETER SqlInstance
        The target SQL Server instances

    .PARAMETER SqlCredential
        Login to the target instance using alternative credentials. Accepts PowerShell credentials (Get-Credential).

        Windows Authentication, SQL Server Authentication, Active Directory - Password, and Active Directory - Integrated are all supported.

        For MFA support, please use Connect-DbaInstance.

    .PARAMETER Credential
        Alternative Windows credentials for exporting Linked Servers and Credentials. Accepts credential objects (Get-Credential)

    .PARAMETER Path
        Specifies the directory where the file or files will be exported.

    .PARAMETER WithReplace
        If this switch is used, databases are restored from backup using WITH REPLACE. This is useful if you want to stage some complex file paths.

    .PARAMETER NoRecovery
        If this switch is used, databases will be left in the No Recovery state to enable further backups to be added.

    .PARAMETER AzureCredential
        Optional AzureCredential to connect to blob storage holding the backups

    .PARAMETER IncludeDbMasterKey
        Exports the db master key then logs into the server to copy it to the $Path

    .PARAMETER Exclude
        Exclude one or more objects to export

        Databases
        Logins
        AgentServer
        Credentials
        LinkedServers
        SpConfigure
        CentralManagementServer
        DatabaseMail
        SysDbUserObjects
        SystemTriggers
        BackupDevices
        Audits
        Endpoints
        ExtendedEvents
        PolicyManagement
        ResourceGovernor
        ServerAuditSpecifications
        CustomErrors
        ServerRoles
        AvailabilityGroups
        ReplicationSettings
        OleDbProvider

    .PARAMETER BatchSeparator
        Batch separator for scripting output. "GO" by default based on (Get-DbatoolsConfigValue -FullName 'formatting.batchseparator').

    .PARAMETER NoPrefix
        If this switch is used, the scripts will not include prefix information containing creator and datetime.

    .PARAMETER ExcludePassword
        If this switch is used, the scripts will not include passwords for Credentials, LinkedServers or Logins.

    .PARAMETER ScriptingOption
        Add scripting options to scripting output for all objects except Registered Servers and Extended Events.

    .PARAMETER Force
        Overwrite files in the location specified by -Path. Note: The Server Name is used when creating the folder structure.

    .PARAMETER EnableException
        By default, when something goes wrong we try to catch it, interpret it and give you a friendly warning message.
        This avoids overwhelming you with "sea of red" exceptions, but is inconvenient because it basically disables advanced scripting.
        Using this switch turns this "nice by default" feature off and enables you to catch exceptions with your own try/catch.

    .NOTES
        Tags: Export
        Author: Chrissy LeMaire (@cl), netnerds.net

        Website: https://dbatools.io
        Copyright: (c) 2018 by dbatools, licensed under MIT
        License: MIT https://opensource.org/licenses/MIT

    .LINK
        https://dbatools.io/Export-DbaInstance

    .EXAMPLE
        PS C:\> Export-DbaInstance -SqlInstance sqlserver\instance

        All databases, logins, job objects and sp_configure options will be exported from sqlserver\instance to an automatically generated folder name in Documents. For example, %userprofile%\Documents\DbatoolsExport\sqldev1$sqlcluster-20201108140000

    .EXAMPLE
        PS C:\> Export-DbaInstance -SqlInstance sqlcluster -Exclude Databases, Logins -Path C:\dr\sqlcluster

        Exports everything but logins and database restore scripts to a folder such as C:\dr\sqlcluster\sqldev1$sqlcluster-20201108140000

    .EXAMPLE
        PS C:\> Export-DbaInstance -SqlInstance sqlcluster -Path C:\servers\ -NoPrefix

        Exports everything to a folder such as C:\servers\sqldev1$sqlcluster-20201108140000 but scripts will not include prefix information.

    .EXAMPLE
        PS C:\> Export-DbaInstance -SqlInstance sqlcluster -Path C:\servers\ -Force

        Exports everything to a folder such as C:\servers\sqldev1$sqlcluster and will overwrite/refresh existing files in that folder. Note: when the -Force param is used the generated folder name will not include a timestamp. This supports the use case of running Export-DbaInstance on a schedule and writing to the same dir each time.
    #>
    [CmdletBinding()]
    param (
        [parameter(Mandatory, ValueFromPipeline)]
        [DbaInstanceParameter[]]$SqlInstance,
        [PSCredential]$SqlCredential,
        [PSCredential]$Credential,
        [Alias("FilePath")]
        [string]$Path = (Get-DbatoolsConfigValue -FullName 'Path.DbatoolsExport'),
        [switch]$NoRecovery,
        [string]$AzureCredential,
        [switch]$IncludeDbMasterKey,
        [ValidateSet('AgentServer', 'Audits', 'AvailabilityGroups', 'BackupDevices', 'CentralManagementServer', 'Credentials', 'CustomErrors', 'DatabaseMail', 'Databases', 'Endpoints', 'ExtendedEvents', 'LinkedServers', 'Logins', 'PolicyManagement', 'ReplicationSettings', 'ResourceGovernor', 'ServerAuditSpecifications', 'ServerRoles', 'SpConfigure', 'SysDbUserObjects', 'SystemTriggers', 'OleDbProvider')]
        [string[]]$Exclude,
        [string]$BatchSeparator = (Get-DbatoolsConfigValue -FullName 'formatting.batchseparator'),
        [Microsoft.SqlServer.Management.Smo.ScriptingOptions]$ScriptingOption,
        [switch]$NoPrefix = $false,
        [switch]$ExcludePassword,
        [switch]$Force,
        [switch]$EnableException
    )
    begin {
        $null = Test-ExportDirectory -Path $Path

        if (-not $ScriptingOption) {
            $ScriptingOption = New-DbaScriptingOption
        }

        $elapsed = [System.Diagnostics.Stopwatch]::StartNew()
        $started = Get-Date

        $eol = [System.Environment]::NewLine
    }
    process {
        if (Test-FunctionInterrupt) { return }
        foreach ($instance in $SqlInstance) {
            $stepCounter = 0
            try {
                $server = Connect-DbaInstance -SqlInstance $instance -SqlCredential $SqlCredential -MinimumVersion 10
            } catch {
                Stop-Function -Message "Failure" -Category ConnectionError -ErrorRecord $_ -Target $instance -Continue
            }

            if ($Force) {
                # when the caller requests to overwrite existing scripts we won't add the dynamic timestamp to the folder name, so that a pre-existing location can be overwritten.
                $exportPath = Join-DbaPath -Path $Path -Child "$($server.name.replace('\', '$'))"
            } else {
                $timeNow = (Get-Date -UFormat (Get-DbatoolsConfigValue -FullName 'formatting.uformat'))
                $exportPath = Join-DbaPath -Path $Path -Child "$($server.name.replace('\', '$'))-$timeNow"
            }

            # Ensure the export dir exists.
            if (-not (Test-Path $exportPath)) {
                try {
                    $null = New-Item -ItemType Directory -Path $exportPath -Force -ErrorAction Stop
                } catch {
                    Stop-Function -Message "Failure" -ErrorRecord $_
                    return
                }
            }

            if ($Exclude -notcontains 'SpConfigure') {
                Write-Message -Level Verbose -Message "Exporting SQL Server Configuration"
                Write-ProgressHelper -StepNumber ($stepCounter++) -Message "Exporting SQL Server Configuration"
                Export-DbaSpConfigure -SqlInstance $server -FilePath "$exportPath\sp_configure.sql"
                # no call to Get-ChildItem because Export-DbaSpConfigure does it
            }

            if ($Exclude -notcontains 'CustomErrors') {
                Write-Message -Level Verbose -Message "Exporting custom errors (user defined messages)"
                Write-ProgressHelper -StepNumber ($stepCounter++) -Message "Exporting custom errors (user defined messages)"
                $null = Get-DbaCustomError -SqlInstance $server | Export-DbaScript -FilePath "$exportPath\customererrors.sql" -BatchSeparator $BatchSeparator -ScriptingOptionsObject $ScriptingOption -NoPrefix:$NoPrefix
                Get-ChildItem -ErrorAction Ignore -Path "$exportPath\customererrors.sql"
            }

            if ($Exclude -notcontains 'ServerRoles') {
                Write-Message -Level Verbose -Message "Exporting server roles"
                Write-ProgressHelper -StepNumber ($stepCounter++) -Message "Exporting server roles"
                $null = Get-DbaServerRole -SqlInstance $server | Export-DbaScript -FilePath "$exportPath\serverroles.sql" -BatchSeparator $BatchSeparator -ScriptingOptionsObject $ScriptingOption -NoPrefix:$NoPrefix
                Get-ChildItem -ErrorAction Ignore -Path "$exportPath\serverroles.sql"
            }

            if ($Exclude -notcontains 'Credentials') {
                Write-Message -Level Verbose -Message "Exporting SQL credentials"
                Write-ProgressHelper -StepNumber ($stepCounter++) -Message "Exporting SQL credentials"
                $null = Export-DbaCredential -SqlInstance $server -Credential $Credential -FilePath "$exportPath\credentials.sql" -ExcludePassword:$ExcludePassword
                Get-ChildItem -ErrorAction Ignore -Path "$exportPath\credentials.sql"
            }

            if ($Exclude -notcontains 'Logins') {
                Write-Message -Level Verbose -Message "Exporting logins"
                Write-ProgressHelper -StepNumber ($stepCounter++) -Message "Exporting logins"
                Export-DbaLogin -SqlInstance $server -FilePath "$exportPath\logins.sql" -ExcludePassword:$ExcludePassword -NoPrefix:$NoPrefix -WarningAction SilentlyContinue
                # no call to Get-ChildItem because Export-DbaLogin does it
            }

            if ($Exclude -notcontains 'DatabaseMail') {
                Write-Message -Level Verbose -Message "Exporting database mail"
                Write-ProgressHelper -StepNumber ($stepCounter++) -Message "Exporting database mail"
                # The first invocation to Export-DbaScript needs to have -Append:$false so that the previous file contents are discarded. Otherwise, the file would end up with duplicate SQL.
                # The subsequent calls to Export-DbaScript need to have -Append:$true because this is a multi-step export and the objects are written to the same file.
                $null = Get-DbaDbMailConfig -SqlInstance $server | Export-DbaScript -FilePath "$exportPath\dbmail.sql" -Append:$false -BatchSeparator $BatchSeparator -ScriptingOptionsObject $ScriptingOption -NoPrefix:$NoPrefix
                $null = Get-DbaDbMailAccount -SqlInstance $server | Export-DbaScript -FilePath "$exportPath\dbmail.sql" -Append:$true -BatchSeparator $BatchSeparator -ScriptingOptionsObject $ScriptingOption -NoPrefix:$NoPrefix
                $null = Get-DbaDbMailProfile -SqlInstance $server | Export-DbaScript -FilePath "$exportPath\dbmail.sql" -Append:$true -BatchSeparator $BatchSeparator -ScriptingOptionsObject $ScriptingOption -NoPrefix:$NoPrefix
                $null = Get-DbaDbMailServer -SqlInstance $server | Export-DbaScript -FilePath "$exportPath\dbmail.sql" -Append:$true -BatchSeparator $BatchSeparator -ScriptingOptionsObject $ScriptingOption -NoPrefix:$NoPrefix

                Get-ChildItem -ErrorAction Ignore -Path "$exportPath\dbmail.sql"
            }

            if ($Exclude -notcontains 'CentralManagementServer') {
                Write-Message -Level Verbose -Message "Exporting Central Management Server"
                Write-ProgressHelper -StepNumber ($stepCounter++) -Message "Exporting Central Management Server"
                $outputFilePath = "$exportPath\regserver.xml"
                $null = Export-DbaRegServer -SqlInstance $server -FilePath $outputFilePath -Overwrite:$Force
                Get-ChildItem -ErrorAction Ignore -Path $outputFilePath
            }

            if ($Exclude -notcontains 'BackupDevices') {
                Write-Message -Level Verbose -Message "Exporting Backup Devices"
                Write-ProgressHelper -StepNumber ($stepCounter++) -Message "Exporting Backup Devices"
                $null = Get-DbaBackupDevice -SqlInstance $server | Export-DbaScript -FilePath "$exportPath\backupdevices.sql" -BatchSeparator $BatchSeparator -ScriptingOptionsObject $ScriptingOption -NoPrefix:$NoPrefix
                Get-ChildItem -ErrorAction Ignore -Path "$exportPath\backupdevices.sql"
            }

            if ($Exclude -notcontains 'LinkedServers') {
                Write-Message -Level Verbose -Message "Exporting linked servers"
                Write-ProgressHelper -StepNumber ($stepCounter++) -Message "Exporting linked servers"
                Export-DbaLinkedServer -SqlInstance $server -FilePath "$exportPath\linkedservers.sql" -Credential $Credential -ExcludePassword:$ExcludePassword
                # no call to Get-ChildItem because Export-DbaLinkedServer does it
            }

            if ($Exclude -notcontains 'SystemTriggers') {
                Write-Message -Level Verbose -Message "Exporting System Triggers"
                Write-ProgressHelper -StepNumber ($stepCounter++) -Message "Exporting System Triggers"
                $null = Get-DbaInstanceTrigger -SqlInstance $server | Export-DbaScript -FilePath "$exportPath\servertriggers.sql" -BatchSeparator $BatchSeparator -ScriptingOptionsObject $ScriptingOption -NoPrefix:$NoPrefix
                $triggers = Get-Content -Path "$exportPath\servertriggers.sql" -Raw -ErrorAction Ignore
                if ($triggers) {
                    $triggers = $triggers.ToString() -replace 'CREATE TRIGGER', "$BatchSeparator$($eol)CREATE TRIGGER"
                    $triggers = $triggers.ToString() -replace 'ENABLE TRIGGER', "$BatchSeparator$($eol)ENABLE TRIGGER"
                    $null = $triggers | Set-Content -Path "$exportPath\servertriggers.sql" -Force
                    Get-ChildItem -ErrorAction Ignore -Path "$exportPath\servertriggers.sql"
                }
            }

            if ($Exclude -notcontains 'Databases') {
                Write-Message -Level Verbose -Message "Exporting database restores"
                Write-ProgressHelper -StepNumber ($stepCounter++) -Message "Exporting database restores"
                Get-DbaDbBackupHistory -SqlInstance $server -Last -WarningAction SilentlyContinue | Restore-DbaDatabase -SqlInstance $server -NoRecovery:$NoRecovery -WithReplace -OutputScriptOnly -WarningAction SilentlyContinue -AzureCredential $AzureCredential | Out-File -FilePath "$exportPath\databases.sql"
                Get-ChildItem -ErrorAction Ignore -Path "$exportPath\databases.sql"
            }

            if ($Exclude -notcontains 'Audits') {
                Write-Message -Level Verbose -Message "Exporting Audits"
                Write-ProgressHelper -StepNumber ($stepCounter++) -Message "Exporting Audits"
                $null = Get-DbaInstanceAudit -SqlInstance $server | Export-DbaScript -FilePath "$exportPath\audits.sql" -BatchSeparator $BatchSeparator -ScriptingOptionsObject $ScriptingOption -NoPrefix:$NoPrefix
                Get-ChildItem -ErrorAction Ignore -Path "$exportPath\audits.sql"
            }

            if ($Exclude -notcontains 'ServerAuditSpecifications') {
                Write-Message -Level Verbose -Message "Exporting Server Audit Specifications"
                Write-ProgressHelper -StepNumber ($stepCounter++) -Message "Exporting Server Audit Specifications"
                $null = Get-DbaInstanceAuditSpecification -SqlInstance $server | Export-DbaScript -FilePath "$exportPath\auditspecs.sql" -BatchSeparator $BatchSeparator -ScriptingOptionsObject $ScriptingOption -NoPrefix:$NoPrefix
                Get-ChildItem -ErrorAction Ignore -Path "$exportPath\auditspecs.sql"
            }

            if ($Exclude -notcontains 'Endpoints') {
                Write-Message -Level Verbose -Message "Exporting Endpoints"
                Write-ProgressHelper -StepNumber ($stepCounter++) -Message "Exporting Endpoints"
                $null = Get-DbaEndpoint -SqlInstance $server | Where-Object IsSystemObject -EQ $false | Export-DbaScript -FilePath "$exportPath\endpoints.sql" -BatchSeparator $BatchSeparator -ScriptingOptionsObject $ScriptingOption -NoPrefix:$NoPrefix
                Get-ChildItem -ErrorAction Ignore -Path "$exportPath\endpoints.sql"
            }

            if ($Exclude -notcontains 'PolicyManagement' -and $PSVersionTable.PSEdition -eq "Core") {
                Write-Message -Level Verbose -Message "Skipping Policy Management -- not supported by PowerShell Core"
            }
            if ($Exclude -notcontains 'PolicyManagement' -and $PSVersionTable.PSEdition -ne "Core") {
                Write-Message -Level Verbose -Message "Exporting Policy Management"
                Write-ProgressHelper -StepNumber ($stepCounter++) -Message "Exporting Policy Management"

                $outputFilePath = "$exportPath\policymanagement.sql"
                $scriptText = ""
                $policyObjects = @()

                # the policy objects are a different set of classes and are not compatible with the SMO object usage in Export-DbaScript

                $policyObjects += Get-DbaPbmCondition -SqlInstance $server
                $policyObjects += Get-DbaPbmObjectSet -SqlInstance $server
                $policyObjects += Get-DbaPbmPolicy -SqlInstance $server

                foreach ($policyObject in $policyObjects) {
                    $tsqlScript = $policyObject.ScriptCreate()
                    $scriptText += $tsqlScript.GetScript() + "$eol$BatchSeparator$eol$eol"
                }

                Set-Content -Path $outputFilePath -Value $scriptText

                Get-ChildItem -ErrorAction Ignore -Path "$exportPath\policymanagement.sql"
            }

            if ($Exclude -notcontains 'ResourceGovernor') {
                Write-Message -Level Verbose -Message "Exporting Resource Governor"
                Write-ProgressHelper -StepNumber ($stepCounter++) -Message "Exporting Resource Governor"
                # The first invocation to Export-DbaScript needs to have -Append:$false so that the previous file contents are discarded. Otherwise, the file would end up with duplicate SQL.
                # The subsequent calls to Export-DbaScript need to have -Append:$true because this is a multi-step export and the objects are written to the same file.
                $null = Get-DbaRgClassifierFunction -SqlInstance $server | Export-DbaScript -FilePath "$exportPath\resourcegov.sql" -Append:$false -BatchSeparator $BatchSeparator -ScriptingOptionsObject $ScriptingOption -NoPrefix:$NoPrefix
                $null = Get-DbaRgResourcePool -SqlInstance $server | Where-Object Name -NotIn 'default', 'internal' | Export-DbaScript -FilePath "$exportPath\resourcegov.sql" -Append:$true -BatchSeparator $BatchSeparator -ScriptingOptionsObject $ScriptingOption -NoPrefix:$NoPrefix
                $null = Get-DbaRgWorkloadGroup -SqlInstance $server | Where-Object Name -NotIn 'default', 'internal' | Export-DbaScript -FilePath "$exportPath\resourcegov.sql" -Append:$true -BatchSeparator $BatchSeparator -ScriptingOptionsObject $ScriptingOption -NoPrefix:$NoPrefix
                $null = Get-DbaResourceGovernor -SqlInstance $server | Export-DbaScript -FilePath "$exportPath\resourcegov.sql" -Append:$true -BatchSeparator $BatchSeparator -ScriptingOptionsObject $ScriptingOption -NoPrefix:$NoPrefix
                Get-ChildItem -ErrorAction Ignore -Path "$exportPath\resourcegov.sql"
            }

            if ($Exclude -notcontains 'ExtendedEvents') {
                Write-Message -Level Verbose -Message "Exporting Extended Events"
                Write-ProgressHelper -StepNumber ($stepCounter++) -Message "Exporting Extended Events"
                $null = Get-DbaXESession -SqlInstance $server | Export-DbaXESession -FilePath "$exportPath\extendedevents.sql" -BatchSeparator $BatchSeparator -NoPrefix:$NoPrefix
                Get-ChildItem -ErrorAction Ignore -Path "$exportPath\extendedevents.sql"
            }

            if ($Exclude -notcontains 'AgentServer') {
                Write-Message -Level Verbose -Message "Exporting job server"

                Write-ProgressHelper -StepNumber ($stepCounter++) -Message "Exporting job server"
                # The first invocation to Export-DbaScript needs to have -Append:$false so that the previous file contents are discarded. Otherwise, the file would end up with duplicate SQL.
                # The subsequent calls to Export-DbaScript need to have -Append:$true because this is a multi-step export and the objects are written to the same file.
                $null = Get-DbaAgentJobCategory -SqlInstance $server | Export-DbaScript -FilePath "$exportPath\sqlagent.sql" -Append:$false -BatchSeparator $BatchSeparator -ScriptingOptionsObject $ScriptingOption -NoPrefix:$NoPrefix
                $null = Get-DbaAgentOperator -SqlInstance $server | Export-DbaScript -FilePath "$exportPath\sqlagent.sql" -Append:$true -BatchSeparator $BatchSeparator -ScriptingOptionsObject $ScriptingOption -NoPrefix:$NoPrefix
                $null = Get-DbaAgentAlert -SqlInstance $server | Export-DbaScript -FilePath "$exportPath\sqlagent.sql" -Append:$true -BatchSeparator $BatchSeparator -ScriptingOptionsObject $ScriptingOption -NoPrefix:$NoPrefix
                $null = Get-DbaAgentProxy -SqlInstance $server | Export-DbaScript -FilePath "$exportPath\sqlagent.sql" -Append:$true -BatchSeparator $BatchSeparator -ScriptingOptionsObject $ScriptingOption -NoPrefix:$NoPrefix
                $null = Get-DbaAgentSchedule -SqlInstance $server | Export-DbaScript -FilePath "$exportPath\sqlagent.sql" -Append:$true -BatchSeparator $BatchSeparator -ScriptingOptionsObject $ScriptingOption -NoPrefix:$NoPrefix
                $null = Get-DbaAgentJob -SqlInstance $server | Export-DbaScript -FilePath "$exportPath\sqlagent.sql" -Append:$true -BatchSeparator $BatchSeparator -ScriptingOptionsObject $ScriptingOption -NoPrefix:$NoPrefix
                Get-ChildItem -ErrorAction Ignore -Path "$exportPath\sqlagent.sql"
            }

            if ($Exclude -notcontains 'ReplicationSettings') {
                Write-Message -Level Verbose -Message "Exporting replication settings"
                Write-ProgressHelper -StepNumber ($stepCounter++) -Message "Exporting replication settings"

                try {
                    $null = Export-DbaRepServerSetting -SqlInstance $instance -SqlCredential $SqlCredential -FilePath "$exportPath\replication.sql" -EnableException
                    Get-ChildItem -ErrorAction Ignore -Path "$exportPath\replication.sql"
                } catch {
                    Write-Message -Level Verbose -Message "Replication failed, skipping"
                }
            }

            if ($Exclude -notcontains 'SysDbUserObjects') {
                Write-Message -Level Verbose -Message "Exporting user objects in system databases (this can take a minute)."
                Write-ProgressHelper -StepNumber ($stepCounter++) -Message "Exporting user objects in system databases (this can take a minute)."
                $outputFile = "$exportPath\userobjectsinsysdbs.sql"
                $sysDbUserObjects = Export-DbaSysDbUserObject -SqlInstance $server -BatchSeparator $BatchSeparator -NoPrefix:$NoPrefix -ScriptingOptionsObject $ScriptingOption -PassThru
                Set-Content -Path $outputFile -Value $sysDbUserObjects # this approach is needed because -Append is used in Export-DbaSysDbUserObject.ps1
                Get-ChildItem -ErrorAction Ignore -Path $outputFile
            }

            if ($Exclude -notcontains 'AvailabilityGroups') {
                Write-Message -Level Verbose -Message "Exporting availability group"
                Write-ProgressHelper -StepNumber ($stepCounter++) -Message "Exporting availability groups"
                $null = Get-DbaAvailabilityGroup -SqlInstance $server -WarningAction SilentlyContinue | Export-DbaScript -FilePath "$exportPath\AvailabilityGroups.sql" -BatchSeparator $BatchSeparator -NoPrefix:$NoPrefix -ScriptingOptionsObject $ScriptingOption
                Get-ChildItem -ErrorAction Ignore -Path "$exportPath\AvailabilityGroups.sql"
            }

            if ($Exclude -notcontains 'OleDbProvider') {
                Write-Message -Level Verbose -Message "Exporting OLEDB Providers"
                Write-ProgressHelper -StepNumber ($stepCounter++) -Message "Exporting OLEDB Providers"
                $null = Get-DbaOleDbProvider -SqlInstance $server -WarningAction SilentlyContinue | Export-DbaScript -FilePath "$exportPath\OleDbProvider.sql" -BatchSeparator $BatchSeparator -NoPrefix:$NoPrefix -ScriptingOptionsObject $ScriptingOption
                Get-ChildItem -ErrorAction Ignore -Path "$exportPath\oledbprovider.sql"
            }


            Write-Progress -Activity "Performing Instance Export for $instance" -Completed
        }
    }
    end {
        $totalTime = ($elapsed.Elapsed.toString().Split(".")[0])
        Write-Message -Level Verbose -Message "SQL Server export complete."
        Write-Message -Level Verbose -Message "Export started: $started"
        Write-Message -Level Verbose -Message "Export completed: $(Get-Date)"
        Write-Message -Level Verbose -Message "Total Elapsed time: $totalTime"
    }
}
# SIG # Begin signature block
# MIIjYAYJKoZIhvcNAQcCoIIjUTCCI00CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCANnxnbD9IjM9rV
# J5N5Sli1jAXaghI0o1ia5UfLwVgoLqCCHVkwggUaMIIEAqADAgECAhADBbuGIbCh
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
# BgorBgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCCsoD6NwKevsZDHP0YNCx+kdnfE
# Ua/Cs5fQQHmuzRqGUzANBgkqhkiG9w0BAQEFAASCAQA5uoeA//jiZsdsuXAx48WK
# oJsVgLWqxojx9pjZUWaLM6wseVEimhtiE2APW/BbRVyZEQ6xZ8YnSSBYAZSx3eNV
# LHBNBT45xInwE5EKN0lPpbHkizO+3lqfNKegumoIoV+RlBsUNjVX+hJ8d93x7vnq
# O4Yo2ecN6b4kOZw/3DJ2kG8EwQOAGmR8UHtsdOCrI592qqvKKnt/pi8iQi+VWTmi
# 4mevaVHt/8baleM1uVv+8bX6S/UauVkEDK3ou5g+kwEeCt/YOau5R3uVpE5yViL2
# bsCe0+oWIuWCgcGb8ODPe60kR5ArUdJ+q4j9rpvNtU0OWhnJaqLdv5D2DfqM57eE
# oYIDIDCCAxwGCSqGSIb3DQEJBjGCAw0wggMJAgEBMHcwYzELMAkGA1UEBhMCVVMx
# FzAVBgNVBAoTDkRpZ2lDZXJ0LCBJbmMuMTswOQYDVQQDEzJEaWdpQ2VydCBUcnVz
# dGVkIEc0IFJTQTQwOTYgU0hBMjU2IFRpbWVTdGFtcGluZyBDQQIQDE1pckuU+jwq
# Sj0pB4A9WjANBglghkgBZQMEAgEFAKBpMBgGCSqGSIb3DQEJAzELBgkqhkiG9w0B
# BwEwHAYJKoZIhvcNAQkFMQ8XDTIyMTExNzA4NTUyOVowLwYJKoZIhvcNAQkEMSIE
# ID2CbVn55z0ojyc5ySN8abhrfrVNfZC22GsM7jKYxkabMA0GCSqGSIb3DQEBAQUA
# BIICAJVpgIB9dPqqI4e2eXeiz1Wgh/Nks+5DYfCYF3uUKX8kJOycJxhzJznEUKtl
# +Gj77hVUt3wg5v0hGlBmJDRPmkVCd0LYTZfJOxLPPjtBJ/n/k84wCqR6C1Wk9qpr
# Tt/lGTTvfH9yjk55jQr9LzmUiBJdgPY5o/eILn2VRVY+ApAKRWxA+YzPrUGj4qv+
# 2gviiP7uSqaOySkXMjSPn5WWabThRKjwQvTs+6+aUigO5mDgCPQwL0WFFrJMIZ5T
# G1pgsLJGpo1v7yyGNm3PhRlEP/YBajSSnpOjyfwMWJxQdIhCkVjYCHDpPXpzqvRm
# 8UgHtAL4PDip9FCR6SfILEzZONVHYwAopSnY1H9LKPN/BPpljqztLZq4+AaeUxtu
# H5UJHi+poCpeeTWAjdeasnUFe+j0gnjJ2E08uacVsZvILaRCuoF9l0lPtDthiyMV
# koWde4A9vAU12//f/oJqqklx89qhs3D/BFpybwcj8QNc6XzdLD0TEMD1tmpBXaTS
# 5hsAAQ3wd7LRe78Obrp5Zq24ZQEziDNyekHhTUpqlGPteFcYE1HIPsd2VyPzlAOP
# ieeAi0k/88EiFlEIAmPZmlZaj0ji448VgKZFRPRKZzDE+DRkl451FdpKsm9arQFf
# 3PE9w2LIy8i9xb0VSTRiRIsHyjELPyPyDBRcZtEwj6gWqJkZ
# SIG # End signature block
