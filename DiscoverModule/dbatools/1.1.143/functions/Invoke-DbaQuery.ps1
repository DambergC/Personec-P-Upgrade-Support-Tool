function Invoke-DbaQuery {
    <#
    .SYNOPSIS
        A command to run explicit T-SQL commands or files.

    .DESCRIPTION
        This function is a wrapper command around Invoke-DbaAsync, which in turn is based on Invoke-SqlCmd2.
        It was designed to be more convenient to use in a pipeline and to behave in a way consistent with the rest of our functions.

    .PARAMETER SqlInstance
        The target SQL Server instance or instances. This can be a collection and receive pipeline input to allow the function to be executed against multiple SQL Server instances.

    .PARAMETER SqlCredential
        Credential object used to connect to the SQL Server Instance as a different user. This can be a Windows or SQL Server account. Windows users are determined by the existence of a backslash, so if you are intending to use an alternative Windows connection instead of a SQL login, ensure it contains a backslash.

    .PARAMETER Database
        The database to select before running the query. This list is auto-populated from the server.

    .PARAMETER Query
        Specifies one or more queries to be run. The queries can be Transact-SQL, XQuery statements, or sqlcmd commands. Multiple queries in a single batch may be separated by a semicolon or a GO

        Escape any double quotation marks included in the string.

        Consider using bracketed identifiers such as [MyTable] instead of quoted identifiers such as "MyTable".

    .PARAMETER QueryTimeout
        Specifies the number of seconds before the queries time out.

    .PARAMETER File
        Specifies the path to one or several files to be used as the query input.

    .PARAMETER SqlObject
        Specify one or more SQL objects. Those will be converted to script and their scripts run on the target system(s).

    .PARAMETER As
        Specifies output type. Valid options for this parameter are 'DataSet', 'DataTable', 'DataRow', 'PSObject', 'PSObjectArray', and 'SingleValue'.

        PSObject and PSObjectArray output introduces overhead but adds flexibility for working with results: https://forums.powershell.org/t/dealing-with-dbnull/2328/2

    .PARAMETER SqlParameter
        Specifies a hashtable of parameters or output from New-DbaSqlParameter for parameterized SQL queries.  http://blog.codinghorror.com/give-me-parameterized-sql-or-give-me-death/

    .PARAMETER AppendServerInstance
        If this switch is enabled, the SQL Server instance will be appended to PSObject and DataRow output.

    .PARAMETER MessagesToOutput
        Use this switch to have on the output stream messages too (e.g. PRINT statements). Output will hold the resultset too.

    .PARAMETER InputObject
        A collection of databases (such as returned by Get-DbaDatabase)

    .PARAMETER EnableException
        By default, when something goes wrong we try to catch it, interpret it and give you a friendly warning message.
        This avoids overwhelming you with "sea of red" exceptions, but is inconvenient because it basically disables advanced scripting.
        Using this switch turns this "nice by default" feature off and enables you to catch exceptions with your own try/catch.

    .PARAMETER ReadOnly
        Execute the query with ReadOnly application intent.

    .PARAMETER CommandType
        Specifies the type of command represented by the query string. Valid options for this parameter are 'Text', 'TableDirect', and 'StoredProcedure'.
        Default is 'Text'. Further information: https://docs.microsoft.com/en-us/dotnet/api/system.data.sqlclient.sqlcommand.commandtype

    .PARAMETER NoExec
        Use this switch to prepend SET NOEXEC ON and append SET NOEXEC OFF to each statement, useful for checking query formal errors


    .NOTES
        Tags: Database, Query, Utility
        Author: Friedrich Weinmann (@FredWeinmann)

        Website: https://dbatools.io
        Copyright: (c) 2018 by dbatools, licensed under MIT
        License: MIT https://opensource.org/licenses/MIT

    .LINK
        https://dbatools.io/Invoke-DbaQuery

    .EXAMPLE
        PS C:\> Invoke-DbaQuery -SqlInstance server\instance -Query 'SELECT foo FROM bar'

        Runs the sql query 'SELECT foo FROM bar' against the instance 'server\instance'

    .EXAMPLE
        PS C:\> Get-DbaRegServer -SqlInstance [SERVERNAME] -Group [GROUPNAME] | Invoke-DbaQuery -Query 'SELECT foo FROM bar'

        Runs the sql query 'SELECT foo FROM bar' against all instances in the group [GROUPNAME] on the CMS [SERVERNAME]

    .EXAMPLE
        PS C:\> "server1", "server1\nordwind", "server2" | Invoke-DbaQuery -File "C:\scripts\sql\rebuild.sql"

        Runs the sql commands stored in rebuild.sql against the instances "server1", "server1\nordwind" and "server2"

    .EXAMPLE
        PS C:\> Get-DbaDatabase -SqlInstance "server1", "server1\nordwind", "server2" | Invoke-DbaQuery -File "C:\scripts\sql\rebuild.sql"

        Runs the sql commands stored in rebuild.sql against all accessible databases of the instances "server1", "server1\nordwind" and "server2"

    .EXAMPLE
        PS C:\> Invoke-DbaQuery -SqlInstance . -Query 'SELECT * FROM users WHERE Givenname = @name' -SqlParameter @{ Name = "Maria" }

        Executes a simple query against the users table using SQL Parameters.
        This avoids accidental SQL Injection and is the safest way to execute queries with dynamic content.
        Keep in mind the limitations inherent in parameters - it is quite impossible to use them for content references.
        While it is possible to parameterize a where condition, it is impossible to use this to select which columns to select.
        The inserted text will always be treated as string content, and not as a reference to any SQL entity (such as columns, tables or databases).
    .EXAMPLE
        PS C:\> Invoke-DbaQuery -SqlInstance aglistener1 -ReadOnly -Query "select something from readonlydb.dbo.atable"

        Executes a query with ReadOnly application intent on aglistener1.

    .EXAMPLE
        PS C:\> Invoke-DbaQuery -SqlInstance server1 -Database tempdb -Query Example_SP -SqlParameter @{ Name = "Maria" } -CommandType StoredProcedure

        Executes a stored procedure Example_SP using SQL Parameters

    .EXAMPLE
        PS C:\> $queryParameters = @{
        >>     StartDate = $startdate
        >>     EndDate   = $enddate
        >> }
        PS C:\> Invoke-DbaQuery -SqlInstance server1 -Database tempdb -Query Example_SP -SqlParameter $queryParameters -CommandType StoredProcedure

        Executes a stored procedure Example_SP using multiple SQL Parameters

    .EXAMPLE
        PS C:\> $inparam = @()
        PS C:\> $inparam += [pscustomobject]@{
        >>     somestring = 'string1'
        >>     somedate = '2021-07-15T01:02:00'
        >> }
        PS C:\> $inparam += [pscustomobject]@{
        >>     somestring = 'string2'
        >>     somedate = '2021-07-15T02:03:00'
        >> }
        >> $inparamAsDataTable = ConvertTo-DbaDataTable -InputObject $inparam
        PS C:\> New-DbaSqlParameter -SqlDbType structured -Value $inparamAsDataTable -TypeName 'dbatools_tabletype'
        PS C:\> Invoke-DbaQuery -SqlInstance localhost -Database master -CommandType StoredProcedure -Query my_proc -SqlParameter $inparamAsDataTable

        Creates an TVP input parameter and uses it to invoke a stored procedure.

    .EXAMPLE
        PS C:\> $output = New-DbaSqlParameter -ParameterName json_result -SqlDbType NVarChar -Size -1 -Direction Output
        PS C:\> Invoke-DbaQuery -SqlInstance localhost -Database master -CommandType StoredProcedure -Query my_proc -SqlParameter $output
        PS C:\> $output.Value

        Creates an output parameter and uses it to invoke a stored procedure.

    .EXAMPLE
        PS C:\> $server = Connect-DbaInstance -SqlInstance localhost -Database master -AlwaysEncrypted
        PS C:\> $inputparamSSN = New-DbaSqlParameter -Direction Input -ParameterName "@SSN" -DbType AnsiStringFixedLength -Size 11 -SqlValue "444-44-4444" -ForceColumnEncryption
        PS C:\> Invoke-DbaQuery -SqlInstance $server -Query 'SELECT * FROM bar WHERE SSN_col = @SSN' -SqlParameter @inputparamSSN

        Creates an input parameter using Always Encrypted
    #>
    [CmdletBinding(DefaultParameterSetName = "Query")]
    param (
        [Parameter(ValueFromPipeline)]
        [Parameter(ParameterSetName = 'Query', Position = 0)]
        [Parameter(ParameterSetName = 'File', Position = 0)]
        [Parameter(ParameterSetName = 'SMO', Position = 0)]
        [DbaInstance[]]$SqlInstance,
        [PsCredential]$SqlCredential,
        [string]$Database,
        [Parameter(Mandatory, ParameterSetName = "Query")]
        [string]$Query,
        [Int32]$QueryTimeout,
        [Parameter(Mandatory, ParameterSetName = "File")]
        [Alias("InputFile")]
        [object[]]$File,
        [Parameter(Mandatory, ParameterSetName = "SMO")]
        [Microsoft.SqlServer.Management.Smo.SqlSmoObject[]]$SqlObject,
        [ValidateSet("DataSet", "DataTable", "DataRow", "PSObject", "PSObjectArray", "SingleValue")]
        [string]$As = "DataRow",
        [Alias("SqlParameters")]
        [psobject[]]$SqlParameter,
        [System.Data.CommandType]$CommandType = 'Text',
        [switch]$AppendServerInstance,
        [switch]$MessagesToOutput,
        [parameter(ValueFromPipeline)]
        [Microsoft.SqlServer.Management.Smo.Database[]]$InputObject,
        [switch]$ReadOnly,
        [switch]$NoExec,
        [switch]$EnableException
    )

    begin {
        Write-Message -Level Debug -Message "Bound parameters: $($PSBoundParameters.Keys -join ", ")"

        if ($PSBoundParameters.SqlParameter) {
            $first = $SqlParameter | Select-Object -First 1
            if ($first -isnot [Microsoft.Data.SqlClient.SqlParameter] -and ($first -isnot [System.Collections.IDictionary] -or $SqlParameter -is [System.Collections.IDictionary[]])) {
                Stop-Function -Message "SqlParameter only accepts a single hashtable or Microsoft.Data.SqlClient.SqlParameter"
                return
            }
        }

        $splatInvokeDbaSqlAsync = @{
            As          = $As
            CommandType = $CommandType
        }

        if (Test-Bound -ParameterName "SqlParameter") {
            $splatInvokeDbaSqlAsync["SqlParameter"] = $SqlParameter
        }
        if (Test-Bound -ParameterName "AppendServerInstance") {
            $splatInvokeDbaSqlAsync["AppendServerInstance"] = $AppendServerInstance
        }
        if (Test-Bound -ParameterName "Query") {
            $splatInvokeDbaSqlAsync["Query"] = $Query
        }
        if (Test-Bound -ParameterName "QueryTimeout") {
            $splatInvokeDbaSqlAsync["QueryTimeout"] = $QueryTimeout
        }
        if (Test-Bound -ParameterName "MessagesToOutput") {
            $splatInvokeDbaSqlAsync["MessagesToOutput"] = $MessagesToOutput
        }
        if (Test-Bound -ParameterName "Verbose") {
            $splatInvokeDbaSqlAsync["Verbose"] = $Verbose
        }
        if (Test-Bound -ParameterName "NoExec") {
            $splatInvokeDbaSqlAsync["NoExec"] = $NoExec
        }

        if (Test-Bound -ParameterName "File") {
            $files = @()
            $temporaryFiles = @()
            $temporaryFilesCount = 0
            $temporaryFilesPrefix = (97 .. 122 | Get-Random -Count 10 | ForEach-Object { [char]$_ }) -join ''

            foreach ($item in $File) {
                if ($null -eq $item) { continue }

                $type = $item.GetType().FullName

                switch ($type) {
                    "System.IO.DirectoryInfo" {
                        if (-not $item.Exists) {
                            Stop-Function -Message "Directory not found" -Category ObjectNotFound
                            return
                        }
                        $files += ($item.GetFiles() | Where-Object Extension -EQ ".sql").FullName

                    }
                    "System.IO.FileInfo" {
                        if (-not $item.Exists) {
                            Stop-Function -Message "Directory not found." -Category ObjectNotFound
                            return
                        }

                        $files += $item.FullName
                    }
                    "System.String" {
                        try {
                            if (Test-PSVersion -Maximum 4) {
                                $uri = [uri]$item
                            } else {
                                $uri = New-Object uri -ArgumentList $item
                            }
                            $uriScheme = $uri.Scheme
                        } catch {
                            $uriScheme = $null
                        }

                        switch -regex ($uriScheme) {
                            "http" {
                                $tempfile = "$(Get-DbatoolsPath -Name temp)\$temporaryFilesPrefix-$temporaryFilesCount.sql"
                                try {
                                    try {
                                        Invoke-TlsWebRequest -Uri $item -OutFile $tempfile -ErrorAction Stop
                                    } catch {
                                        (New-Object System.Net.WebClient).Proxy.Credentials = [System.Net.CredentialCache]::DefaultNetworkCredentials
                                        Invoke-TlsWebRequest -Uri $item -OutFile $tempfile -ErrorAction Stop
                                    }
                                    $files += $tempfile
                                    $temporaryFilesCount++
                                    $temporaryFiles += $tempfile
                                } catch {
                                    Stop-Function -Message "Failed to download file $item" -ErrorRecord $_
                                    return
                                }
                            }
                            default {
                                try {
                                    $paths = Resolve-Path $item | Select-Object -ExpandProperty Path | Get-Item -ErrorAction Stop
                                } catch {
                                    Stop-Function -Message "Failed to resolve path: $item" -ErrorRecord $_
                                    return
                                }

                                foreach ($path in $paths) {
                                    if (-not $path.PSIsContainer) {
                                        if (Test-PSVersion -Is 3) {
                                            if (([uri]$path.FullName).Scheme -ne 'file') {
                                                Stop-Function -Message "Could not resolve path $path as filesystem object"
                                                return
                                            }
                                        } else {
                                            if ((New-Object uri -ArgumentList $path).Scheme -ne 'file') {
                                                Stop-Function -Message "Could not resolve path $path as filesystem object"
                                                return
                                            }
                                        }
                                        $files += $path.FullName
                                    }
                                }
                            }
                        }
                    }
                    default {
                        Stop-Function -Message "Unkown input type: $type" -Category InvalidArgument
                        return
                    }
                }
            }
        }

        if (Test-Bound -ParameterName "SqlObject") {
            $files = @()
            $temporaryFiles = @()
            $temporaryFilesCount = 0
            $temporaryFilesPrefix = (97 .. 122 | Get-Random -Count 10 | ForEach-Object { [char]$_ }) -join ''

            foreach ($object in $SqlObject) {
                try { $code = Export-DbaScript -InputObject $object -Passthru -EnableException }
                catch {
                    Stop-Function -Message "Failed to generate script for object $object" -ErrorRecord $_
                    return
                }

                try {
                    $newfile = "$(Get-DbatoolsPath -Name temp)\$temporaryFilesPrefix-$temporaryFilesCount.sql"
                    Set-Content -Value $code -Path $newfile -Force -ErrorAction Stop -Encoding UTF8
                    $files += $newfile
                    $temporaryFilesCount++
                    $temporaryFiles += $newfile
                } catch {
                    Stop-Function -Message "Failed to write sql script to temp" -ErrorRecord $_
                    return
                }
            }
        }
    }

    process {
        if (Test-FunctionInterrupt) { return }
        if (Test-Bound -ParameterName "Database", "InputObject" -And) {
            Stop-Function -Category InvalidArgument -Message "You can't use -Database with piped databases"
            return
        }
        if (Test-Bound -ParameterName "SqlInstance", "InputObject" -And) {
            Stop-Function -Category InvalidArgument -Message "You can't use -SqlInstance with piped databases"
            return
        }
        if (Test-Bound -ParameterName "SqlInstance", "InputObject" -Not) {
            Stop-Function -Category InvalidArgument -Message "Please provide either SqlInstance or InputObject"
            return
        }


        foreach ($db in $InputObject) {
            if (!$db.IsAccessible) {
                Write-Message -Level Warning -Message "Database $db is not accessible. Skipping."
                continue
            }
            $server = $db.Parent
            $conncontext = $server.ConnectionContext
            if ($conncontext.DatabaseName -ne $db.Name) {
                # Save StatementTimeout because it might be reset on GetDatabaseConnection
                $savedStatementTimeout = $conncontext.StatementTimeout
                $conncontext = $conncontext.Copy().GetDatabaseConnection($db.Name)
                $conncontext.StatementTimeout = $savedStatementTimeout
            }
            try {
                if ($File -or $SqlObject) {
                    foreach ($item in $files) {
                        if ($null -eq $item) { continue }
                        $filePath = $(Resolve-Path -LiteralPath $item).ProviderPath
                        $QueryfromFile = [System.IO.File]::ReadAllText("$filePath")
                        Invoke-DbaAsync -SQLConnection $conncontext @splatInvokeDbaSqlAsync -Query $QueryfromFile
                    }
                } else { Invoke-DbaAsync -SQLConnection $conncontext @splatInvokeDbaSqlAsync }
            } catch {
                Stop-Function -Message "[$db] Failed during execution" -ErrorRecord $_ -Target $server -Continue
            }
        }
        foreach ($instance in $SqlInstance) {
            # Verbose output in Invoke-DbaQuery is special, because it's the only way to assure on all versions of Powershell to have separate outputs (results and messages) coming from the TSQL Query.
            # We suppress the verbosity of all other functions in order to be sure the output is consistent with what you get, e.g., executing the same in SSMS
            Write-Message -Level Debug -Message "SqlInstance passed in, will work on: $instance"
            try {
                $noConnectionChangeNeeded = # we want to bypass Connect-DbaInstance if
                ($instance.InputObject.GetType().Name -eq "Server") -and # we have Server SMO object and
                (-not $ReadOnly) -and # no readonly intent is requested and
                (-not $Database -or $instance.InputObject.ConnectionContext.DatabaseName -eq $Database)  # the database is not set or the currently connected
                if ($noConnectionChangeNeeded) {
                    Write-Message -Level Debug -Message "Current connection will be reused"
                    $server = $instance.InputObject
                } else {
                    $connDbaInstanceParams = @{
                        SqlInstance         = $instance
                        SqlCredential       = $SqlCredential
                        Database            = $Database
                        NonPooledConnection = $true           # see #8491 for details, also #7725 is still relevant
                        Verbose             = $false
                    }
                    if ($ReadOnly) {
                        $connDbaInstanceParams.ApplicationIntent = "ReadOnly"
                    }
                    $server = Connect-DbaInstance @connDbaInstanceParams
                }
            } catch {
                Stop-Function -Message "Failure" -ErrorRecord $_ -Target $instance -Continue
            }
            $conncontext = $server.ConnectionContext
            try {
                if ($File -or $SqlObject) {
                    foreach ($item in $files) {
                        if ($null -eq $item) { continue }
                        $filePath = $(Resolve-Path -LiteralPath $item).ProviderPath
                        $QueryfromFile = [System.IO.File]::ReadAllText("$filePath")
                        Invoke-DbaAsync -SQLConnection $conncontext @splatInvokeDbaSqlAsync -Query $QueryfromFile
                    }
                } else {
                    Invoke-DbaAsync -SQLConnection $conncontext @splatInvokeDbaSqlAsync
                }
            } catch {
                Stop-Function -Message "[$instance] Failed during execution" -ErrorRecord $_ -Target $instance -Continue
            }
            if ($connDbaInstanceParams.NonPooledConnection) {
                # Close non-pooled connection as this is not done automatically. If it is a reused Server SMO, connection will be opened again automatically on next request.
                $null = $server | Disconnect-DbaInstance -Verbose:$false
            }
        }
    }

    end {
        # Execute end even when interrupting, as only used for cleanup

        if ($temporaryFiles) {
            # Clean up temporary files that were downloaded
            foreach ($item in $temporaryFiles) {
                Remove-Item -Path $item -ErrorAction Ignore
            }
        }
    }
}
# SIG # Begin signature block
# MIIjYAYJKoZIhvcNAQcCoIIjUTCCI00CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCAD2XhPEoWotFCo
# 9pDL84/RgXMmxweWZTHEakSHmwt6s6CCHVkwggUaMIIEAqADAgECAhADBbuGIbCh
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
# BgorBgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCAdcSg3ZTukvYzW5FFxAcVc/Luz
# geYtDgXP4WC7Due1RzANBgkqhkiG9w0BAQEFAASCAQCn/hGJjnyZOBYEySHtCA5/
# On4gTbno3CGu3bqBoLx3oB8zEM0TzOgnm0VgqRu/HQtKbIyblZbV9iMzTqRTGJa0
# WblXPPtbWqeNlvaiZmJUOhx/fCgUuX7HeKRWntxRcmrPxS1Qx5CmMABzI2Z/DGIv
# 6KTCvQZz/Gl1LMMnmioO1wafjSfHVTqS9ejwaEfAHZJSpCSwiWJ/WgXHWpTanyok
# 8Klm8ba6k01ti8B/vkddyXbhwVnDaPpK8tS7kTCdr/2EsiPsJrIjRnPMkT0sLvf8
# kXD1bUBPCX/Ft1j2AHzGbt7SWcjBpRwgWkUY5J5XgeexI52id1pSv3ZewbMFIEfK
# oYIDIDCCAxwGCSqGSIb3DQEJBjGCAw0wggMJAgEBMHcwYzELMAkGA1UEBhMCVVMx
# FzAVBgNVBAoTDkRpZ2lDZXJ0LCBJbmMuMTswOQYDVQQDEzJEaWdpQ2VydCBUcnVz
# dGVkIEc0IFJTQTQwOTYgU0hBMjU2IFRpbWVTdGFtcGluZyBDQQIQDE1pckuU+jwq
# Sj0pB4A9WjANBglghkgBZQMEAgEFAKBpMBgGCSqGSIb3DQEJAzELBgkqhkiG9w0B
# BwEwHAYJKoZIhvcNAQkFMQ8XDTIyMTExNzA4NTY0NVowLwYJKoZIhvcNAQkEMSIE
# INjdcuQIAWPmcXjFsCK1mpM0FfSsVYiKlqJbOe5fVUX3MA0GCSqGSIb3DQEBAQUA
# BIICAEFAX7lF8yunW1dOvqMo8V5ni9B+7zsdggP6a7Hthm5KvLUAuvssAqkP8Bfp
# jFOEliK7Fl5wJQ+jN1zlgZrK9iCFJA1yat8/DdbXsDtn/ejD42gTOd9wJYUffFKX
# QKNc3AA0gl0vPsbsRQo+lfVpg7b0CSI1ZcMxQQEmP22IEuG1pwcRjzWTle59fo0n
# hkI8nVlA53YG6o+7bvByJcrGqaG4y4A/uRIm3GmwYE4jYVnlmWJvpMtq3GYOXPpJ
# fBbAnakmJnYyGBtDZIrSQkRjeWqtlXDsRGA75xkROZ26laI2SN7/0M1OstXW2SBr
# fFhSH4UL001WESpjFaX4uGXIeULcPHxAsF0I7Kps+L5Xa1Sl5/pEuOyH4zskVyA9
# YQ6NjrfsJdQIbU/W17/K8zNd7FZhWVH/gmNvXOx+j2K1uV6ADSgCagM8FBi3uYGv
# tqbvKJkO0zOtH4YAaAXI6O7sqdIJkOJ8eOrqhDHxsGBMh8hygREvO84Ni7Ii2fGH
# E82Xjy6MdM/jUKBUR+BDRAaphM5m+LmH3Zdh0KyEN9HBcRgFNsevrAFg2gjx0Rgs
# HQP8sb6sks+UVZxJOZ5PX+XmxiSdQhxBo8DfiVRgrlpNLnJmr7nLVAXvLP/NjR4e
# yewiOPwExQkfXqNggB5NhFzotTBAhoX4bfkKepKj66oY8wCU
# SIG # End signature block
