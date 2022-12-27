function Test-DbaDbCompression {
    <#
    .SYNOPSIS
        Returns tables and indexes with preferred compression setting.
    .DESCRIPTION
        This function returns the results of a full table/index compression analysis and the estimated, best option to date for either NONE, Page, or Row Compression.

        Remember Uptime is critical, the longer uptime, the more accurate the analysis is, and it would be best if you utilized Get-DbaUptime first, before running this command.

        Test-DbaDbCompression script derived from GitHub and the Tiger Team's repository: (https://github.com/Microsoft/tigertoolbox/tree/master/Evaluate-Compression-Gains)
        In the output, you will find the following information:
        - Column Percent_Update shows the percentage of update operations on a specific table, index, or partition, relative to total operations on that object. The lower the percentage of Updates (that is, the table, index, or partition is infrequently updated), the better candidate it is for page compression.
        - Column Percent_Scan shows the percentage of scan operations on a table, index, or partition, relative to total operations on that object. The higher the value of Scan (that is, the table, index, or partition is mostly scanned), the better candidate it is for page compression.
        - Column Compression_Type_Recommendation can have four possible outputs indicating where there is most gain, if any: 'PAGE', 'ROW', 'NO_GAIN' or '?'. When the output is '?' this approach could not give a recommendation, so as a rule of thumb I would lean to ROW if the object suffers mainly UPDATES, or PAGE if mainly INSERTS, but this is where knowing your workload is essential. When the output is 'NO_GAIN' well, that means that according to sp_estimate_data_compression_savings no space gains will be attained when compressing, as in the above output example, where compressing would grow the affected object.

        This script will execute on the context of the current database.
        Also be aware that this may take a while to execute on large objects, because if the IS locks taken by the
        sp_estimate_data_compression_savings cannot be honored, the SP will be blocked.
        It only considers Row or Page Compression (not column compression)
        It only evaluates User Tables

    .PARAMETER SqlInstance
        The target SQL Server instance or instances. This can be a collection and receive pipeline input to allow the function to be executed against multiple SQL Server instances.

    .PARAMETER SqlCredential
        Login to the target instance using alternative credentials. Accepts PowerShell credentials (Get-Credential).

        Windows Authentication, SQL Server Authentication, Active Directory - Password, and Active Directory - Integrated are all supported.

        For MFA support, please use Connect-DbaInstance.

    .PARAMETER Database
        The database(s) to process - this list is auto-populated from the server. If unspecified, all databases will be processed.

    .PARAMETER ExcludeDatabase
        The database(s) to exclude - this list is auto-populated from the server

    .PARAMETER Schema
        Filter to only get specific schemas If unspecified, all schemas will be processed.

    .PARAMETER Table
        Filter to only get specific tables If unspecified, all User tables will be processed.

    .PARAMETER ResultSize
        Allows you to limit the number of results returned, as some systems can have very large number of tables.  Default value is no restriction.

    .PARAMETER Rank
        Allows you to specify the field used for ranking when determining the ResultSize
        Can be either TotalPages, UsedPages or TotalRows with default of TotalPages. Only applies when ResultSize is used.

    .PARAMETER FilterBy
        Allows you to specify level of filtering when determining the ResultSize
        Can be at either Table, Index or Partition level with default of Partition. Only applies when ResultSize is used.

    .PARAMETER EnableException
        By default, when something goes wrong we try to catch it, interpret it and give you a friendly warning message.
        This avoids overwhelming you with "sea of red" exceptions, but is inconvenient because it basically disables advanced scripting.
        Using this switch turns this "nice by default" feature off and enables you to catch exceptions with your own try/catch.

    .INPUTS
        Accepts a DbaInstanceParameter. Any collection of SQL Server Instance names or SMO objects can be piped to command.

    .OUTPUTS
        Returns a PsCustomObject with following fields: ComputerName, InstanceName, SqlInstance, Database, IndexName, Partition, IndexID, PercentScan, PercentUpdate, RowEstimatePercentOriginal, PageEstimatePercentOriginal, CompressionTypeRecommendation, SizeCurrent, SizeRequested, PercentCompression

    .NOTES
        Tags: Compression, Table
        Author: Jason Squires (@js_0505), jstexasdba@gmail.com

        Website: https://dbatools.io
        Copyright: (c) 2018 by dbatools, licensed under MIT
        License: MIT https://opensource.org/licenses/MIT

    .LINK
        https://dbatools.io/Test-DbaDbCompression

    .EXAMPLE
        PS C:\> Test-DbaDbCompression -SqlInstance localhost

        Returns results of all potential compression options for all databases for the default instance on the local host. Returns a recommendation of either Page, Row or NO_GAIN

    .EXAMPLE
        PS C:\> Test-DbaDbCompression -SqlInstance ServerA

        Returns results of all potential compression options for all databases on the instance ServerA

    .EXAMPLE
        PS C:\> Test-DbaDbCompression -SqlInstance ServerA -Database DBName | Out-GridView

        Returns results of all potential compression options for a single database DBName with the recommendation of either Page or Row or NO_GAIN in a nicely formatted GridView

    .EXAMPLE
        PS C:\> $cred = Get-Credential sqladmin
        PS C:\> Test-DbaDbCompression -SqlInstance ServerA -ExcludeDatabase MyDatabase -SqlCredential $cred

        Returns results of all potential compression options for all databases except MyDatabase on instance ServerA using SQL credentials to authentication to ServerA.
        Returns the recommendation of either Page, Row or NO_GAIN

    .EXAMPLE
        PS C:\> Test-DbaDbCompression -SqlInstance ServerA -Schema Test -Table MyTable

        Returns results of all potential compression options for the Table Test.MyTable in instance ServerA on ServerA and ServerB.
        Returns the recommendation of either Page, Row or NO_GAIN.
        Returns a result for each partition of any Heap, Clustered or NonClustered index.

    .EXAMPLE
        PS C:\> Test-DbaDbCompression -SqlInstance ServerA, ServerB -ResultSize 10

        Returns results of all potential compression options for all databases on ServerA and ServerB.
        Returns the recommendation of either Page, Row or NO_GAIN.
        Returns results for the top 10 partitions by TotalPages used per database.

    .EXAMPLE
        PS C:\> ServerA | Test-DbaDbCompression -Schema Test -ResultSize 10 -Rank UsedPages -FilterBy Table

        Returns results of all potential compression options for all databases on ServerA containing a schema Test
        Returns results for the top 10 Tables by Used Pages per database.
        Results are split by Table, Index and Partition so more than 10 results may be returned.

    .EXAMPLE
        PS C:\> $servers = 'Server1','Server2'
        PS C:\> $servers | Test-DbaDbCompression -Database DBName | Out-GridView

        Returns results of all potential compression options for a single database DBName on Server1 or Server2
        Returns the recommendation of either Page, Row or NO_GAIN in a nicely formatted GridView

    .EXAMPLE
        PS C:\> $cred = Get-Credential sqladmin
        PS C:\> Test-DbaDbCompression -SqlInstance ServerA -Database MyDB -SqlCredential $cred -Schema Test -Table Test1, Test2

        Returns results of all potential compression options for objects in Database MyDb on instance ServerA using SQL credentials to authentication to ServerA.
        Returns the recommendation of either Page, Row or NO_GAIN for tables with Schema Test and name in Test1 or Test2

    .EXAMPLE
        PS C:\> $servers = 'Server1','Server2'
        PS C:\> foreach ($svr in $servers) {
        >> Test-DbaDbCompression -SqlInstance $svr | Export-Csv -Path C:\temp\CompressionAnalysisPAC.csv -Append
        >> }

        This produces a full analysis of all your servers listed and is pushed to a csv for you to analyze.

    #>
    [CmdletBinding(DefaultParameterSetName = "Default")]
    param (
        [parameter(Mandatory, ValueFromPipeline)]
        [DbaInstanceParameter[]]$SqlInstance,
        [PSCredential]$SqlCredential,
        [string[]]$Database,
        [string[]]$ExcludeDatabase,
        [string[]]$Schema,
        [string[]]$Table,
        [int]$ResultSize,
        [ValidateSet('TotalPages', 'UsedPages', 'TotalRows')]
        [string]$Rank = 'TotalPages',
        [ValidateSet('Partition', 'Index', 'Table')]
        [string]$FilterBy = 'Partition',
        [switch]$EnableException
    )

    begin {
        Write-Message -Level System -Message "Bound parameters: $($PSBoundParameters.Keys -join ", ")"

        if ($Schema) {
            $sqlSchemaWhere = "AND s.name IN ('$($Schema -join "','")')"
        }

        if ($Table) {
            $sqlTableWhere = "AND t.name IN ('$($Table -join "','")')"
        }

        if ($ResultSize) {
            $sqlOrderBy = switch ($Rank) {
                UsedPages { 'UsedSpaceKB' }
                TotalRows { 'RowCounts' }
                default { 'TotalSpaceKB' }
            }

            if ($FilterBy -eq 'Table') {
                $sqlJoinFiltered = 'AND t.TableName = tdc.TableName COLLATE DATABASE_DEFAULT'
                $indexSQL = '0 as [IndexID]'
                $partitionSQL = '0 AS [Partition]'
                $groupBySQL = 's.Name, t.Name'
            } elseif ($FilterBy -eq 'Index') {
                $sqlJoinFiltered = 'AND t.TableName = tdc.TableName COLLATE DATABASE_DEFAULT AND t.IndexID = tdc.IndexID'
                $indexSQL = 'i.index_id as [IndexID]'
                $partitionSQL = '0 AS [Partition]'
                $groupBySQL = 's.Name, t.Name, i.index_id'
            } else {
                $sqlJoinFiltered = 'AND t.TableName = tdc.TableName COLLATE DATABASE_DEFAULT AND t.IndexID = tdc.IndexID AND t.[Partition] = tdc.[Partition]'
                $indexSQL = 'i.index_id as [IndexID]'
                $partitionSQL = 'p.partition_number AS [Partition]'
                $groupBySQL = 's.Name, t.Name, i.index_id, p.partition_number'
            }

            $sqlRestrict = "-- remove tables not in Top N
                With TopN(SchemaName, TableName, IndexID, [Partition], RowCounts, TotalSpaceKB, UsedSpaceKB) as
                (
                    SELECT TOP $ResultSize
                        s.Name AS SchemaName,
                        t.NAME as TableName,
                        $indexSQL,
                        $partitionSQL,
                        SUM(p.rows) AS RowCounts,
                        SUM(a.total_pages) * 8 AS TotalSpaceKB,
                        SUM(a.used_pages) * 8 AS UsedSpaceKB
                    FROM
                        sys.tables t
                    INNER JOIN
                        sys.indexes i ON t.OBJECT_ID = i.object_id
                    INNER JOIN
                        sys.partitions p ON i.object_id = p.OBJECT_ID AND i.index_id = p.index_id
                    INNER JOIN
                        sys.allocation_units a ON p.partition_id = a.container_id
                    LEFT OUTER JOIN
                        sys.schemas s ON t.schema_id = s.schema_id
                    WHERE objectproperty(t.object_id, 'IsUserTable') = 1
                        AND p.data_compression_desc = 'NONE'
                        AND p.rows > 0
                        $sqlSchemaWhere
                        $sqlTableWhere
                    GROUP BY
                        $groupBySQL
                    ORDER BY
                        $sqlOrderBy Desc
                )
                DELETE tdc
                FROM ##TestDbaCompression tdc
                LEFT JOIN TopN t
                    ON t.SchemaName = tdc.[Schema] COLLATE DATABASE_DEFAULT
                    $sqlJoinFiltered
                WHERE t.IndexID IS NULL;"
        }
    }

    process {

        foreach ($instance in $SqlInstance) {
            try {
                $server = Connect-DbaInstance -SqlInstance $instance -SqlCredential $SqlCredential -MinimumVersion 10
            } catch {
                Stop-Function -Message "Failure" -Category ConnectionError -ErrorRecord $_ -Target $instance -Continue
            }

            $Server.ConnectionContext.StatementTimeout = 0
            $sqlVersion = $(Get-DbaBuild -SqlInstance $server).Build.Major

            $sqlVersionRestrictions = @()

            if ($sqlVersion -ge 12) {
                $sqlVersionRestrictions += "
            BEGIN
                -- remove memory optimized tables
                DELETE tdc
                FROM ##TestDbaCompression tdc
                INNER JOIN sys.tables t
                    ON SCHEMA_NAME(t.schema_id) = tdc.[Schema] COLLATE DATABASE_DEFAULT
                    AND t.name = tdc.TableName COLLATE DATABASE_DEFAULT
                WHERE t.is_memory_optimized = 1
            END"
            }
            if ($sqlVersion -ge 13) {
                $sqlVersionRestrictions += "
            BEGIN
                -- remove tables with encrypted columns
                DELETE tdc
                FROM ##TestDbaCompression tdc
                INNER JOIN sys.tables t
                    ON SCHEMA_NAME(t.schema_id) = tdc.[Schema] COLLATE DATABASE_DEFAULT
                    AND t.name = tdc.TableName COLLATE DATABASE_DEFAULT
                INNER JOIN sys.columns c
                    ON t.object_id = c.object_id
                WHERE encryption_type IS NOT NULL
            END"
            }
            if ($sqlVersion -ge 14) {
                $sqlVersionRestrictions += "
            BEGIN
                -- remove graph (node/edge) tables
                DELETE tdc
                FROM ##TestDbaCompression tdc
                INNER JOIN sys.tables t
                    ON tdc.[Schema] = SCHEMA_NAME(t.schema_id) COLLATE DATABASE_DEFAULT
                    AND tdc.TableName = t.name COLLATE DATABASE_DEFAULT
                WHERE (is_node = 1 OR is_edge = 1)
            END"
            }
            $sql = "SET NOCOUNT ON;

IF OBJECT_ID('tempdb..##TestDbaCompression', 'U') IS NOT NULL
    DROP TABLE ##TestDbaCompression

IF OBJECT_ID('tempdb..##tmpEstimateRow', 'U') IS NOT NULL
    DROP TABLE ##tmpEstimateRow

IF OBJECT_ID('tempdb..##tmpEstimatePage', 'U') IS NOT NULL
    DROP TABLE ##tmpEstimatePage

CREATE TABLE ##TestDbaCompression (
    [Schema] SYSNAME
    ,[TableName] SYSNAME
    ,[ObjectId] INT
    ,[IndexName] SYSNAME NULL
    ,[Partition] INT
    ,[IndexID] INT
    ,[IndexType] VARCHAR(25)
    ,[PercentScan] SMALLINT
    ,[PercentUpdate] SMALLINT
    ,[RowEstimatePercentOriginal] BIGINT
    ,[PageEstimatePercentOriginal] BIGINT
    ,[CompressionTypeRecommendation] VARCHAR(7)
    ,SizeCurrent BIGINT
    ,SizeRequested BIGINT
    ,PercentCompression NUMERIC(10, 2)
    );

CREATE TABLE ##tmpEstimateRow (
    objname SYSNAME
    ,schname SYSNAME
    ,indid INT
    ,partnr INT
    ,SizeCurrent BIGINT
    ,SizeRequested BIGINT
    ,SampleCurrent BIGINT
    ,SampleRequested BIGINT
    );

CREATE TABLE ##tmpEstimatePage (
    objname SYSNAME
    ,schname SYSNAME
    ,indid INT
    ,partnr INT
    ,SizeCurrent BIGINT
    ,SizeRequested BIGINT
    ,SampleCurrent BIGINT
    ,SampleRequested BIGINT
    );

INSERT INTO ##TestDbaCompression (
    [Schema]
    ,[TableName]
    ,[ObjectId]
    ,[IndexName]
    ,[Partition]
    ,[IndexID]
    ,[IndexType]
    ,[PercentScan]
    ,[PercentUpdate]
    )
    SELECT s.NAME AS [Schema]
    ,t.NAME AS [TableName]
    ,t.OBJECT_ID AS [OBJECTID]
    ,x.NAME AS [IndexName]
    ,p.partition_number AS [Partition]
    ,x.Index_ID AS [IndexID]
    ,x.type_desc AS [IndexType]
    ,NULL AS [PercentScan]
    ,NULL AS [PercentUpdate]
FROM sys.tables t
INNER JOIN sys.schemas s ON t.schema_id = s.schema_id
INNER JOIN sys.indexes x ON x.object_id = t.object_id
INNER JOIN sys.partitions p ON x.object_id = p.object_id
    AND x.Index_ID = p.Index_ID
WHERE OBJECTPROPERTY(t.object_id, 'IsUserTable') = 1
    AND p.data_compression_desc = 'NONE'
    AND p.rows > 0
    $sqlSchemaWhere
    $sqlTableWhere
ORDER BY [TableName] ASC;

$sqlRestrict

BEGIN
    -- remove any tables with sparse columns
    DELETE tdc
    FROM ##TestDbaCompression tdc
    INNER JOIN sys.columns c
        on tdc.ObjectId = c.object_id
    WHERE c. is_sparse = 1
END

$sqlVersionRestrictions

DECLARE @schema SYSNAME
    ,@tbname SYSNAME
    ,@ixid INT

DECLARE cur CURSOR FAST_FORWARD
FOR
SELECT [Schema]
    ,[TableName]
    ,[IndexID]
FROM ##TestDbaCompression

OPEN cur

FETCH NEXT
FROM cur
INTO @schema
    ,@tbname
    ,@ixid

WHILE @@FETCH_STATUS = 0
BEGIN
    DECLARE @sqlcmd NVARCHAR(500)

    SET @sqlcmd = 'EXEC sp_estimate_data_compression_savings ''' + @schema + ''', ''' + @tbname + ''', ''' + cast(@ixid AS VARCHAR) + ''', NULL, ''ROW''';

    INSERT INTO ##tmpEstimateRow (
        objname
        ,schname
        ,indid
        ,partnr
        ,SizeCurrent
        ,SizeRequested
        ,SampleCurrent
        ,SampleRequested
        )
    EXECUTE sp_executesql @sqlcmd

    SET @sqlcmd = 'EXEC sp_estimate_data_compression_savings ''' + @schema + ''', ''' + @tbname + ''', ''' + cast(@ixid AS VARCHAR) + ''', NULL, ''PAGE''';

    INSERT INTO ##tmpEstimatePage (
        objname
        ,schname
        ,indid
        ,partnr
        ,SizeCurrent
        ,SizeRequested
        ,SampleCurrent
        ,SampleRequested
        )
    EXECUTE sp_executesql @sqlcmd

    FETCH NEXT
    FROM cur
    INTO @schema
        ,@tbname
        ,@ixid
END

CLOSE cur

DEALLOCATE cur;

--Update usage and partition_number - If database was restore the sys.dm_db_index_operational_stats will be empty until tables have accesses. Executing the sp_estimate_data_compression_savings first will make those entries appear
UPDATE ##TestDbaCompression
SET
 [PercentScan] =
     case when (i.range_scan_count + i.leaf_insert_count + i.leaf_delete_count + i.leaf_update_count + i.leaf_page_merge_count + i.singleton_lookup_count) = 0 THEN 0
     ELSE i.range_scan_count * 100.0 / NULLIF((i.range_scan_count + i.leaf_insert_count + i.leaf_delete_count + i.leaf_update_count + i.leaf_page_merge_count + i.singleton_lookup_count), 0)
     END
 ,[PercentUpdate] =
    case when (i.range_scan_count + i.leaf_insert_count + i.leaf_delete_count + i.leaf_update_count + i.leaf_page_merge_count + i.singleton_lookup_count) = 0 THEN 0
    ELSE i.leaf_update_count * 100.0 / NULLIF((i.range_scan_count + i.leaf_insert_count + i.leaf_delete_count + i.leaf_update_count + i.leaf_page_merge_count + i.singleton_lookup_count), 0)
    END
FROM sys.dm_db_index_operational_stats(db_id(), NULL, NULL, NULL) i
INNER JOIN ##TestDbaCompression tmp
    ON tmp.ObjectId = i.object_id
    AND tmp.IndexID = i.index_id;


WITH tmp_cte (
    objname
    ,schname
    ,indid
    ,partnr
    ,pct_of_orig_row
    ,pct_of_orig_page
    ,SizeCurrent
    ,SizeRequested
    )
AS (
    SELECT tr.objname
        ,tr.schname
        ,tr.indid
        ,tr.partnr
        ,(tr.SampleRequested * 100) / CASE
            WHEN tr.SampleCurrent = 0
                THEN 1
            ELSE tr.SampleCurrent
            END AS pct_of_orig_row
        ,(tp.SampleRequested * 100) / CASE
            WHEN tp.SampleCurrent = 0
                THEN 1
            ELSE tp.SampleCurrent
            END AS pct_of_orig_page
        ,tr.SizeCurrent
        ,tr.SizeRequested
    FROM ##tmpEstimateRow tr
    INNER JOIN ##tmpEstimatePage tp ON tr.objname = tp.objname
        AND tr.schname = tp.schname
        AND tr.indid = tp.indid
        AND tr.partnr = tp.partnr
    )
UPDATE ##TestDbaCompression
SET [RowEstimatePercentOriginal] = tcte.pct_of_orig_row
    ,[PageEstimatePercentOriginal] = tcte.pct_of_orig_page
    ,SizeCurrent = tcte.SizeCurrent
    ,SizeRequested = tcte.SizeRequested
    ,PercentCompression = 100 - (cast(tcte.[SizeRequested] AS NUMERIC(21, 2)) * 100 / (tcte.[SizeCurrent] - ABS(SIGN(tcte.[SizeCurrent])) + 1))
FROM tmp_cte tcte
    ,##TestDbaCompression tcomp
WHERE tcte.objname = tcomp.TableName
    AND tcte.schname = tcomp.[Schema]
    AND tcte.indid = tcomp.IndexID
    AND tcte.partnr = tcomp.Partition;

WITH tmp_cte2 (
    TableName
    ,[Schema]
    ,IndexID
    ,[CompressionTypeRecommendation]
    )
AS (
    SELECT TableName
        ,[Schema]
        ,IndexID
        ,CASE
            WHEN [RowEstimatePercentOriginal] >= 100
                AND [PageEstimatePercentOriginal] >= 100
                THEN 'NO_GAIN'
            WHEN [PercentUpdate] >= 10
                THEN 'ROW'
            WHEN [PercentScan] <= 1
                AND [PercentUpdate] <= 1
                AND [RowEstimatePercentOriginal] < [PageEstimatePercentOriginal]
                THEN 'ROW'
            WHEN [PercentScan] <= 1
                AND [PercentUpdate] <= 1
                AND [RowEstimatePercentOriginal] > [PageEstimatePercentOriginal]
                THEN 'PAGE'
            WHEN [PercentScan] >= 60
                AND [PercentUpdate] <= 5
                THEN 'PAGE'
            WHEN [PercentScan] <= 35
                AND [PercentUpdate] <= 5
                THEN '?'
            ELSE 'ROW'
            END
    FROM ##TestDbaCompression
    )
UPDATE ##TestDbaCompression
SET [CompressionTypeRecommendation] = tcte2.[CompressionTypeRecommendation]
FROM tmp_cte2 tcte2
    ,##TestDbaCompression tcomp2
WHERE tcte2.TableName = tcomp2.TableName
    AND tcte2.[Schema] = tcomp2.[Schema]
    AND tcte2.IndexID = tcomp2.IndexID;

SET NOCOUNT ON;

SELECT DBName = DB_Name()
    ,[Schema]
    ,[TableName]
    ,[IndexName]
    ,[Partition]
    ,[IndexID]
    ,[IndexType]
    ,[PercentScan]
    ,[PercentUpdate]
    ,[RowEstimatePercentOriginal]
    ,[PageEstimatePercentOriginal]
    ,[CompressionTypeRecommendation]
    ,SizeCurrentKB = [SizeCurrent]
    ,SizeRequestedKB = [SizeRequested]
    ,PercentCompression
FROM ##TestDbaCompression;

IF OBJECT_ID('tempdb..##TestDbaCompression', 'U') IS NOT NULL
    DROP TABLE ##TestDbaCompression

IF OBJECT_ID('tempdb..##tmpEstimateRow', 'U') IS NOT NULL
    DROP TABLE ##tmpEstimateRow

IF OBJECT_ID('tempdb..##tmpEstimatePage', 'U') IS NOT NULL
    DROP TABLE ##tmpEstimatePage;

"
            Write-Message -Level Debug -Message "SQL Statement: $sql"
            [long]$instanceVersionNumber = $($server.VersionString).Replace(".", "")


            #If SQL Server 2016 SP1 (13.0.4001.0) or higher every version supports compression.
            if ($server.EngineEdition -ne "EnterpriseOrDeveloper" -and $instanceVersionNumber -lt 13040010) {
                Stop-Function -Message "Compression before SQLServer 2016 SP1 (13.0.4001.0) is only supported by enterprise, developer or evaluation edition. $server has version $($server.VersionString) and edition is $($server.EngineEdition)." -Target $db -Continue
            }
            #Filter Database list
            try {
                $dbs = $server.Databases | Where-Object IsAccessible

                if ($Database) {
                    $dbs = $dbs | Where-Object { $Database -contains $_.Name -and $_.IsSystemObject -eq 0 }
                }

                else {
                    $dbs = $dbs | Where-Object { $_.IsSystemObject -eq 0 }
                }

                if (Test-Bound "ExcludeDatabase") {
                    $dbs = $dbs | Where-Object Name -NotIn $ExcludeDatabase
                }
            } catch {
                Stop-Function -Message "Unable to gather list of databases for $instance" -Target $instance -ErrorRecord $_ -Continue
            }

            foreach ($db in $dbs) {
                try {
                    $dbCompatibilityLevel = [int]($db.CompatibilityLevel.ToString().Replace('Version', ''))

                    Write-Message -Level Verbose -Message "Querying $instance - $db"
                    if ($db.status -ne 'Normal' -or $db.IsAccessible -eq $false) {
                        Write-Message -Level Warning -Message "$db is not accessible." -Target $db
                        Continue
                    }

                    if ($dbCompatibilityLevel -lt 100) {
                        Stop-Function -Message "$db has a compatibility level lower than Version100 and will be skipped." -Target $db -Continue
                        Continue
                    }
                    #Execute query against individual database and add to output
                    foreach ($row in ($server.Query($sql, $db.Name))) {
                        [PSCustomObject]@{
                            ComputerName                  = $server.ComputerName
                            InstanceName                  = $server.ServiceName
                            SqlInstance                   = $server.DomainInstanceName
                            Database                      = $row.DBName
                            Schema                        = $row.Schema
                            TableName                     = $row.TableName
                            IndexName                     = $row.IndexName
                            Partition                     = $row.Partition
                            IndexID                       = $row.IndexID
                            IndexType                     = $row.IndexType
                            PercentScan                   = $row.PercentScan
                            PercentUpdate                 = $row.PercentUpdate
                            RowEstimatePercentOriginal    = $row.RowEstimatePercentOriginal
                            PageEstimatePercentOriginal   = $row.PageEstimatePercentOriginal
                            CompressionTypeRecommendation = $row.CompressionTypeRecommendation
                            SizeCurrent                   = [DbaSize]($row.SizeCurrentKB * 1024)
                            SizeRequested                 = [DbaSize]($row.SizeRequestedKB * 1024)
                            PercentCompression            = $row.PercentCompression
                        }
                    }
                } catch {
                    Stop-Function -Message "Unable to query $instance - $db" -Target $db -ErrorRecord $_ -Continue
                }
            }
        }
    }
}
# SIG # Begin signature block
# MIIjYAYJKoZIhvcNAQcCoIIjUTCCI00CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCBnlHnpPIX4qyAD
# QRE2SVjtKJJJtS0kmvSJxgEUUpULlaCCHVkwggUaMIIEAqADAgECAhADBbuGIbCh
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
# BgorBgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCAFw131fQjq+2N4NBPTBG1JaFS9
# +PHXb+DLsU+tMe6fvzANBgkqhkiG9w0BAQEFAASCAQCUfHfkLQczPSnBA8Uf5AlM
# cvtKhP2MS+tdiSTaIljYsuf7DmfHiyAkv7aitSyryqsffdzVJLiHoOsh5SZq4efi
# dCEuZ4hScB7hDbNm+szdVuCPg5b2lP5CJu0ezS68nmZmKf6wH9fcIBnmDGvfLcv3
# NmeeByoHlqOgWPdzNPD/Q+9KV1Tr0tr1S0THi/kbHt1piU3lKXOk6X7Lv2taAyT0
# JvlDBv6XIgX/5/IXIUSvM+HU3iQouo4ddRn1MLuTht5hGSB82E9wXIdJnM11usQi
# IMnYFtXvBTszvuSsvsF8PUM3iBbLjFe0nSfclP1pF7U4fdFaOv5m8ZhfkiYTg+AR
# oYIDIDCCAxwGCSqGSIb3DQEJBjGCAw0wggMJAgEBMHcwYzELMAkGA1UEBhMCVVMx
# FzAVBgNVBAoTDkRpZ2lDZXJ0LCBJbmMuMTswOQYDVQQDEzJEaWdpQ2VydCBUcnVz
# dGVkIEc0IFJTQTQwOTYgU0hBMjU2IFRpbWVTdGFtcGluZyBDQQIQDE1pckuU+jwq
# Sj0pB4A9WjANBglghkgBZQMEAgEFAKBpMBgGCSqGSIb3DQEJAzELBgkqhkiG9w0B
# BwEwHAYJKoZIhvcNAQkFMQ8XDTIyMTExNzA4NTc0N1owLwYJKoZIhvcNAQkEMSIE
# IIjo4RCWAMiwujfllD+uAzw9PQmTKwJ1RWbeDL7E4C9+MA0GCSqGSIb3DQEBAQUA
# BIICAIPzBHD7t9c2Md0Rcbb4KMEGzlmuLlqucNWxtJ/0XLY8hf92HOdPwrXQWAAe
# kGi3hNaVn9AynyEX8fDOg5v+0qZi/KMaPaGtql9B26iggNcYVDFiO+BpRCXyhC1u
# 1vnvcYAIF18fAnA/A5eQW6dJxoHmS8nyXzHhyZpb8WUXPF9iZuht9mpvVGuzd2S0
# Xamd4kPmtmYC8eTUBOK9ancxnMXxz0evVTd4aZ2dg3IlLqVAgmXc9JCQ6LeDH/td
# uJrButbtm6KlpnHGasSuOWTDdj/3v9I9aL2wbAhHLvbU3rARSHS8f6QIzgobPbPk
# iG4PUc7UhN3IAXMrD59fzNsFueUbRAdJwlHMa7STy+Bou7jEDo0XmdmX0j3TCmAq
# NE6Mz2Rdvm+WzFuR3bfqiBHWDjnM4UPwLTCipOPyiQ6WQKUmzprRRnyW3NRrSlzD
# XR3rGqD5jpDKHCP4Xrb5fY+w0QjsYpOT02qkLYGWRkFMwKEg3WrugoJBMJDs4qq/
# qRA/74foV5dxDMNWaMnTywJgNkiVfmUppQJ2AbxnPBiqwDS463GxJDko9My0flmo
# 9ar9nWAbFFfxiZkSFqsJHTNWWYXpvHM/6XQkVqhm+oP85Pcg7+7BNXERAd5A5H7d
# FtvkgbHqSYbQLqTxDVvfnqQ+fdok4kCijvpqgwWWTtiSc+1E
# SIG # End signature block
