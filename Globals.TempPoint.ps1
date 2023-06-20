#--------------------------------------------
# Declare Global Variables and Functions here
#--------------------------------------------
### BSONPOSH / Boe Prox http://bsonposh.com/

#region Get-PageFile

function Get-PageFile
{
	
    <#
        .Synopsis 
            Gets the Page File info for specified host
            
        .Description
            Gets the Page File info for specified host
            
        .Parameter ComputerName
            Name of the Computer to get the Paging File info from (Default is localhost.)
            
        .Example
            Get-PageFile
            Description
            -----------
            Gets Page File from local machine
    
        .Example
            Get-PageFile -ComputerName MyServer
            Description
            -----------
            Gets Page File from MyServer
            
        .Example
            $Servers | Get-PageFile
            Description
            -----------
            Gets Page File for each machine in the pipeline
            
        .OUTPUTS
            PSObject
            
        .Notes
            NAME:      Get-PageFile 
            AUTHOR:    YetiCentral\bshell
            Website:   www.bsonposh.com
            #Requires -Version 2.0
    #>
	
	[Cmdletbinding()]
	Param (
		[alias('dnsHostName')]
		[Parameter(ValueFromPipelineByPropertyName = $true, ValueFromPipeline = $true)]
		[string]$ComputerName = $Env:COMPUTERNAME
	)
	
	Process
	{
		Write-Verbose " [Get-PageFile] :: Process Start"
		if ($ComputerName -match "(.*)(\$)$")
		{
			$ComputerName = $ComputerName -replace "(.*)(\$)$", '$1'
		}
		if (Test-Connection $ComputerName -Count 1 -Quiet)
		{
			try
			{
				Write-Verbose " [Get-PageFile] :: Collecting Paging File Info"
				$PagingFiles = Get-WmiObject Win32_PageFile -ComputerName $ComputerName -ErrorAction SilentlyContinue
				if ($PagingFiles)
				{
					foreach ($PageFile in $PagingFiles)
					{
						$myobj = @{
							ComputerName = $ComputerName
							Name		 = $PageFile.Name
							SizeGB	     = [int]($PageFile.FileSize / 1GB)
							InitialSize  = $PageFile.InitialSize
							MaximumSize  = $PageFile.MaximumSize
						}
						
						$obj = New-Object PSObject -Property $myobj
						$obj.PSTypeNames.Clear()
						$obj.PSTypeNames.Add('BSonPosh.Computer.PageFile')
						$obj
					}
				}
				else
				{
					$Pagefile = Get-ChildItem \\$ComputerName\c$\pagefile.sys -Force -ErrorAction SilentlyContinue
					if ($PageFile)
					{
						$myobj = @{
							ComputerName = $ComputerName
							Name		 = $PageFile.Name
							SizeGB	     = [int]($Pagefile.Length / 1GB)
							InitialSize  = "System Managed"
							MaximumSize  = "System Managed"
						}
						
						$obj = New-Object PSObject -Property $myobj
						$obj.PSTypeNames.Clear()
						$obj.PSTypeNames.Add('BSonPosh.Computer.PageFile')
						$obj
					}
					else
					{
						Write-Host "[Get-PageFile] :: No Paging File setting found. Most likely set to system managed or you do not have access."
					}
				}
			}
			catch
			{
				Write-Verbose " [Get-PageFile] :: [$ComputerName] Failed with Error: $($Error[0])"
			}
		}
	}
}

#endregion 

#region Get-PageFileSetting

function Get-PageFileSetting
{
	
    <#
        .Synopsis 
            Gets the Page File setting info for specified host
            
        .Description
            Gets the Page File setting info for specified host
            
        .Parameter ComputerName
            Name of the Computer to get the Page File setting info from (Default is localhost.)
            
        .Example
            Get-PageFileSetting
            Description
            -----------
            Gets Page File setting from local machine
    
        .Example
            Get-PageFileSetting -ComputerName MyServer
            Description
            -----------
            Gets Page File setting from MyServer
            
        .Example
            $Servers | Get-PageFileSetting
            Description
            -----------
            Gets Page File setting for each machine in the pipeline
            
        .OUTPUTS
            PSObject
            
        .Notes
            NAME:      Get-PageFileSetting 
            AUTHOR:    YetiCentral\bshell
            Website:   www.bsonposh.com
            #Requires -Version 2.0
    #>
	
	[Cmdletbinding()]
	Param (
		[alias('dnsHostName')]
		[Parameter(ValueFromPipelineByPropertyName = $true, ValueFromPipeline = $true)]
		[string]$ComputerName = $Env:COMPUTERNAME
	)
	
	Process
	{
		Write-Verbose " [Get-PageFileSetting] :: Process Start"
		if ($ComputerName -match "(.*)(\$)$")
		{
			$ComputerName = $ComputerName -replace "(.*)(\$)$", '$1'
		}
		if (Test-Host $ComputerName -TCPPort 135)
		{
			try
			{
				Write-Verbose " [Get-PageFileSetting] :: Collecting Paging File Info"
				$PagingFiles = Get-WmiObject Win32_PageFileSetting -ComputerName $ComputerName -EnableAllPrivileges
				if ($PagingFiles)
				{
					foreach ($PageFile in $PagingFiles)
					{
						$PageFile
					}
				}
				else
				{
					Return "No Paging File setting found. Most likely set to system managed"
				}
			}
			catch
			{
				Write-Verbose " [Get-PageFileSetting] :: [$ComputerName] Failed with Error: $($Error[0])"
			}
		}
	}
}

#endregion 

#region Get-HostsFile
Function Get-HostsFile
{
<#
.SYNOPSIS
   Retrieves the contents of a hosts file on a specified system
.DESCRIPTION
   Retrieves the contents of a hosts file on a specified system
.PARAMETER Computer
    Computer name to view host file from
.NOTES
    Name: Get-HostsFile
    Author: Boe Prox
    DateCreated: 15Mar2011
.LINK  

http://boeprox.wordpress.com

.EXAMPLE
    Get-HostsFile "server1" 

Description
-----------
Retrieves the contents of the hosts file on 'server1' 

#>
	[cmdletbinding(
				   DefaultParameterSetName = 'Default',
				   ConfirmImpact = 'low'
				   )]
	Param (
		[Parameter(
				   ValueFromPipeline = $True)]
		[string[]]$Computer
		
	)
	Begin
	{
		$psBoundParameters.GetEnumerator() | % {
			Write-Verbose "Parameter: $_"
		}
		If (!$PSBoundParameters['computer'])
		{
			Write-Verbose "No computer name given, using local computername"
			[string[]]$computer = $Env:Computername
		}
		$report = @()
	}
	Process
	{
		Write-Verbose "Starting process of computers"
		ForEach ($c in $computer)
		{
			Write-Verbose "Testing connection of $c"
			If (Test-Connection -ComputerName $c -Quiet -Count 1)
			{
				Write-Verbose "Validating path to hosts file"
				If (Test-Path "\\$c\C$\Windows\system32\drivers\etc\hosts")
				{
					Switch -regex -file ("\\$c\c$\Windows\system32\drivers\etc\hosts")
					{
						"^\d\w+" {
							Write-Verbose "Adding IPV4 information to collection"
							$temp = "" | Select Computer, IPV4, IPV6, Hostname, Notes
							$new = $_.Split("") | ? { $_ -ne "" }
							$temp.Computer = $c
							$temp.IPV4 = $new[0]
							$temp.HostName = $new[1]
							If ($new[2] -eq $Null)
							{
								$temp.Notes = "NA"
							}
							Else
							{
								$temp.Notes = $new[2]
							}
							$report += $temp
						}
						Default {
							If (!("\s+" -match $_ -OR $_.StartsWith("#")))
							{
								Write-Verbose "Adding IPV6 information to collection"
								$temp = "" | Select Computer, IPV4, IPV6, Hostname, Notes
								$new = $_.Split("") | ? { $_ -ne "" }
								$temp.Computer = $c
								$temp.IPV6 = $new[0]
								$temp.HostName = $new[1]
								If ($new[2] -eq $Null)
								{
									$temp.Notes = "NA"
								}
								Else
								{
									$temp.Notes = $new[2]
								}
								$report += $temp
							}
						}
					}
				} #EndIF
				ElseIf (Test-Path "\\$c\C$\WinNT\system32\drivers\etc\hosts")
				{
					Switch -regex -file ("\\$c\c$\WinNT\system32\drivers\etc\hosts")
					{
						"^#\w+" {
						}
						"^\d\w+" {
							Write-Verbose "Adding IPV4 information to collection"
							$temp = "" | Select Computer, IPV4, IPV6, Hostname, Notes
							$new = $_.Split("") | ? { $_ -ne "" }
							$temp.Computer = $c
							$temp.IPV4 = $new[0]
							$temp.HostName = $new[1]
							If ($new[2] -eq $Null)
							{
								$temp.Notes = "NA"
							}
							Else
							{
								$temp.Notes = $new[2]
							}
							$report += $temp
						}
						Default {
							If (!("\s+" -match $_ -OR $_.StartsWith("#")))
							{
								Write-Verbose "Adding IPV6 information to collection"
								$temp = "" | Select Computer, IPV4, IPV6, Hostname, Notes
								$new = $_.Split("") | ? { $_ -ne "" }
								$temp.Computer = $c
								$temp.IPV6 = $new[0]
								$temp.HostName = $new[1]
								If ($new[2] -eq $Null)
								{
									$temp.Notes = "NA"
								}
								Else
								{
									$temp.Notes = $new[2]
								}
								$report += $temp
							}
						}
					}
				} #End ElseIf
				Else
				{
					Write-Verbose "No host file found"
					$temp = "" | Select Computer, IPV4, IPV6, Hostname, Notes
					$temp.Computer = $c
					$temp.IPV4 = "NA"
					$temp.IPV6 = "NA"
					$temp.Hostname = "NA"
					$temp.Notes = "Unable to locate host file"
					$report += $temp
				} #End Else
			}
			Else
			{
				Write-Verbose "No computer found"
				$temp = "" | Select Computer, IPV4, IPV6, Hostname, Notes
				$temp.Computer = $c
				$temp.IPV4 = "NA"
				$temp.IPV6 = "NA"
				$temp.Hostname = "NA"
				$temp.Notes = "Unable to locate Computer"
				$report += $temp
			}
		}
	}
	End
	{
		Write-Output $report
	}
}
#endregion Get-HostFileContent

#region Get-DiskPartition 

function Get-DiskPartition
{
	
    <#
        .Synopsis 
            Gets the disk partition info for specified host
            
        .Description
            Gets the disk partition info for specified host
            
        .Parameter ComputerName
            Name of the Computer to get the disk partition info from (Default is localhost.)
            
        .Example
            Get-DiskPartition
            Description
            -----------
            Gets Disk Partitions from local machine
    
        .Example
            Get-DiskPartition -ComputerName MyServer
            Description
            -----------
            Gets Disk Partitions from MyServer
            
        .Example
            $Servers | Get-DiskPartition
            Description
            -----------
            Gets Disk Partitions for each machine in the pipeline
            
        .OUTPUTS
            PSObject
            
        .Notes
        NAME:      Get-DiskPartition 
        AUTHOR:    YetiCentral\bshell
        Website:   www.bsonposh.com
        #Requires -Version 2.0
    #>
	
	[Cmdletbinding()]
	Param (
		[alias('dnsHostName')]
		[Parameter(ValueFromPipelineByPropertyName = $true, ValueFromPipeline = $true)]
		[string]$ComputerName = $Env:COMPUTERNAME
	)
	
	Process
	{
		Write-Verbose " [Get-DiskPartition] :: Process Start"
		if ($ComputerName -match "(.*)(\$)$")
		{
			$ComputerName = $ComputerName -replace "(.*)(\$)$", '$1'
		}
		if (Test-Host $ComputerName -TCPPort 135)
		{
			try
			{
				Write-Verbose " [Get-DiskPartition] :: Getting Partition info use WMI"
				$Partitions = Get-WmiObject Win32_DiskPartition -ComputerName $ComputerName
				Write-Verbose " [Get-DiskPartition] :: Found $($Partitions.Count) partitions"
				foreach ($Partition in $Partitions)
				{
					Write-Verbose " [Get-DiskPartition] :: Creating Hash Table"
					$myobj = @{ }
					
					Write-Verbose " [Get-DiskPartition] :: Adding BlockSize        - $($Partition.BlockSize)"
					$myobj.BlockSize = $Partition.BlockSize
					
					Write-Verbose " [Get-DiskPartition] :: Adding BootPartition    - $($Partition.BootPartition)"
					$myobj.BootPartition = $Partition.BootPartition
					
					Write-Verbose " [Get-DiskPartition] :: Adding ComputerName     - $ComputerName"
					$myobj.ComputerName = $ComputerName
					
					Write-Verbose " [Get-DiskPartition] :: Adding Description      - $($Partition.name)"
					$myobj.Description = $Partition.Name
					
					Write-Verbose " [Get-DiskPartition] :: Adding PrimaryPartition - $($Partition.PrimaryPartition)"
					$myobj.PrimaryPartition = $Partition.PrimaryPartition
					
					Write-Verbose " [Get-DiskPartition] :: Adding Index            - $($Partition.Index)"
					$myobj.Index = $Partition.Index
					
					Write-Verbose " [Get-DiskPartition] :: Adding SizeMB           - $($Partition.Size)"
					$myobj.SizeMB = ($Partition.Size/1mb).ToString("n2", $Culture)
					
					Write-Verbose " [Get-DiskPartition] :: Adding Type             - $($Partition.Type)"
					$myobj.Type = $Partition.Type
					
					Write-Verbose " [Get-DiskPartition] :: Setting IsAligned "
					$myobj.IsAligned = $Partition.StartingOffset % 64kb -eq 0
					
					Write-Verbose " [Get-DiskPartition] :: Creating Object"
					$obj = New-Object PSObject -Property $myobj
					$obj.PSTypeNames.Clear()
					$obj.PSTypeNames.Add('BSonPosh.DiskPartition')
					$obj
				}
			}
			catch
			{
				Write-Verbose " [Get-DiskPartition] :: [$ComputerName] Failed with Error: $($Error[0])"
			}
		}
		Write-Verbose " [Get-DiskPartition] :: Process End"
	}
}

#endregion 

#region Get-DiskSpace

function Get-DiskSpace
{
	
    <#
        .Synopsis  
            Gets the disk space for specified host
            
        .Description
            Gets the disk space for specified host
            
        .Parameter ComputerName
            Name of the Computer to get the diskspace from (Default is localhost.)
            
        .Example
            Get-Diskspace
            # Gets diskspace from local machine
    
        .Example
            Get-Diskspace -ComputerName MyServer
            Description
            -----------
            Gets diskspace from MyServer
            
        .Example
            $Servers | Get-Diskspace
            Description
            -----------
            Gets diskspace for each machine in the pipeline
            
        .OUTPUTS
            PSCustomObject
            
        .Notes
            NAME:      Get-DiskSpace 
            AUTHOR:    YetiCentral\bshell
            Website:   www.bsonposh.com
            #Requires -Version 2.0
    #>
	
	[Cmdletbinding()]
	Param (
		[alias('dnsHostName')]
		[Parameter(ValueFromPipelineByPropertyName = $true, ValueFromPipeline = $true)]
		[string]$ComputerName = $Env:COMPUTERNAME
	)
	
	Begin
	{
		Write-Verbose " [Get-DiskSpace] :: Start Begin"
		$Culture = New-Object System.Globalization.CultureInfo("en-US")
		Write-Verbose " [Get-DiskSpace] :: End Begin"
	}
	
	Process
	{
		Write-Verbose " [Get-DiskSpace] :: Start Process"
		if ($ComputerName -match "(.*)(\$)$")
		{
			$ComputerName = $ComputerName -replace "(.*)(\$)$", '$1'
			
		}
		Write-Verbose " [Get-DiskSpace] :: `$ComputerName - $ComputerName"
		Write-Verbose " [Get-DiskSpace] :: Testing Connectivity"
		if (Test-Host $ComputerName -TCPPort 135)
		{
			Write-Verbose " [Get-DiskSpace] :: Connectivity Passed"
			try
			{
				Write-Verbose " [Get-DiskSpace] :: Getting Operating System Version using - Get-WmiObject Win32_OperatingSystem -ComputerName $ComputerName -Property Version"
				$OSVersionInfo = Get-WmiObject Win32_OperatingSystem -ComputerName $ComputerName -Property Version -ea STOP
				Write-Verbose " [Get-DiskSpace] :: Getting Operating System returned $($OSVersionInfo.Version)"
				if ($OSVersionInfo.Version -gt 5.2)
				{
					Write-Verbose " [Get-DiskSpace] :: Version high enough to use Win32_Volume"
					Write-Verbose " [Get-DiskSpace] :: Calling Get-WmiObject -class Win32_Volume -ComputerName $ComputerName -Property `"Name`",`"FreeSpace`",`"Capacity`" -filter `"DriveType=3`""
					$DiskInfos = Get-WmiObject -class Win32_Volume                          `
											   -ComputerName $ComputerName                  `
											   -Property "Name", "FreeSpace", "Capacity"      `
											   -filter "DriveType=3" -ea STOP
					Write-Verbose " [Get-DiskSpace] :: Win32_Volume returned $($DiskInfos.count) disks"
					foreach ($DiskInfo in $DiskInfos)
					{
						$myobj = @{ }
						$myobj.ComputerName = $ComputerName
						$myobj.OSVersion = $OSVersionInfo.Version
						$Myobj.Drive = $DiskInfo.Name
						$Myobj.CapacityGB = [float]($DiskInfo.Capacity/1GB).ToString("n2", $Culture)
						$Myobj.FreeSpaceGB = [float]($DiskInfo.FreeSpace/1GB).ToString("n2", $Culture)
						$Myobj.PercentFree = "{0:P2}" -f ($DiskInfo.FreeSpace / $DiskInfo.Capacity)
						$obj = New-Object PSObject -Property $myobj
						$obj.PSTypeNames.Clear()
						$obj.PSTypeNames.Add('BSonPosh.DiskSpace')
						$obj
					}
				}
				else
				{
					Write-Verbose " [Get-DiskSpace] :: Version not high enough to use Win32_Volume using Win32_LogicalDisk"
					$DiskInfos = Get-WmiObject -class Win32_LogicalDisk                       `
											   -ComputerName $ComputerName                       `
											   -Property SystemName, DeviceID, FreeSpace, Size   `
											   -filter "DriveType=3" -ea STOP
					foreach ($DiskInfo in $DiskInfos)
					{
						$myobj = @{ }
						$myobj.ComputerName = $ComputerName
						$myobj.OSVersion = $OSVersionInfo.Version
						$Myobj.Drive = "{0}\" -f $DiskInfo.DeviceID
						$Myobj.CapacityGB = [float]($DiskInfo.Capacity/1GB).ToString("n2", $Culture)
						$Myobj.FreeSpaceGB = [float]($DiskInfo.FreeSpace/1GB).ToString("n2", $Culture)
						$Myobj.PercentFree = "{0:P2}" -f ($DiskInfo.FreeSpace / $DiskInfo.Capacity)
						$obj = New-Object PSObject -Property $myobj
						$obj.PSTypeNames.Clear()
						$obj.PSTypeNames.Add('BSonPosh.DiskSpace')
						$obj
					}
				}
			}
			catch
			{
				Write-Host " Host [$ComputerName] Failed with Error: $($Error[0])" -ForegroundColor Red
			}
		}
		else
		{
			Write-Host " Host [$ComputerName] Failed Connectivity Test " -ForegroundColor Red
		}
		Write-Verbose " [Get-DiskSpace] :: End Process"
		
	}
}

#endregion 

#region Get-Processor

function Get-Processor
{
	
    <#
        .Synopsis 
            Gets the Computer Processor info for specified host.
            
        .Description
            Gets the Computer Processor info for specified host.
            
        .Parameter ComputerName
            Name of the Computer to get the Computer Processor info from (Default is localhost.)
            
        .Example
            Get-Processor
            Description
            -----------
            Gets Computer Processor info from local machine
    
        .Example
            Get-Processor -ComputerName MyServer
            Description
            -----------
            Gets Computer Processor info from MyServer
            
        .Example
            $Servers | Get-Processor
            Description
            -----------
            Gets Computer Processor info for each machine in the pipeline
            
        .OUTPUTS
            PSCustomObject
            
        .INPUTS
            System.String
            
        .Link
            N/A
            
        .Notes
            NAME:      Get-Processor
            AUTHOR:    bsonposh
            Website:   http://www.bsonposh.com
            Version:   1
            #Requires -Version 2.0
    #>
	
	[Cmdletbinding()]
	Param (
		[alias('dnsHostName')]
		[Parameter(ValueFromPipelineByPropertyName = $true, ValueFromPipeline = $true)]
		[string]$ComputerName = $Env:COMPUTERNAME
	)
	
	Process
	{
		
		if ($ComputerName -match "(.*)(\$)$")
		{
			$ComputerName = $ComputerName -replace "(.*)(\$)$", '$1'
		}
		if (Test-Host -ComputerName $ComputerName -TCPPort 135)
		{
			try
			{
				$CPUS = Get-WmiObject Win32_Processor -ComputerName $ComputerName -ea STOP
				foreach ($CPU in $CPUs)
				{
					$myobj = @{
						ComputerName = $ComputerName
						Name		 = $CPU.Name
						Manufacturer = $CPU.Manufacturer
						Speed	     = $CPU.MaxClockSpeed
						Cores	     = $CPU.NumberOfCores
						L2Cache	     = $CPU.L2CacheSize
						Stepping	 = $CPU.Stepping
					}
				}
				$obj = New-Object PSObject -Property $myobj
				$obj.PSTypeNames.Clear()
				$obj.PSTypeNames.Add('BSonPosh.Computer.Processor')
				$obj
			}
			catch
			{
				Write-Host " Host [$ComputerName] Failed with Error: $($Error[0])" -ForegroundColor Red
			}
		}
		else
		{
			Write-Host " Host [$ComputerName] Failed Connectivity Test " -ForegroundColor Red
		}
		
	}
}

#endregion

#region Get-IP 

function Get-IP
{
	
    <#
        .Synopsis 
            Get the IP of the specified host.
            
        .Description
            Get the IP of the specified host.
            
        .Parameter ComputerName
            Name of the Computer to get IP (Default localhost.)
                
        .Example
            Get-IP
            Description
            -----------
            Get IP information the localhost
            
            
        .OUTPUTS
            PSCustomObject
            
        .INPUTS
            System.String
        
        .Notes
            NAME:      Get-IP
            AUTHOR:    YetiCentral\bshell
            Website:   www.bsonposh.com
            #Requires -Version 2.0
    #>
	
	[Cmdletbinding()]
	Param (
		[alias('dnsHostName')]
		[Parameter(ValueFromPipelineByPropertyName = $true, ValueFromPipeline = $true)]
		[string]$ComputerName = $Env:COMPUTERNAME
	)
	Process
	{
		$NICs = Get-WmiObject Win32_NetworkAdapterConfiguration -Filter "IPEnabled='$True'" -ComputerName $ComputerName
		foreach ($Nic in $NICs)
		{
			$myobj = @{
				Name	   = $Nic.Description
				MacAddress = $Nic.MACAddress
				IP4	       = $Nic.IPAddress | where{ $_ -match "\d+\.\d+\.\d+\.\d+" }
				IP6	       = $Nic.IPAddress | where{ $_ -match "\:\:" }
				IP4Subnet  = $Nic.IPSubnet | where{ $_ -match "\d+\.\d+\.\d+\.\d+" }
				DefaultGWY = $Nic.DefaultIPGateway | Select -First 1
				DNSServer  = $Nic.DNSServerSearchOrder
				WINSPrimary = $Nic.WINSPrimaryServer
				WINSSecondary = $Nic.WINSSecondaryServer
			}
			$obj = New-Object PSObject -Property $myobj
			$obj.PSTypeNames.Clear()
			$obj.PSTypeNames.Add('BSonPosh.IPInfo')
			$obj
		}
	}
}

#endregion 

#region Get-InstalledSoftware

function Get-InstalledSoftware
{
	
    <#
        .Synopsis
            Gets the installed software using Uninstall regkey for specified host.

        .Description
            Gets the installed software using Uninstall regkey for specified host.

        .Parameter ComputerName
            Name of the Computer to get the installed software from (Default is localhost.)

        .Example
            Get-InstalledSoftware
            Description
            -----------
            Gets installed software from local machine

        .Example
            Get-InstalledSoftware -ComputerName MyServer
            Description
            -----------
            Gets installed software from MyServer

        .Example
            $Servers | Get-InstalledSoftware
            Description
            -----------
            Gets installed software for each machine in the pipeline

        .OUTPUTS
            PSCustomObject

        .Notes
            NAME:      Get-InstalledSoftware
            AUTHOR:    YetiCentral\bshell
            Website:   www.bsonposh.com
            #Requires -Version 2.0
    #>
	
	[Cmdletbinding()]
	Param (
		[alias('dnsHostName')]
		[Parameter(ValueFromPipelineByPropertyName = $true, ValueFromPipeline = $true)]
		[string]$ComputerName = $Env:COMPUTERNAME
	)
	begin
	{
		
		Write-Verbose " [Get-InstalledPrograms] :: Start Begin"
		$Culture = New-Object System.Globalization.CultureInfo("en-US")
		Write-Verbose " [Get-InstalledPrograms] :: End Begin"
		
	}
	process
	{
		
		Write-Verbose " [Get-InstalledPrograms] :: Start Process"
		if ($ComputerName -match "(.*)(\$)$")
		{
			$ComputerName = $ComputerName -replace "(.*)(\$)$", '$1'
			
		}
		Write-Verbose " [Get-InstalledPrograms] :: `$ComputerName - $ComputerName"
		Write-Verbose " [Get-InstalledPrograms] :: Testing Connectivity"
		if (Test-Host $ComputerName -TCPPort 135)
		{
			try
			{
				$RegKey = Get-RegistryKey -Path "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall" -ComputerName $ComputerName
				foreach ($key in $RegKey.GetSubKeyNames())
				{
					$SubKey = $RegKey.OpenSubKey($key)
					if ($SubKey.GetValue("DisplayName"))
					{
						$myobj = @{
							Name    = $SubKey.GetValue("DisplayName")
							Version = $SubKey.GetValue("DisplayVersion")
							Vendor  = $SubKey.GetValue("Publisher")
						}
						$obj = New-Object PSObject -Property $myobj
						$obj.PSTypeNames.Clear()
						$obj.PSTypeNames.Add('BSonPosh.SoftwareInfo')
						$obj
					}
				}
			}
			catch
			{
				Write-Host " Host [$ComputerName] Failed with Error: $($Error[0])" -ForegroundColor Red
			}
		}
		else
		{
			Write-Host " Host [$ComputerName] Failed Connectivity Test " -ForegroundColor Red
		}
		Write-Verbose " [Get-InstalledPrograms] :: End Process"
		
	}
}

#endregion 

#region Get-RegistryHive 

function Get-RegistryHive
{
	param ($HiveName)
	Switch -regex ($HiveName)
	{
		"^(HKCR|ClassesRoot|HKEY_CLASSES_ROOT)$"               { [Microsoft.Win32.RegistryHive]"ClassesRoot"; continue }
		"^(HKCU|CurrentUser|HKEY_CURRENTt_USER)$"              { [Microsoft.Win32.RegistryHive]"CurrentUser"; continue }
		"^(HKLM|LocalMachine|HKEY_LOCAL_MACHINE)$"          { [Microsoft.Win32.RegistryHive]"LocalMachine"; continue }
		"^(HKU|Users|HKEY_USERS)$"                          { [Microsoft.Win32.RegistryHive]"Users"; continue }
		"^(HKCC|CurrentConfig|HKEY_CURRENT_CONFIG)$"          { [Microsoft.Win32.RegistryHive]"CurrentConfig"; continue }
		"^(HKPD|PerformanceData|HKEY_PERFORMANCE_DATA)$"    { [Microsoft.Win32.RegistryHive]"PerformanceData"; continue }
		Default                                                { 1; continue }
	}
}

#endregion 

#region Get-RegistryKey 

function Get-RegistryKey
{
	
    <#
        .Synopsis 
            Gets the registry key provide by Path.
            
        .Description
            Gets the registry key provide by Path.
                        
        .Parameter Path 
            Path to the key.
            
        .Parameter ComputerName 
            Computer to get the registry key from.
            
        .Parameter Recurse 
            Recursively returns registry keys starting from the Path.
        
        .Parameter ReadWrite
            Returns the Registry key in Read Write mode.
            
        .Example
            Get-registrykey HKLM\Software\Adobe
            Description
            -----------
            Returns the Registry key for HKLM\Software\Adobe
            
        .Example
            Get-registrykey HKLM\Software\Adobe -ComputerName MyServer1
            Description
            -----------
            Returns the Registry key for HKLM\Software\Adobe on MyServer1
        
        .Example
            Get-registrykey HKLM\Software\Adobe -Recurse
            Description
            -----------
            Returns the Registry key for HKLM\Software\Adobe and all child keys
                    
        .OUTPUTS
            Microsoft.Win32.RegistryKey
            
        .INPUTS
            System.String
            
        .Link
            New-RegistryKey
            Remove-RegistryKey
            Test-RegistryKey
        .Notes
            NAME:      Get-RegistryKey
            AUTHOR:    bsonposh
            Website:   http://www.bsonposh.com
            Version:   1
            #Requires -Version 2.0
    #>
	
	[Cmdletbinding()]
	Param (
		
		[Parameter(mandatory = $true)]
		[string]$Path,
		[Alias("Server")]
		[Parameter(ValueFromPipeline = $true)]
		[string]$ComputerName = $Env:ComputerName,
		[Parameter()]
		[switch]$Recurse,
		[Alias("RW")]
		[Parameter()]
		[switch]$ReadWrite
		
	)
	
	Begin
	{
		
		Write-Verbose " [Get-RegistryKey] :: Start Begin"
		Write-Verbose " [Get-RegistryKey] :: `$Path = $Path"
		Write-Verbose " [Get-RegistryKey] :: Getting `$Hive and `$KeyPath from $Path "
		$PathParts = $Path -split "\\|/", 0, "RegexMatch"
		$Hive = $PathParts[0]
		$KeyPath = $PathParts[1 .. $PathParts.count] -join "\"
		Write-Verbose " [Get-RegistryKey] :: `$Hive = $Hive"
		Write-Verbose " [Get-RegistryKey] :: `$KeyPath = $KeyPath"
		
		Write-Verbose " [Get-RegistryKey] :: End Begin"
		
	}
	
	Process
	{
		
		Write-Verbose " [Get-RegistryKey] :: Start Process"
		Write-Verbose " [Get-RegistryKey] :: `$ComputerName = $ComputerName"
		
		$RegHive = Get-RegistryHive $hive
		
		if ($RegHive -eq 1)
		{
			Write-Host "Invalid Path: $Path, Registry Hive [$hive] is invalid!" -ForegroundColor Red
		}
		else
		{
			Write-Verbose " [Get-RegistryKey] :: `$RegHive = $RegHive"
			
			$BaseKey = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey($RegHive, $ComputerName)
			Write-Verbose " [Get-RegistryKey] :: `$BaseKey = $BaseKey"
			
			if ($ReadWrite)
			{
				try
				{
					$Key = $BaseKey.OpenSubKey($KeyPath, $true)
					$Key = $Key | Add-Member -Name "ComputerName" -MemberType NoteProperty -Value $ComputerName -PassThru
					$Key = $Key | Add-Member -Name "Hive" -MemberType NoteProperty -Value $RegHive -PassThru
					$Key = $Key | Add-Member -Name "Path" -MemberType NoteProperty -Value $KeyPath -PassThru
					$Key.PSTypeNames.Clear()
					$Key.PSTypeNames.Add('BSonPosh.Registry.Key')
					$Key
				}
				catch
				{
					Write-Verbose " [Get-RegistryKey] ::  ERROR :: Unable to Open Key:$KeyPath in $KeyPath with RW Access"
				}
				
			}
			else
			{
				try
				{
					$Key = $BaseKey.OpenSubKey("$KeyPath")
					if ($Key)
					{
						$Key = $Key | Add-Member -Name "ComputerName" -MemberType NoteProperty -Value $ComputerName -PassThru
						$Key = $Key | Add-Member -Name "Hive" -MemberType NoteProperty -Value $RegHive -PassThru
						$Key = $Key | Add-Member -Name "Path" -MemberType NoteProperty -Value $KeyPath -PassThru
						$Key.PSTypeNames.Clear()
						$Key.PSTypeNames.Add('BSonPosh.Registry.Key')
						$Key
					}
				}
				catch
				{
					Write-Verbose " [Get-RegistryKey] ::  ERROR :: Unable to Open SubKey:$Name in $KeyPath"
				}
			}
			
			if ($Recurse)
			{
				Write-Verbose " [Get-RegistryKey] :: Recurse Passed: Processing Subkeys of [$($Key.Name)]"
				$Key
				$SubKeyNames = $Key.GetSubKeyNames()
				foreach ($Name in $SubKeyNames)
				{
					try
					{
						$SubKey = $Key.OpenSubKey($Name)
						if ($SubKey.GetSubKeyNames())
						{
							Write-Verbose " [Get-RegistryKey] :: Calling [Get-RegistryKey] for [$($SubKey.Name)]"
							Get-RegistryKey -ComputerName $ComputerName -Path $SubKey.Name -Recurse
						}
						else
						{
							Get-RegistryKey -ComputerName $ComputerName -Path $SubKey.Name
						}
					}
					catch
					{
						Write-Verbose " [Get-RegistryKey] ::  ERROR :: Write-Host Unable to Open SubKey:$Name in $($Key.Name)"
					}
				}
			}
		}
		Write-Verbose " [Get-RegistryKey] :: End Process"
		
	}
}

#endregion 

#region Get-RegistryValue 

function Get-RegistryValue
{
	
    <#
        .Synopsis 
            Get the value for given the registry value.
            
        .Description
            Get the value for given the registry value.
                        
        .Parameter Path 
            Path to the key that contains the value.
            
        .Parameter Name 
            Name of the Value to check.
            
        .Parameter ComputerName 
            Computer to get value.
            
        .Parameter Recurse 
            Recursively gets the Values on the given key.
            
        .Parameter Default 
            Returns the default value for the Value.
        
        .Example
            Get-RegistryValue HKLM\SOFTWARE\Adobe\SwInstall -Name State 
            Description
            -----------
            Returns value of State under HKLM\SOFTWARE\Adobe\SwInstall.
            
        .Example
            Get-RegistryValue HKLM\Software\Adobe -Name State -ComputerName MyServer1
            Description
            -----------
            Returns value of State under HKLM\SOFTWARE\Adobe\SwInstall on MyServer1
            
        .Example
            Get-RegistryValue HKLM\Software\Adobe -Recurse
            Description
            -----------
            Returns all the values under HKLM\SOFTWARE\Adobe.
    
        .Example
            Get-RegistryValue HKLM\Software\Adobe -ComputerName MyServer1 -Recurse
            Description
            -----------
            Returns all the values under HKLM\SOFTWARE\Adobe on MyServer1
            
        .Example
            Get-RegistryValue HKLM\Software\Adobe -Default
            Description
            -----------
            Returns the default value for HKLM\SOFTWARE\Adobe.
                    
        .OUTPUTS
            PSCustomObject
            
        .INPUTS
            System.String
            
        .Link
            New-RegistryValue
            Remove-RegistryValue
            Test-RegistryValue
            
        .Notes    
            NAME:      Get-RegistryValue
            AUTHOR:    bsonposh
            Website:   http://www.bsonposh.com
            Version:   1
            #Requires -Version 2.0
    #>
	
	[Cmdletbinding()]
	Param (
		[Parameter(mandatory = $true)]
		[string]$Path,
		[Parameter()]
		[string]$Name,
		[Alias("dnsHostName")]
		[Parameter(ValueFromPipeline = $true)]
		[string]$ComputerName = $Env:ComputerName,
		[Parameter()]
		[switch]$Recurse,
		[Parameter()]
		[switch]$Default
	)
	
	Process
	{
		
		Write-Verbose " [Get-RegistryValue] :: Begin Process"
		Write-Verbose " [Get-RegistryValue] :: Calling Get-RegistryKey -Path $path -ComputerName $ComputerName"
		
		if ($Recurse)
		{
			$Keys = Get-RegistryKey -Path $path -ComputerName $ComputerName -Recurse
			foreach ($Key in $Keys)
			{
				if ($Name)
				{
					try
					{
						Write-Verbose " [Get-RegistryValue] :: Getting Value for [$Name]"
						$myobj = @{ } #| Select ComputerName,Name,Value,Type,Path
						$myobj.ComputerName = $ComputerName
						$myobj.Name = $Name
						$myobj.value = $Key.GetValue($Name)
						$myobj.Type = $Key.GetValueKind($Name)
						$myobj.path = $Key
						
						$obj = New-Object PSCustomObject -Property $myobj
						$obj.PSTypeNames.Clear()
						$obj.PSTypeNames.Add('BSonPosh.Registry.Value')
						$obj
					}
					catch
					{
						Write-Verbose " [Get-RegistryValue] ::  ERROR :: Unable to Get Value for:$Name in $($Key.Name)"
					}
					
				}
				elseif ($Default)
				{
					try
					{
						Write-Verbose " [Get-RegistryValue] :: Getting Value for [(Default)]"
						$myobj = @{ } #"" | Select ComputerName,Name,Value,Type,Path
						$myobj.ComputerName = $ComputerName
						$myobj.Name = "(Default)"
						$myobj.value = if ($Key.GetValue("")) { $Key.GetValue("") }
						else { "EMPTY" }
						$myobj.Type = if ($Key.GetValue("")) { $Key.GetValueKind("") }
						else { "N/A" }
						$myobj.path = $Key
						
						$obj = New-Object PSCustomObject -Property $myobj
						$obj.PSTypeNames.Clear()
						$obj.PSTypeNames.Add('BSonPosh.Registry.Value')
						$obj
					}
					catch
					{
						Write-Verbose " [Get-RegistryValue] ::  ERROR :: Unable to Get Value for:(Default) in $($Key.Name)"
					}
				}
				else
				{
					try
					{
						Write-Verbose " [Get-RegistryValue] :: Getting all Values for [$Key]"
						foreach ($ValueName in $Key.GetValueNames())
						{
							Write-Verbose " [Get-RegistryValue] :: Getting all Value for [$ValueName]"
							$myobj = @{ } #"" | Select ComputerName,Name,Value,Type,Path
							$myobj.ComputerName = $ComputerName
							$myobj.Name = if ($ValueName -match "^$") { "(Default)" }
							else { $ValueName }
							$myobj.value = $Key.GetValue($ValueName)
							$myobj.Type = $Key.GetValueKind($ValueName)
							$myobj.path = $Key
							
							$obj = New-Object PSCustomObject -Property $myobj
							$obj.PSTypeNames.Clear()
							$obj.PSTypeNames.Add('BSonPosh.Registry.Value')
							$obj
						}
					}
					catch
					{
						Write-Verbose " [Get-RegistryValue] ::  ERROR :: Unable to Get Value for:$ValueName in $($Key.Name)"
					}
				}
			}
		}
		else
		{
			$Key = Get-RegistryKey -Path $path -ComputerName $ComputerName
			Write-Verbose " [Get-RegistryValue] :: Get-RegistryKey returned $Key"
			if ($Name)
			{
				try
				{
					Write-Verbose " [Get-RegistryValue] :: Getting Value for [$Name]"
					$myobj = @{ } # | Select ComputerName,Name,Value,Type,Path
					$myobj.ComputerName = $ComputerName
					$myobj.Name = $Name
					$myobj.value = $Key.GetValue($Name)
					$myobj.Type = $Key.GetValueKind($Name)
					$myobj.path = $Key
					
					$obj = New-Object PSCustomObject -Property $myobj
					$obj.PSTypeNames.Clear()
					$obj.PSTypeNames.Add('BSonPosh.Registry.Value')
					$obj
				}
				catch
				{
					Write-Verbose " [Get-RegistryValue] ::  ERROR :: Unable to Get Value for:$Name in $($Key.Name)"
				}
			}
			elseif ($Default)
			{
				try
				{
					Write-Verbose " [Get-RegistryValue] :: Getting Value for [(Default)]"
					$myobj = @{ } #"" | Select ComputerName,Name,Value,Type,Path
					$myobj.ComputerName = $ComputerName
					$myobj.Name = "(Default)"
					$myobj.value = if ($Key.GetValue("")) { $Key.GetValue("") }
					else { "EMPTY" }
					$myobj.Type = if ($Key.GetValue("")) { $Key.GetValueKind("") }
					else { "N/A" }
					$myobj.path = $Key
					
					$obj = New-Object PSCustomObject -Property $myobj
					$obj.PSTypeNames.Clear()
					$obj.PSTypeNames.Add('BSonPosh.Registry.Value')
					$obj
				}
				catch
				{
					Write-Verbose " [Get-RegistryValue] ::  ERROR :: Unable to Get Value for:$Name in $($Key.Name)"
				}
			}
			else
			{
				Write-Verbose " [Get-RegistryValue] :: Getting all Values for [$Key]"
				foreach ($ValueName in $Key.GetValueNames())
				{
					Write-Verbose " [Get-RegistryValue] :: Getting all Value for [$ValueName]"
					$myobj = @{ } #"" | Select ComputerName,Name,Value,Type,Path
					$myobj.ComputerName = $ComputerName
					$myobj.Name = if ($ValueName -match "^$") { "(Default)" }
					else { $ValueName }
					$myobj.value = $Key.GetValue($ValueName)
					$myobj.Type = $Key.GetValueKind($ValueName)
					$myobj.path = $Key
					
					$obj = New-Object PSCustomObject -Property $myobj
					$obj.PSTypeNames.Clear()
					$obj.PSTypeNames.Add('BSonPosh.Registry.Value')
					$obj
				}
			}
		}
		
		Write-Verbose " [Get-RegistryValue] :: End Process"
		
	}
}

#endregion 

#region New-RegistryKey 

function New-RegistryKey
{
	
    <#
        .Synopsis 
            Creates a new key in the provide by Path.
            
        .Description
            Creates a new key in the provide by Path.
                        
        .Parameter Path 
            Path to create the key in.
            
        .Parameter ComputerName 
            Computer to the create registry key on.
            
        .Parameter Name 
            Name of the Key to create
        
        .Example
            New-registrykey HKLM\Software\Adobe -Name DeleteMe
            Description
            -----------
            Creates a key called DeleteMe under HKLM\Software\Adobe
            
        .Example
            New-registrykey HKLM\Software\Adobe -Name DeleteMe -ComputerName MyServer1
            Description
            -----------
            Creates a key called DeleteMe under HKLM\Software\Adobe on MyServer1
                    
        .OUTPUTS
            Microsoft.Win32.RegistryKey
            
        .INPUTS
            System.String
            
        .Link
            Get-RegistryKey
            Remove-RegistryKey
            Test-RegistryKey
            
        NAME:      New-RegistryKey
        AUTHOR:    bsonposh
        Website:   http://www.bsonposh.com
        Version:   1
        #Requires -Version 2.0
    #>
	[Cmdletbinding(SupportsShouldProcess = $true)]
	Param (
		[Parameter(mandatory = $true)]
		[string]$Path,
		[Parameter(mandatory = $true)]
		[string]$Name,
		[Alias("Server")]
		[Parameter(ValueFromPipeline = $true)]
		[string]$ComputerName = $Env:ComputerName
	)
	Begin
	{
		
		Write-Verbose " [New-RegistryKey] :: Start Begin"
		$ReadWrite = [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree
		
		Write-Verbose " [New-RegistryKey] :: `$Path = $Path"
		Write-Verbose " [New-RegistryKey] :: Getting `$Hive and `$KeyPath from $Path "
		$PathParts = $Path -split "\\|/", 0, "RegexMatch"
		$Hive = $PathParts[0]
		$KeyPath = $PathParts[1 .. $PathParts.count] -join "\"
		Write-Verbose " [New-RegistryKey] :: `$Hive = $Hive"
		Write-Verbose " [New-RegistryKey] :: `$KeyPath = $KeyPath"
		
		Write-Verbose " [New-RegistryKey] :: End Begin"
		
	}
	Process
	{
		
		Write-Verbose " [Get-RegistryKey] :: Start Process"
		Write-Verbose " [Get-RegistryKey] :: `$ComputerName = $ComputerName"
		
		$RegHive = Get-RegistryHive $hive
		
		if ($RegHive -eq 1)
		{
			Write-Host "Invalid Path: $Path, Registry Hive [$hive] is invalid!" -ForegroundColor Red
		}
		else
		{
			Write-Verbose " [Get-RegistryKey] :: `$RegHive = $RegHive"
			$BaseKey = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey($RegHive, $ComputerName)
			Write-Verbose " [Get-RegistryKey] :: `$BaseKey = $BaseKey"
			$Key = $BaseKey.OpenSubKey($KeyPath, $True)
			if ($PSCmdlet.ShouldProcess($ComputerName, "Creating Key [$Name] under $Path"))
			{
				$Key.CreateSubKey($Name, $ReadWrite)
			}
		}
		Write-Verbose " [Get-RegistryKey] :: End Process"
		
	}
}

#endregion 

#region New-RegistryValue 

function New-RegistryValue
{
	
    <#
        .Synopsis 
            Create a value under the registry key.
            
        .Description
            Create a value under the registry key.
                        
        .Parameter Path 
            Path to the key.
            
        .Parameter Name 
            Name of the Value to create.
            
        .Parameter Value 
            Value to for the new Value.
            
        .Parameter Type
            Type for the new Value. Valid Types: Unknown, String (default,) ExpandString, Binary, DWord, MultiString, a
    nd Qword
            
        .Parameter ComputerName 
            Computer to create the Value on.
            
        .Example
            New-RegistryValue HKLM\SOFTWARE\Adobe\MyKey -Name State -Value "Hi There"
            Description
            -----------
            Creates the Value State and sets the value to "Hi There" under HKLM\SOFTWARE\Adobe\MyKey.
            
        .Example
            New-RegistryValue HKLM\SOFTWARE\Adobe\MyKey -Name State -Value 0 -ComputerName MyServer1
            Description
            -----------
            Creates the Value State and sets the value to "Hi There" under HKLM\SOFTWARE\Adobe\MyKey on MyServer1.
            
        .Example
            New-RegistryValue HKLM\SOFTWARE\Adobe\MyKey -Name MyDWord -Value 0 -Type DWord
            Description
            -----------
            Creates the DWORD Value MyDWord and sets the value to 0 under HKLM\SOFTWARE\Adobe\MyKey.
                    
        .OUTPUTS
            System.Boolean
            
        .INPUTS
            System.String
            
        .Link
            New-RegistryValue
            Remove-RegistryValue
            Get-RegistryValue
            
        NAME:      Test-RegistryValue
        AUTHOR:    bsonposh
        Website:   http://www.bsonposh.com
        Version:   1
        #Requires -Version 2.0
    #>
	
	[Cmdletbinding(SupportsShouldProcess = $true)]
	Param (
		[Parameter(mandatory = $true)]
		[string]$Path,
		[Parameter(mandatory = $true)]
		[string]$Name,
		[Parameter()]
		[string]$Value,
		[Parameter()]
		[string]$Type,
		[Alias("dnsHostName")]
		[Parameter(ValueFromPipeline = $true)]
		[string]$ComputerName = $Env:ComputerName
	)
	Begin
	{
		
		Write-Verbose " [New-RegistryValue] :: Start Begin"
		Write-Verbose " [New-RegistryValue] :: `$Path = $Path"
		Write-Verbose " [New-RegistryValue] :: `$Name = $Name"
		Write-Verbose " [New-RegistryValue] :: `$Value = $Value"
		
		Switch ($Type)
		{
			"Unknown"       { $ValueType = [Microsoft.Win32.RegistryValueKind]::Unknown; continue }
			"String"        { $ValueType = [Microsoft.Win32.RegistryValueKind]::String; continue }
			"ExpandString"  { $ValueType = [Microsoft.Win32.RegistryValueKind]::ExpandString; continue }
			"Binary"        { $ValueType = [Microsoft.Win32.RegistryValueKind]::Binary; continue }
			"DWord"         { $ValueType = [Microsoft.Win32.RegistryValueKind]::DWord; continue }
			"MultiString"   { $ValueType = [Microsoft.Win32.RegistryValueKind]::MultiString; continue }
			"QWord"         { $ValueType = [Microsoft.Win32.RegistryValueKind]::QWord; continue }
			default         { $ValueType = [Microsoft.Win32.RegistryValueKind]::String; continue }
		}
		Write-Verbose " [New-RegistryValue] :: `$Type = $Type"
		Write-Verbose " [New-RegistryValue] :: End Begin"
		
	}
	
	Process
	{
		
		if (Test-RegistryValue -Path $path -Name $Name -ComputerName $ComputerName)
		{
			"Registry value already exist"
		}
		else
		{
			Write-Verbose " [New-RegistryValue] :: Start Process"
			Write-Verbose " [New-RegistryValue] :: Calling Get-RegistryKey -Path $path -ComputerName $ComputerName"
			$Key = Get-RegistryKey -Path $path -ComputerName $ComputerName -ReadWrite
			Write-Verbose " [New-RegistryValue] :: Get-RegistryKey returned $Key"
			Write-Verbose " [New-RegistryValue] :: Setting Value for [$Name]"
			if ($PSCmdlet.ShouldProcess($ComputerName, "Creating Value [$Name] under $Path with value [$Value]"))
			{
				if ($Value)
				{
					$Key.SetValue($Name, $Value, $ValueType)
				}
				else
				{
					$Key.SetValue($Name, $ValueType)
				}
				Write-Verbose " [New-RegistryValue] :: Returning New Key: Get-RegistryValue -Path $path -Name $Name -ComputerName $ComputerName"
				Get-RegistryValue -Path $path -Name $Name -ComputerName $ComputerName
			}
		}
		Write-Verbose " [New-RegistryValue] :: End Process"
		
	}
}

#endregion 

#region Remove-RegistryKey 

function Remove-RegistryKey
{
	
    <#
        .Synopsis 
            Removes a new key in the provide by Path.
            
        .Description
            Removes a new key in the provide by Path.
                        
        .Parameter Path 
            Path to remove the registry key from.
            
        .Parameter ComputerName 
            Computer to remove the registry key from.
            
        .Parameter Name 
            Name of the registry key to remove.
            
        .Parameter Recurse 
            Recursively removes registry key and all children from path.
        
        .Example
            Remove-registrykey HKLM\Software\Adobe -Name DeleteMe
            Description
            -----------
            Removes the registry key called DeleteMe under HKLM\Software\Adobe
            
        .Example
            Remove-RegistryKey HKLM\Software\Adobe -Name DeleteMe -ComputerName MyServer1
            Description
            -----------
            Removes the key called DeleteMe under HKLM\Software\Adobe on MyServer1
            
        .Example
            Remove-RegistryKey HKLM\Software\Adobe -Name DeleteMe -ComputerName MyServer1 -Recurse
            Description
            -----------
            Removes the key called DeleteMe under HKLM\Software\Adobe on MyServer1 and all child keys.
                    
        .OUTPUTS
            $null
            
        .INPUTS
            System.String
            
        .Link
            Get-RegistryKey
            New-RegistryKey
            Test-RegistryKey
            
        .Notes
        NAME:      Remove-RegistryKey
        AUTHOR:    bsonposh
        Website:   http://www.bsonposh.com
        Version:   1
        #Requires -Version 2.0
    #>
	
	[Cmdletbinding(SupportsShouldProcess = $true)]
	Param (
		
		[Parameter(mandatory = $true)]
		[string]$Path,
		[Parameter(mandatory = $true)]
		[string]$Name,
		[Alias("Server")]
		[Parameter(ValueFromPipeline = $true)]
		[string]$ComputerName = $Env:ComputerName,
		[Parameter()]
		[switch]$Recurse
	)
	Begin
	{
		
		Write-Verbose " [Remove-RegistryKey] :: Start Begin"
		
		Write-Verbose " [Remove-RegistryKey] :: `$Path = $Path"
		Write-Verbose " [Remove-RegistryKey] :: Getting `$Hive and `$KeyPath from $Path "
		$PathParts = $Path -split "\\|/", 0, "RegexMatch"
		$Hive = $PathParts[0]
		$KeyPath = $PathParts[1 .. $PathParts.count] -join "\"
		Write-Verbose " [Remove-RegistryKey] :: `$Hive = $Hive"
		Write-Verbose " [Remove-RegistryKey] :: `$KeyPath = $KeyPath"
		
		Write-Verbose " [Remove-RegistryKey] :: End Begin"
		
	}
	
	Process
	{
		
		Write-Verbose " [Remove-RegistryKey] :: Start Process"
		Write-Verbose " [Remove-RegistryKey] :: `$ComputerName = $ComputerName"
		
		if (Test-RegistryKey -Path $path\$name -ComputerName $ComputerName)
		{
			$RegHive = Get-RegistryHive $hive
			
			if ($RegHive -eq 1)
			{
				Write-Host "Invalid Path: $Path, Registry Hive [$hive] is invalid!" -ForegroundColor Red
			}
			else
			{
				Write-Verbose " [Remove-RegistryKey] :: `$RegHive = $RegHive"
				$BaseKey = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey($RegHive, $ComputerName)
				Write-Verbose " [Remove-RegistryKey] :: `$BaseKey = $BaseKey"
				
				$Key = $BaseKey.OpenSubKey($KeyPath, $True)
				
				if ($PSCmdlet.ShouldProcess($ComputerName, "Deleteing Key [$Name]"))
				{
					if ($Recurse)
					{
						Write-Verbose " [Remove-RegistryKey] :: Calling DeleteSubKeyTree($Name)"
						$Key.DeleteSubKeyTree($Name)
					}
					else
					{
						Write-Verbose " [Remove-RegistryKey] :: Calling DeleteSubKey($Name)"
						$Key.DeleteSubKey($Name)
					}
				}
			}
		}
		else
		{
			"Key [$path\$name] does not exist"
		}
		Write-Verbose " [Remove-RegistryKey] :: End Process"
		
	}
}

#endregion 

#region Remove-RegistryValue 

function Remove-RegistryValue
{
	
    <#
        .Synopsis 
            Removes the value.
            
        .Description
            Removes the value.
                        
        .Parameter Path 
            Path to the key that contains the value.
            
        .Parameter Name 
            Name of the Value to Remove.
    
        .Parameter ComputerName 
            Computer to remove value from.
            
        .Example
            Remove-RegistryValue HKLM\SOFTWARE\Adobe\MyKey -Name State
            Description
            -----------
            Removes the value STATE under HKLM\SOFTWARE\Adobe\MyKey.
            
        .Example
            Remove-RegistryValue HKLM\Software\Adobe\MyKey -Name State -ComputerName MyServer1
            Description
            -----------
            Removes the value STATE under HKLM\SOFTWARE\Adobe\MyKey on MyServer1.
                    
        .OUTPUTS
            $null
            
        .INPUTS
            System.String
            
        .Link
            New-RegistryValue
            Test-RegistryValue
            Get-RegistryValue
            Set-RegistryValue
            
        NAME:      Remove-RegistryValue
        AUTHOR:    bsonposh
        Website:   http://www.bsonposh.com
        Version:   1
        #Requires -Version 2.0
    #>
	
	[Cmdletbinding(SupportsShouldProcess = $true)]
	Param (
		[Parameter(mandatory = $true)]
		[string]$Path,
		[Parameter(mandatory = $true)]
		[string]$Name,
		[Alias("dnsHostName")]
		[Parameter(ValueFromPipeline = $true)]
		[string]$ComputerName = $Env:ComputerName
	)
	Begin
	{
		
		Write-Verbose " [Remove-RegistryValue] :: Start Begin"
		
		Write-Verbose " [Remove-RegistryValue] :: `$Path = $Path"
		Write-Verbose " [Remove-RegistryValue] :: `$Name = $Name"
		
		Write-Verbose " [Remove-RegistryValue] :: End Begin"
		
	}
	
	Process
	{
		
		if (Test-RegistryValue -Path $path -Name $Name -ComputerName $ComputerName)
		{
			Write-Verbose " [Remove-RegistryValue] :: Start Process"
			Write-Verbose " [Remove-RegistryValue] :: Calling Get-RegistryKey -Path $path -ComputerName $ComputerName"
			$Key = Get-RegistryKey -Path $path -ComputerName $ComputerName -ReadWrite
			Write-Verbose " [Remove-RegistryValue] :: Get-RegistryKey returned $Key"
			Write-Verbose " [Remove-RegistryValue] :: Setting Value for [$Name]"
			if ($PSCmdlet.ShouldProcess($ComputerName, "Deleting Value [$Name] under $Path"))
			{
				$Key.DeleteValue($Name)
			}
		}
		else
		{
			"Registry Value is already gone"
		}
		
		Write-Verbose " [Remove-RegistryValue] :: End Process"
		
	}
}

#endregion 

#region Search-Registry 

function Search-Registry
{
	
    <#
        .Synopsis 
            Searchs the Registry.
            
        .Description
            Searchs the Registry.
                        
        .Parameter Filter 
            The RegEx filter you want to search for.
            
        .Parameter Name 
            Name of the Key or Value you want to search for.
        
        .Parameter Value
            Value to search for (Registry Values only.)
            
        .Parameter Path
            Base of the Search. Should be in this format: "Software\Microsoft\..." See the Examples for specific exampl
    es.
            
        .Parameter Hive
            The Base Hive to search in (Default to LocalMachine.)
            
        .Parameter ComputerName 
            Computer to search.
            
        .Parameter KeyOnly
            Only returns Registry Keys. Not valid with -value parameter.
            
        .Example
            Search-Registry -Hive HKLM -Filter "Powershell" -Path "SOFTWARE\Clients"
            Description
            -----------
            Searchs the Registry for Keys or Values that match 'Powershell" in path "SOFTWARE\Clients"
            
        .Example
            Search-Registry -Hive HKLM -Filter "Powershell" -Path "SOFTWARE\Clients" -computername MyServer1
            Description
            -----------
            Searchs the Registry for Keys or Values that match 'Powershell" in path "SOFTWARE\Clients" on MyServer1
            
        .Example
            Search-Registry -Hive HKLM -Name "Powershell" -Path "SOFTWARE\Clients"
            Description
            -----------
            Searchs the Registry keys and values with name 'Powershell' in "SOFTWARE\Clients"
            
        .Example
            Search-Registry -Hive HKLM -Name "Powershell" -Path "SOFTWARE\Clients" -KeyOnly
            Description
            -----------
            Searchs the Registry keys with name 'Powershell' in "SOFTWARE\Clients"
        
        .Example
            Search-Registry -Hive HKLM -Value "Powershell" -Path "SOFTWARE\Clients"
            Description
            -----------
            Searchs the Registry Values with Value of 'Powershell' in "SOFTWARE\Clients"
            
        .OUTPUTS
            Microsoft.Win32.RegistryKey
            
        .INPUTS
            System.String
            
        .Link
            Get-RegistryKey
            Get-RegistryValue
            Test-RegistryKey
        
        .Notes
            NAME:      Search-Registry
            AUTHOR:    bsonposh
            Website:   http://www.bsonposh.com
            Version:   1
            #Requires -Version 2.0
    #>
	
	[Cmdletbinding(DefaultParameterSetName = "ByFilter")]
	Param (
		[Parameter(ParameterSetName = "ByFilter", Position = 0)]
		[string]$Filter = ".*",
		[Parameter(ParameterSetName = "ByName", Position = 0)]
		[string]$Name,
		[Parameter(ParameterSetName = "ByValue", Position = 0)]
		[string]$Value,
		[Parameter()]
		[string]$Path,
		[Parameter()]
		[string]$Hive = "LocalMachine",
		[alias('dnsHostName')]
		[Parameter(ValueFromPipelineByPropertyName = $true, ValueFromPipeline = $true)]
		[string]$ComputerName = $Env:COMPUTERNAME,
		[Parameter()]
		[switch]$KeyOnly
	)
	Begin
	{
		
		Write-Verbose " [Search-Registry] :: Start Begin"
		
		Write-Verbose " [Search-Registry] :: Active Parameter Set $($PSCmdlet.ParameterSetName)"
		switch ($PSCmdlet.ParameterSetName)
		{
			"ByFilter"    { Write-Verbose " [Search-Registry] :: `$Filter = $Filter" }
			"ByName"    { Write-Verbose " [Search-Registry] :: `$Name = $Name" }
			"ByValue"    { Write-Verbose " [Search-Registry] :: `$Value = $Value" }
		}
		$RegHive = Get-RegistryHive $Hive
		Write-Verbose " [Search-Registry] :: `$Hive = $RegHive"
		Write-Verbose " [Search-Registry] :: `$KeyOnly = $KeyOnly"
		
		Write-Verbose " [Search-Registry] :: End Begin"
		
	}
	
	Process
	{
		
		Write-Verbose " [Search-Registry] :: Start Process"
		
		Write-Verbose " [Search-Registry] :: `$ComputerName = $ComputerName"
		switch ($PSCmdlet.ParameterSetName)
		{
			"ByFilter"    {
				if ($KeyOnly)
				{
					if ($Path -and (Test-RegistryKey "$RegHive\$Path"))
					{
						Get-RegistryKey -Path "$RegHive\$Path" -ComputerName $ComputerName -Recurse | ?{ $_.Name -match "$Filter" }
					}
					else
					{
						$BaseKey = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey($RegHive, $ComputerName)
						foreach ($SubKeyName in $BaseKey.GetSubKeyNames())
						{
							try
							{
								$SubKey = $BaseKey.OpenSubKey($SubKeyName, $true)
								Get-RegistryKey -Path $SubKey.Name -ComputerName $ComputerName -Recurse | ?{ $_.Name -match "$Filter" }
							}
							catch
							{
								Write-Host "Access Error on Key [$SubKeyName]... skipping."
							}
						}
					}
				}
				else
				{
					if ($Path -and (Test-RegistryKey "$RegHive\$Path"))
					{
						Get-RegistryKey -Path "$RegHive\$Path" -ComputerName $ComputerName -Recurse | ?{ $_.Name -match "$Filter" }
						Get-RegistryValue -Path "$RegHive\$Path" -ComputerName $ComputerName -Recurse | ?{ $_.Name -match "$Filter" }
					}
					else
					{
						$BaseKey = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey($RegHive, $ComputerName)
						foreach ($SubKeyName in $BaseKey.GetSubKeyNames())
						{
							try
							{
								$SubKey = $BaseKey.OpenSubKey($SubKeyName, $true)
								Get-RegistryKey -Path $SubKey.Name -ComputerName $ComputerName -Recurse | ?{ $_.Name -match "$Filter" }
								Get-RegistryValue -Path $SubKey.Name -ComputerName $ComputerName -Recurse | ?{ $_.Name -match "$Filter" }
							}
							catch
							{
								Write-Host "Access Error on Key [$SubKeyName]... skipping."
							}
						}
					}
				}
			}
			"ByName"    {
				if ($KeyOnly)
				{
					if ($Path -and (Test-RegistryKey "$RegHive\$Path"))
					{
						$NameFilter = "^.*\\{0}$" -f $Name
						Get-RegistryKey -Path "$RegHive\$Path" -ComputerName $ComputerName -Recurse | ?{ $_.Name -match $NameFilter }
					}
					else
					{
						$BaseKey = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey($RegHive, $ComputerName)
						foreach ($SubKeyName in $BaseKey.GetSubKeyNames())
						{
							try
							{
								$SubKey = $BaseKey.OpenSubKey($SubKeyName, $true)
								$NameFilter = "^.*\\{0}$" -f $Name
								Get-RegistryKey -Path "$RegHive\$Path" -ComputerName $ComputerName -Recurse | ?{ $_.Name -match $NameFilter }
							}
							catch
							{
								Write-Host "Access Error on Key [$SubKeyName]... skipping."
							}
						}
					}
				}
				else
				{
					if ($Path -and (Test-RegistryKey "$RegHive\$Path"))
					{
						$NameFilter = "^.*\\{0}$" -f $Name
						Get-RegistryKey -Path "$RegHive\$Path" -ComputerName $ComputerName -Recurse | ?{ $_.Name -match $NameFilter }
						Get-RegistryValue -Path "$RegHive\$Path" -ComputerName $ComputerName -Recurse | ?{ $_.Name -eq $Name }
					}
					else
					{
						$BaseKey = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey($RegHive, $ComputerName)
						foreach ($SubKeyName in $BaseKey.GetSubKeyNames())
						{
							try
							{
								$SubKey = $BaseKey.OpenSubKey($SubKeyName, $true)
								$NameFilter = "^.*\\{0}$" -f $Name
								Get-RegistryKey -Path "$RegHive\$Path" -ComputerName $ComputerName -Recurse | ?{ $_.Name -match $NameFilter }
								Get-RegistryValue -Path $SubKey.Name -ComputerName $ComputerName -Recurse | ?{ $_.Name -eq $Name }
							}
							catch
							{
								Write-Host "Access Error on Key [$SubKeyName]... skipping."
							}
						}
					}
				}
			}
			"ByValue"    {
				if ($Path -and (Test-RegistryKey "$RegHive\$Path"))
				{
					Get-RegistryValue -Path "$RegHive\$Path" -ComputerName $ComputerName -Recurse | ?{ $_.Value -eq $Value }
				}
				else
				{
					$BaseKey = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey($RegHive, $ComputerName)
					foreach ($SubKeyName in $BaseKey.GetSubKeyNames())
					{
						try
						{
							$SubKey = $BaseKey.OpenSubKey($SubKeyName, $true)
							Get-RegistryValue -Path "$RegHive\$Path" -ComputerName $ComputerName -Recurse | ?{ $_.Value -eq $Value }
						}
						catch
						{
							Write-Host "Access Error on Key [$SubKeyName]... skipping."
						}
					}
				}
			}
		}
		
		Write-Verbose " [Search-Registry] :: End Process"
		
	}
}

#endregion 

#region Set-RegistryValue 

function Set-RegistryValue
{
	
    <#
        .Synopsis 
            Sets a value under the registry key.
            
        .Description
            Sets a value under the registry key.
                        
        .Parameter Path 
            Path to the key.
            
        .Parameter Name 
            Name of the Value to Set.
            
        .Parameter Value 
            New Value.
            
        .Parameter Type
            Type for the Value. Valid Types: Unknown, String (default,) ExpandString, Binary, DWord, MultiString, and Q
    word
            
        .Parameter ComputerName 
            Computer to set the Value on.
            
        .Example
            Set-RegistryValue HKLM\SOFTWARE\Adobe\MyKey -Name State -Value "Hi There"
            Description
            -----------
            Sets the Value State and sets the value to "Hi There" under HKLM\SOFTWARE\Adobe\MyKey.
            
        .Example
            Set-RegistryValue HKLM\SOFTWARE\Adobe\MyKey -Name State -Value 0 -ComputerName MyServer1
            Description
            -----------
            Sets the Value State and sets the value to "Hi There" under HKLM\SOFTWARE\Adobe\MyKey on MyServer1.
            
        .Example
            Set-RegistryValue HKLM\SOFTWARE\Adobe\MyKey -Name MyDWord -Value 0 -Type DWord
            Description
            -----------
            Sets the DWORD Value MyDWord and sets the value to 0 under HKLM\SOFTWARE\Adobe\MyKey.
            
        .OUTPUTS
            PSCustomObject
            
        .INPUTS
            System.String
            
        .Link
            New-RegistryValue
            Remove-RegistryValue
            Get-RegistryValue
            Test-RegistryValue
        
        .Notes
            NAME:      Set-RegistryValue
            AUTHOR:    bsonposh
            Website:   http://www.bsonposh.com
            Version:   1
            #Requires -Version 2.0
    #>
	
	[Cmdletbinding(SupportsShouldProcess = $true)]
	Param (
		[Parameter(mandatory = $true)]
		[string]$Path,
		[Parameter(mandatory = $true)]
		[string]$Name,
		[Parameter()]
		[string]$Value,
		[Parameter()]
		[string]$Type,
		[Alias("dnsHostName")]
		[Parameter(ValueFromPipeline = $true)]
		[string]$ComputerName = $Env:ComputerName
	)
	
	Begin
	{
		
		Write-Verbose " [Set-RegistryValue] :: Start Begin"
		
		Write-Verbose " [Set-RegistryValue] :: `$Path = $Path"
		Write-Verbose " [Set-RegistryValue] :: `$Name = $Name"
		Write-Verbose " [Set-RegistryValue] :: `$Value = $Value"
		
		Switch ($Type)
		{
			"Unknown"       { $ValueType = [Microsoft.Win32.RegistryValueKind]::Unknown; continue }
			"String"        { $ValueType = [Microsoft.Win32.RegistryValueKind]::String; continue }
			"ExpandString"  { $ValueType = [Microsoft.Win32.RegistryValueKind]::ExpandString; continue }
			"Binary"        { $ValueType = [Microsoft.Win32.RegistryValueKind]::Binary; continue }
			"DWord"         { $ValueType = [Microsoft.Win32.RegistryValueKind]::DWord; continue }
			"MultiString"   { $ValueType = [Microsoft.Win32.RegistryValueKind]::MultiString; continue }
			"QWord"         { $ValueType = [Microsoft.Win32.RegistryValueKind]::QWord; continue }
			default         { $ValueType = [Microsoft.Win32.RegistryValueKind]::String; continue }
		}
		Write-Verbose " [Set-RegistryValue] :: `$Type = $Type"
		
		Write-Verbose " [Set-RegistryValue] :: End Begin"
		
	}
	
	Process
	{
		
		Write-Verbose " [Set-RegistryValue] :: Start Process"
		
		Write-Verbose " [Set-RegistryValue] :: Calling Get-RegistryKey -Path $path -ComputerName $ComputerName"
		$Key = Get-RegistryKey -Path $path -ComputerName $ComputerName -ReadWrite
		Write-Verbose " [Set-RegistryValue] :: Get-RegistryKey returned $Key"
		Write-Verbose " [Set-RegistryValue] :: Setting Value for [$Name]"
		if ($PSCmdlet.ShouldProcess($ComputerName, "Creating Value [$Name] under $Path with value [$Value]"))
		{
			if ($Value)
			{
				$Key.SetValue($Name, $Value, $ValueType)
			}
			else
			{
				$Key.SetValue($Name, $ValueType)
			}
			Write-Verbose " [Set-RegistryValue] :: Returning New Key: Get-RegistryValue -Path $path -Name $Name -ComputerName $ComputerName"
			Get-RegistryValue -Path $path -Name $Name -ComputerName $ComputerName
		}
		Write-Verbose " [Set-RegistryValue] :: End Process"
		
	}
}

#endregion 

#region Test-RegistryKey 

function Test-RegistryKey
{
	
    <#
        .Synopsis 
            Test for given the registry key.
            
        .Description
            Test for given the registry key.
                        
        .Parameter Path 
            Path to the key.
            
        .Parameter ComputerName 
            Computer to test the registry key on.
            
        .Example
            Test-registrykey HKLM\Software\Adobe
            Description
            -----------
            Returns $True if the Registry key for HKLM\Software\Adobe
            
        .Example
            Test-registrykey HKLM\Software\Adobe -ComputerName MyServer1
            Description
            -----------
            Returns $True if the Registry key for HKLM\Software\Adobe on MyServer1
                    
        .OUTPUTS
            System.Boolean
            
        .INPUTS
            System.String
            
        .Link
            New-RegistryKey
            Remove-RegistryKey
            Get-RegistryKey
        
        .Notes
            NAME:      Test-RegistryKey
            AUTHOR:    bsonposh
            Website:   http://www.bsonposh.com
            Version:   1
            #Requires -Version 2.0
    #>
	
	[Cmdletbinding(SupportsShouldProcess = $true)]
	Param (
		
		[Parameter(ValueFromPipelineByPropertyName = $True, mandatory = $true)]
		[string]$Path,
		[alias('dnsHostName')]
		[Parameter(ValueFromPipelineByPropertyName = $true, ValueFromPipeline = $true)]
		[string]$ComputerName = $Env:COMPUTERNAME
		
	)
	
	Begin
	{
		
		Write-Verbose " [Test-RegistryKey] :: Start Begin"
		
		Write-Verbose " [Test-RegistryKey] :: `$Path = $Path"
		Write-Verbose " [Test-RegistryKey] :: Getting `$Hive and `$KeyPath from $Path "
		$PathParts = $Path -split "\\|/", 0, "RegexMatch"
		$Hive = $PathParts[0]
		$KeyPath = $PathParts[1 .. $PathParts.count] -join "\"
		Write-Verbose " [Test-RegistryKey] :: `$Hive = $Hive"
		Write-Verbose " [Test-RegistryKey] :: `$KeyPath = $KeyPath"
		
		Write-Verbose " [Test-RegistryKey] :: End Begin"
		
	}
	
	Process
	{
		
		Write-Verbose " [Test-RegistryKey] :: Start Process"
		
		Write-Verbose " [Test-RegistryKey] :: `$ComputerName = $ComputerName"
		
		$RegHive = Get-RegistryHive $hive
		
		if ($RegHive -eq 1)
		{
			Write-Host "Invalid Path: $Path, Registry Hive [$hive] is invalid!" -ForegroundColor Red
		}
		else
		{
			Write-Verbose " [Test-RegistryKey] :: `$RegHive = $RegHive"
			
			$BaseKey = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey($RegHive, $ComputerName)
			Write-Verbose " [Test-RegistryKey] :: `$BaseKey = $BaseKey"
			
			Try
			{
				$Key = $BaseKey.OpenSubKey($KeyPath)
				if ($Key)
				{
					$true
				}
				else
				{
					$false
				}
			}
			catch
			{
				$false
			}
		}
		Write-Verbose " [Test-RegistryKey] :: End Process"
		
	}
}

#endregion 

#region Test-RegistryValue 

function Test-RegistryValue
{
	
    <#
        .Synopsis 
            Test the value for given the registry value.
            
        .Description
            Test the value for given the registry value.
                        
        .Parameter Path 
            Path to the key that contains the value.
            
        .Parameter Name 
            Name of the Value to check.
            
        .Parameter Value 
            Value to check for.
            
        .Parameter ComputerName 
            Computer to test.
            
        .Example
            Test-RegistryValue HKLM\SOFTWARE\Adobe\SwInstall -Name State -Value 0
            Description
            -----------
            Returns $True if the value of State under HKLM\SOFTWARE\Adobe\SwInstall is 0
            
        .Example
            Test-RegistryValue HKLM\Software\Adobe -ComputerName MyServer1
            Description
            -----------
            Returns $True if the value of State under HKLM\SOFTWARE\Adobe\SwInstall is 0 on MyServer1
                    
        .OUTPUTS
            System.Boolean
            
        .INPUTS
            System.String
            
        .Link
            New-RegistryValue
            Remove-RegistryValue
            Get-RegistryValue
        
        .Notes    
            NAME:      Test-RegistryValue
            AUTHOR:    bsonposh
            Website:   http://www.bsonposh.com
            Version:   1
            #Requires -Version 2.0
    #>
	
	[Cmdletbinding()]
	Param (
		
		[Parameter(mandatory = $true)]
		[string]$Path,
		[Parameter(mandatory = $true)]
		[string]$Name,
		[Parameter()]
		[string]$Value,
		[alias('dnsHostName')]
		[Parameter(ValueFromPipelineByPropertyName = $true, ValueFromPipeline = $true)]
		[string]$ComputerName = $Env:COMPUTERNAME
		
	)
	
	Process
	{
		
		Write-Verbose " [Test-RegistryValue] :: Begin Process"
		Write-Verbose " [Test-RegistryValue] :: Calling Get-RegistryKey -Path $path -ComputerName $ComputerName"
		$Key = Get-RegistryKey -Path $path -ComputerName $ComputerName
		Write-Verbose " [Test-RegistryValue] :: Get-RegistryKey returned $Key"
		if ($Value)
		{
			try
			{
				$CurrentValue = $Key.GetValue($Name)
				$Value -eq $CurrentValue
			}
			catch
			{
				$false
			}
		}
		else
		{
			try
			{
				$CurrentValue = $Key.GetValue($Name)
				if ($CurrentValue) { $True }
				else { $false }
			}
			catch
			{
				$false
			}
		}
		Write-Verbose " [Test-RegistryValue] :: End Process"
		
	}
}

#endregion 

#region Get-DiskRelationship
function Get-DiskRelationship
{
	param (
		[string]$computername = "localhost"
	)
	Get-WmiObject -Class Win32_DiskDrive -ComputerName $computername | foreach {
		"`n {0} {1}" -f $($_.Name), $($_.Model)
		
		$query = "ASSOCIATORS OF {Win32_DiskDrive.DeviceID='" `
		+ $_.DeviceID + "'} WHERE ResultClass=Win32_DiskPartition"
		
		Get-WmiObject -Query $query -ComputerName $computername | foreach {
			""
			"Name             : {0}" -f $_.Name
			"Description      : {0}" -f $_.Description
			"PrimaryPartition : {0}" -f $_.PrimaryPartition
			
			$query2 = "ASSOCIATORS OF {Win32_DiskPartition.DeviceID='" `
			+ $_.DeviceID + "'} WHERE ResultClass=Win32_LogicalDisk"
			
			Get-WmiObject -Query $query2 -ComputerName $computername | Format-List Name,
																				   @{ Name = "Disk Size (GB)"; Expression = { "{0:F3}" -f $($_.Size/1GB) } },
																				   @{ Name = "Free Space (GB)"; Expression = { "{0:F3}" -f $($_.FreeSpace/1GB) } }
			
		}
	}
}
#endregion

#region Get-MountPoint
function Get-MountPoint
{
	param (
		[string]$computername = "localhost"
	)
	Get-WmiObject -Class Win32_MountPoint -ComputerName $computername |
	where { $_.Directory -like 'Win32_Directory.Name="*"' } |
	foreach {
		$vol = $_.Volume
		Get-WmiObject -Class Win32_Volume -ComputerName $computername | where { $_.__RELPATH -eq $vol } |
		Select @{ Name = "Folder"; Expression = { $_.Caption } },
			   @{ Name = "Size (GB)"; Expression = { "{0:F3}" -f $($_.Capacity / 1GB) } },
			   @{ Name = "Free (GB)"; Expression = { "{0:F3}" -f $($_.FreeSpace / 1GB) } },
			   @{ Name = "%Free"; Expression = { "{0:F2}" -f $(($_.FreeSpace/$_.Capacity) * 100) } } | ft -AutoSize
	}
}
#endregion

#region Get-MappedDrive
function Get-MappedDrive
{
	param (
		[string]$computername = "localhost"
	)
	Get-WmiObject -Class Win32_MappedLogicalDisk -ComputerName $computername |
	Format-List DeviceId, VolumeName, SessionID, Size, FreeSpace, ProviderName
}
#endregion

#region Test-Host 

function Test-Host
{
	
    <#
        .Synopsis 
            Test a host for connectivity using either WMI ping or TCP port
            
        .Description
            Allows you to test a host for connectivity before further processing
            
        .Parameter Server
            Name of the Server to Process.
            
        .Parameter TCPPort
            TCP Port to connect to. (default 135)
            
        .Parameter Timeout
            Timeout for the TCP connection (default 1 sec)
            
        .Parameter Property
            Name of the Property that contains the value to test.
            
        .Example
            cat ServerFile.txt | Test-Host | Invoke-DoSomething
            Description
            -----------
            To test a list of hosts.
            
        .Example
            cat ServerFile.txt | Test-Host -tcp 80 | Invoke-DoSomething
            Description
            -----------
            To test a list of hosts against port 80.
            
        .Example
            Get-ADComputer | Test-Host -property dnsHostname | Invoke-DoSomething
            Description
            -----------
            To test the output of Get-ADComputer using the dnshostname property
            
            
        .OUTPUTS
            System.Object
            
        .INPUTS
            System.String
            
        .Link
            Test-Port
            
        NAME:      Test-Host
        AUTHOR:    YetiCentral\bshell
        Website:   www.bsonposh.com
        LASTEDIT:  02/04/2009 18:25:15
        #Requires -Version 2.0
    #>
	
	[CmdletBinding()]
	Param (
		
		[Parameter(ValueFromPipelineByPropertyName = $true, ValueFromPipeline = $true, Mandatory = $True)]
		[string]$ComputerName,
		[Parameter()]
		[int]$TCPPort = 80,
		[Parameter()]
		[int]$timeout = 3000,
		[Parameter()]
		[string]$property
		
	)
	Begin
	{
		
		function PingServer
		{
			Param ($MyHost)
			$ErrorActionPreference = "SilentlyContinue"
			Write-Verbose " [PingServer] :: Pinging [$MyHost]"
			try
			{
				$pingresult = Get-WmiObject win32_pingstatus -f "address='$MyHost'"
				$ResultCode = $pingresult.statuscode
				Write-Verbose " [PingServer] :: Ping returned $ResultCode"
				if ($ResultCode -eq 0) { $true }
				else { $false }
			}
			catch
			{
				Write-Verbose " [PingServer] :: Ping Failed with Error: ${error[0]}"
				$false
			}
		}
		
	}
	
	Process
	{
		
		Write-Verbose " [Test-Host] :: Begin Process"
		if ($ComputerName -match "(.*)(\$)$")
		{
			$ComputerName = $ComputerName -replace "(.*)(\$)$", '$1'
		}
		Write-Verbose " [Test-Host] :: ComputerName   : $ComputerName"
		if ($TCPPort)
		{
			Write-Verbose " [Test-Host] :: Timeout  : $timeout"
			Write-Verbose " [Test-Host] :: Port     : $TCPPort"
			if ($property)
			{
				Write-Verbose " [Test-Host] :: Property : $Property"
				$Result = Test-Port $_.$property -tcp $TCPPort -timeout $timeout
				if ($Result)
				{
					if ($_) { $_ }
					else { $ComputerName }
				}
			}
			else
			{
				Write-Verbose " [Test-Host] :: Running - 'Test-Port $ComputerName -tcp $TCPPort -timeout $timeout'"
				$Result = Test-Port $ComputerName -tcp $TCPPort -timeout $timeout
				if ($Result)
				{
					if ($_) { $_ }
					else { $ComputerName }
				}
			}
		}
		else
		{
			if ($property)
			{
				Write-Verbose " [Test-Host] :: Property : $Property"
				try
				{
					if (PingServer $_.$property)
					{
						if ($_) { $_ }
						else { $ComputerName }
					}
				}
				catch
				{
					Write-Verbose " [Test-Host] :: $($_.$property) Failed Ping"
				}
			}
			else
			{
				Write-Verbose " [Test-Host] :: Simple Ping"
				try
				{
					if (PingServer $ComputerName) { $ComputerName }
				}
				catch
				{
					Write-Verbose " [Test-Host] :: $ComputerName Failed Ping"
				}
			}
		}
		Write-Verbose " [Test-Host] :: End Process"
		
	}
	
}

#endregion 

#region Test-Port 

function Test-Port
{
	
    <#
        .Synopsis 
            Test a host to see if the specified port is open.
            
        .Description
            Test a host to see if the specified port is open.
                        
        .Parameter TCPPort 
            Port to test (Default 135.)
            
        .Parameter Timeout 
            How long to wait (in milliseconds) for the TCP connection (Default 3000.)
            
        .Parameter ComputerName 
            Computer to test the port against (Default in localhost.)
            
        .Example
            Test-Port -tcp 3389
            Description
            -----------
            Returns $True if the localhost is listening on 3389
            
        .Example
            Test-Port -tcp 3389 -ComputerName MyServer1
            Description
            -----------
            Returns $True if MyServer1 is listening on 3389
                    
        .OUTPUTS
            System.Boolean
            
        .INPUTS
            System.String
            
        .Link
            Test-Host
            Wait-Port
            
        .Notes
            NAME:      Test-Port
            AUTHOR:    bsonposh
            Website:   http://www.bsonposh.com
            Version:   1
            #Requires -Version 2.0
    #>
	
	[Cmdletbinding()]
	Param (
		[Parameter()]
		[int]$TCPport = 135,
		[Parameter()]
		[int]$TimeOut = 3000,
		[Alias("dnsHostName")]
		[Parameter(ValueFromPipelineByPropertyName = $true, ValueFromPipeline = $true)]
		[String]$ComputerName = $env:COMPUTERNAME
	)
	Begin
	{
		Write-Verbose " [Test-Port] :: Start Script"
		Write-Verbose " [Test-Port] :: Setting Error state = 0"
	}
	
	Process
	{
		
		Write-Verbose " [Test-Port] :: Creating [system.Net.Sockets.TcpClient] instance"
		$tcpclient = New-Object system.Net.Sockets.TcpClient
		
		Write-Verbose " [Test-Port] :: Calling BeginConnect($ComputerName,$TCPport,$null,$null)"
		try
		{
			$iar = $tcpclient.BeginConnect($ComputerName, $TCPport, $null, $null)
			Write-Verbose " [Test-Port] :: Waiting for timeout [$timeout]"
			$wait = $iar.AsyncWaitHandle.WaitOne($TimeOut, $false)
		}
		catch [System.Net.Sockets.SocketException]
		{
			Write-Verbose " [Test-Port] :: Exception: $($_.exception.message)"
			Write-Verbose " [Test-Port] :: End"
			return $false
		}
		catch
		{
			Write-Verbose " [Test-Port] :: General Exception"
			Write-Verbose " [Test-Port] :: End"
			return $false
		}
		
		if (!$wait)
		{
			$tcpclient.Close()
			Write-Verbose " [Test-Port] :: Connection Timeout"
			Write-Verbose " [Test-Port] :: End"
			return $false
		}
		else
		{
			Write-Verbose " [Test-Port] :: Closing TCP Socket"
			try
			{
				$tcpclient.EndConnect($iar) | out-Null
				$tcpclient.Close()
			}
			catch
			{
				Write-Verbose " [Test-Port] :: Unable to Close TCP Socket"
			}
			$true
		}
	}
	End
	{
		Write-Verbose " [Test-Port] :: End Script"
	}
}
#endregion 

#region Get-MemoryConfiguration 

function Get-MemoryConfiguration
{
	
    <#
        .Synopsis 
            Gets the Memory Config for specified host.
            
        .Description
            Gets the Memory Config for specified host.
            
        .Parameter ComputerName
            Name of the Computer to get the Memory Config from (Default is localhost.)
            
        .Example
            Get-MemoryConfiguration
            Description
            -----------
            Gets Memory Config from local machine
    
        .Example
            Get-MemoryConfiguration -ComputerName MyServer
            Description
            -----------
            Gets Memory Config from MyServer
            
        .Example
            $Servers | Get-MemoryConfiguration
            Description
            -----------
            Gets Memory Config for each machine in the pipeline
            
        .OUTPUTS
            PSCustomObject
            
        .Notes
            NAME:      Get-MemoryConfiguration 
            AUTHOR:    YetiCentral\bshell
            Website:   www.bsonposh.com
            #Requires -Version 2.0
    #>
	
	[Cmdletbinding()]
	Param (
		[alias('dnsHostName')]
		[Parameter(ValueFromPipelineByPropertyName = $true, ValueFromPipeline = $true)]
		[string]$ComputerName = $Env:COMPUTERNAME
	)
	
	Process
	{
		
		Write-Verbose " [Get-MemoryConfiguration] :: Begin Process"
		if ($ComputerName -match "(.*)(\$)$")
		{
			$ComputerName = $ComputerName -replace "(.*)(\$)$", '$1'
		}
		if (Test-Host $ComputerName -TCPPort 135)
		{
			Write-Verbose " [Get-MemoryConfiguration] :: Processing $ComputerName"
			try
			{
				$MemorySlots = Get-WmiObject Win32_PhysicalMemory -ComputerName $ComputerName -ea STOP
				foreach ($Dimm in $MemorySlots)
				{
					$myobj = @{ }
					$myobj.ComputerName = $ComputerName
					$myobj.Description = $Dimm.Tag
					$myobj.Slot = $Dimm.DeviceLocator
					$myobj.Speed = $Dimm.Speed
					$myobj.SizeGB = $Dimm.Capacity/1gb
					
					$obj = New-Object PSObject -Property $myobj
					$obj.PSTypeNames.Clear()
					$obj.PSTypeNames.Add('BSonPosh.MemoryConfiguration')
					$obj
				}
			}
			catch
			{
				Write-Host " Host [$ComputerName] Failed with Error: $($Error[0])" -ForegroundColor Red
			}
		}
		else
		{
			Write-Host " Host [$ComputerName] Failed Connectivity Test " -ForegroundColor Red
		}
		Write-Verbose " [Get-MemoryConfiguration] :: End Process"
		
	}
}

#endregion 

#region Get-NetStat 
#Need to Implement
#[Parameter()]
#[int]$ID,
#[Parameter()]
#[int]$RemotePort,
#[Parameter()]
#[string]$RemoteAddress,
function Get-NetStat
{
	
    <#
        .Synopsis 
            Get the Network stats of the local host.
            
        .Description
            Get the Network stats of the local host.
            
        .Parameter ProcessName
            Name of the Process to get Network stats for.
        
        .Parameter State
            State to return: Valid Values are: "LISTENING", "ESTABLISHED", "CLOSE_WAIT", or "TIME_WAIT"

        .Parameter Interval
            Number of times you want to run netstat. Cannot be used with Loop.
            
        .Parameter Sleep
            Time between calls to netstat. Used with Interval or Loop.
            
        .Parameter Loop
            Loops netstat calls until you press ctrl-c. Cannot be used with Internval.
            
        .Example
            Get-NetStat
            Description
            -----------
            Returns all Network stat information on the localhost
        
        .Example
            Get-NetStat -ProcessName chrome
            Description
            -----------
            Returns all Network stat information on the localhost for process chrome.
            
        .Example
            Get-NetStat -State ESTABLISHED
            Description
            -----------
            Returns all the established connections on the localhost
            
        .Example
            Get-NetStat -State ESTABLISHED -Loop
            Description
            -----------
            Loops established connections.
            
        .OUTPUTS
            PSCustomObject
            
        .INPUTS
            System.String
        
        .Notes
            NAME:      Get-NetStat
            AUTHOR:    YetiCentral\bshell
            Website:   www.bsonposh.com
            #Requires -Version 2.0

    #>
	
	[Cmdletbinding(DefaultParameterSetName = "All")]
	Param (
		[Parameter()]
		[string]$ProcessName,
		[Parameter()]
		[ValidateSet("LISTENING", "ESTABLISHED", "CLOSE_WAIT", "TIME_WAIT")]
		[string]$State,
		[Parameter(ParameterSetName = "Interval")]
		[int]$Interval,
		[Parameter()]
		[int]$Sleep = 1,
		[Parameter(ParameterSetName = "Loop")]
		[switch]$Loop
	)
	
	function Parse-Netstat ($NetStat)
	{
		Write-Verbose " [Parse-Netstat] :: Parsing Netstat results"
		switch -regex ($NetStat)
		{
			$RegEx
			{
				Write-Verbose " [Parse-Netstat] :: creating Custom object"
				$myobj = @{
					Protocol	 = $matches.Protocol
					LocalAddress = $matches.LocalAddress.split(":")[0]
					LocalPort    = $matches.LocalAddress.split(":")[1]
					RemoteAddress = $matches.RemoteAddress.split(":")[0]
					RemotePort   = $matches.RemoteAddress.split(":")[1]
					State	     = $matches.State
					ProcessID    = $matches.PID
					ProcessName  = Get-Process -id $matches.PID -ea 0 | %{ $_.name }
				}
				
				$obj = New-Object PSCustomObject -Property $myobj
				$obj.PSTypeNames.Clear()
				$obj.PSTypeNames.Add('BSonPosh.NetStatInfo')
				Write-Verbose " [Parse-Netstat] :: Created object for [$($obj.LocalAddress):$($obj.LocalPort)]"
				
				if ($ProcessName)
				{
					$obj | where{ $_.ProcessName -eq $ProcessName }
				}
				elseif ($State)
				{
					$obj | where{ $_.State -eq $State }
				}
				else
				{
					$obj
				}
				
			}
		}
	}
	
	[RegEX]$RegEx = '\s+(?<Protocol>\S+)\s+(?<LocalAddress>\S+)\s+(?<RemoteAddress>\S+)\s+(?<State>\S+)\s+(?<PID>\S+)'
	$Connections = @{ }
	
	switch -exact ($pscmdlet.ParameterSetName)
	{
		"All"           {
			Write-Verbose " [Get-NetStat] :: ParameterSet - ALL"
			$NetStatResults = netstat -ano | ?{ $_ -match "(TCP|UDP)\s+\d" }
			Parse-Netstat $NetStatResults
		}
		"Interval"      {
			Write-Verbose " [Get-NetStat] :: ParameterSet - Interval"
			for ($i = 1; $i -le $Interval; $i++)
			{
				Start-Sleep $Sleep
				$NetStatResults = netstat -ano | ?{ $_ -match "(TCP|UDP)\s+\d" }
				Parse-Netstat $NetStatResults | Out-String
			}
		}
		"Loop"          {
			Write-Verbose " [Get-NetStat] :: ParameterSet - Loop"
			Write-Host
			Write-Host "Protocol LocalAddress  LocalPort RemoteAddress  RemotePort State       ProcessName   PID"
			Write-Host "-------- ------------  --------- -------------  ---------- -----       -----------   ---" -ForegroundColor White
			$oldPos = $Host.UI.RawUI.CursorPosition
			[console]::TreatControlCAsInput = $true
			while ($true)
			{
				Write-Verbose " [Get-NetStat] :: Getting Netstat data"
				$NetStatResults = netstat -ano | ?{ $_ -match "(TCP|UDP)\s+\d" }
				Write-Verbose " [Get-NetStat] :: Getting Netstat data from Netstat"
				$Results = Parse-Netstat $NetStatResults
				Write-Verbose " [Get-NetStat] :: Parse-NetStat returned $($results.count) results"
				foreach ($Result in $Results)
				{
					$Key = $Result.LocalPort
					$Value = $Result.ProcessID
					$msg = "{0,-9}{1,-14}{2,-10}{3,-15}{4,-11}{5,-12}{6,-14}{7,-10}" -f $Result.Protocol, $Result.LocalAddress, $Result.LocalPort,
					$Result.RemoteAddress, $Result.RemotePort, $Result.State,
					$Result.ProcessName, $Result.ProcessID
					if ($Connections.$Key -eq $Value)
					{
						Write-Host $msg
					}
					else
					{
						$Connections.$Key = $Value
						Write-Host $msg -ForegroundColor Yellow
					}
				}
				if ($Host.UI.RawUI.KeyAvailable -and (3 -eq [int]$Host.UI.RawUI.ReadKey("AllowCtrlC,IncludeKeyUp,NoEcho").Character))
				{
					Write-Host "Exiting now..." -foregroundcolor Yellow
					Write-Host
					[console]::TreatControlCAsInput = $false
					break
				}
				$Host.UI.RawUI.CursorPosition = $oldPos
				start-sleep $Sleep
			}
		}
	}
}

#endregion 

#region Get-NicInfo 

function Get-NICInfo
{
	
    <#
        .Synopsis  
            Gets the NIC info for specified host
            
        .Description
            Gets the NIC info for specified host
            
        .Parameter ComputerName
            Name of the Computer to get the NIC info from (Default is localhost.)
            
        .Example
            Get-NicInfo
            # Gets NIC info from local machine
    
        .Example
            Get-NicInfo -ComputerName MyServer
            Description
            -----------
            Gets NIC info from MyServer
            
        .Example
            $Servers | Get-NicInfo
            Description
            -----------
            Gets NIC info for each machine in the pipeline
            
        .OUTPUTS
            PSCustomObject
            
        .Notes
            NAME:      Get-NicInfo 
            AUTHOR:    YetiCentral\bshell
            Website:   www.bsonposh.com
            #Requires -Version 2.0
    #>
	
	[Cmdletbinding()]
	Param (
		[alias('dnsHostName')]
		[Parameter(ValueFromPipelineByPropertyName = $true, ValueFromPipeline = $true)]
		[string]$ComputerName = $Env:COMPUTERNAME
	)
	
	Process
	{
		if ($ComputerName -match "(.*)(\$)$")
		{
			$ComputerName = $ComputerName -replace "(.*)(\$)$", '$1'
		}
		
		if (Test-Host -ComputerName $ComputerName -TCPPort 135)
		{
			try
			{
				$NICS = Get-WmiObject -class Win32_NetworkAdapterConfiguration -ComputerName $ComputerName
				
				foreach ($NIC in $NICS)
				{
					$Query = "Select Name,NetConnectionID FROM Win32_NetworkAdapter WHERE Index='$($NIC.Index)'"
					$NetConnnectionID = Get-WmiObject -Query $Query -ComputerName $ComputerName
					
					$myobj = @{
						ComputerName = $ComputerName
						Name		 = $NetConnnectionID.Name
						NetID	     = $NetConnnectionID.NetConnectionID
						MacAddress   = $NIC.MacAddress
						IP		     = $NIC.IPAddress | ?{ $_ -match "\d*\.\d*\.\d*\." }
						Subnet	     = $NIC.IPSubnet | ?{ $_ -match "\d*\.\d*\.\d*\." }
						Enabled	     = $NIC.IPEnabled
						Index	     = $NIC.Index
					}
					
					$obj = New-Object PSObject -Property $myobj
					$obj.PSTypeNames.Clear()
					$obj.PSTypeNames.Add('BSonPosh.NICInfo')
					$obj
				}
			}
			catch
			{
				Write-Host " Host [$ComputerName] Failed with Error: $($Error[0])" -ForegroundColor Red
			}
		}
		else
		{
			Write-Host " Host [$ComputerName] Failed Connectivity Test " -ForegroundColor Red
		}
	}
}

#endregion 

#region Get-MotherBoard

function Get-MotherBoard
{
	
    <#
        .Synopsis 
            Gets the Mother Board info for specified host.
            
        .Description
            Gets the Mother Board info for specified host.
            
        .Parameter ComputerName
            Name of the Computer to get the Mother Board info from (Default is localhost.) 
            
        .Example
            Get-MotherBoard
            Description
            -----------
            Gets Mother Board info from local machine
    
        .Example
            Get-MotherBoard -ComputerName MyOtherDesktop
            Description
            -----------
            Gets Mother Board info from MyOtherDesktop
            
        .Example
            $Windows7Machines | Get-MotherBoard
            Description
            -----------
            Gets Mother Board info for each machine in the pipeline
            
        .OUTPUTS
            PSCustomObject
            
        .INPUTS
            System.String
            
        .Link
            N/A
            
        .Notes
            NAME:      Get-MotherBoard
            AUTHOR:    bsonposh
            Website:   http://www.bsonposh.com
            Version:   1
            #Requires -Version 2.0
    #>
	
	[Cmdletbinding()]
	Param (
		[alias('dnsHostName')]
		[Parameter(ValueFromPipelineByPropertyName = $true, ValueFromPipeline = $true)]
		[string]$ComputerName = $Env:COMPUTERNAME
	)
	
	Process
	{
		
		if ($ComputerName -match "(.*)(\$)$")
		{
			$ComputerName = $ComputerName -replace "(.*)(\$)$", '$1'
		}
		if (Test-Host -ComputerName $ComputerName -TCPPort 135)
		{
			try
			{
				$MBInfo = Get-WmiObject Win32_BaseBoard -ComputerName $ComputerName -ea STOP
				$myobj = @{
					ComputerName = $ComputerName
					Name		 = $MBInfo.Product
					Manufacturer = $MBInfo.Manufacturer
					Version	     = $MBInfo.Version
					SerialNumber = $MBInfo.SerialNumber
				}
				
				$obj = New-Object PSObject -Property $myobj
				$obj.PSTypeNames.Clear()
				$obj.PSTypeNames.Add('BSonPosh.Computer.MotherBoard')
				$obj
			}
			catch
			{
				Write-Host " Host [$ComputerName] Failed with Error: $($Error[0])" -ForegroundColor Red
			}
		}
		else
		{
			Write-Host " Host [$ComputerName] Failed Connectivity Test " -ForegroundColor Red
		}
		
	}
}

#endregion # Get-MotherBoard

#region Get-Routetable 

function Get-Routetable
{
	
    <#
        .Synopsis 
            Gets the route table for specified host.
            
        .Description
            Gets the route table for specified host.
            
        .Parameter ComputerName
            Name of the Computer to get the route table from (Default is localhost.)
            
        .Example
            Get-RouteTable
            Description
            -----------
            Gets route table from local machine
    
        .Example
            Get-RouteTable -ComputerName MyServer
            Description
            -----------
            Gets route table from MyServer
            
        .Example
            $Servers | Get-RouteTable
            Description
            -----------
            Gets route table for each machine in the pipeline
            
        .OUTPUTS
            PSCustomObject
            
        .INPUTS
            System.String
            
        .Link
            N/A
            
        .Notes
            NAME:      Get-RouteTable
            AUTHOR:    bsonposh
            Website:   http://www.bsonposh.com
            Version:   1
            #Requires -Version 2.0
    #>
	
	[Cmdletbinding()]
	Param (
		[alias('dnsHostName')]
		[Parameter(ValueFromPipelineByPropertyName = $true, ValueFromPipeline = $true)]
		[string]$ComputerName = $Env:COMPUTERNAME
	)
	process
	{
		
		if ($ComputerName -match "(.*)(\$)$")
		{
			$ComputerName = $ComputerName -replace "(.*)(\$)$", '$1'
		}
		if (Test-Host $ComputerName -TCPPort 135)
		{
			$Routes = Get-WMIObject Win32_IP4RouteTable -ComputerName $ComputerName -Property Name, Mask, NextHop, Metric1, Type
			foreach ($Route in $Routes)
			{
				$myobj = @{ }
				$myobj.ComputerName = $ComputerName
				$myobj.Name = $Route.Name
				$myobj.NetworkMask = $Route.mask
				$myobj.Gateway = if ($Route.NextHop -eq "0.0.0.0") { "On-Link" }
				else { $Route.NextHop }
				$myobj.Metric = $Route.Metric1
				
				$obj = New-Object PSObject -Property $myobj
				$obj.PSTypeNames.Clear()
				$obj.PSTypeNames.Add('BSonPosh.RouteTable')
				$obj
			}
		}
		else
		{
			Write-Host " Host [$ComputerName] Failed Connectivity Test " -ForegroundColor Red
		}
		
	}
}

#endregion 

#region Get-SystemType 

function Get-SystemType
{
	
    <#
        .Synopsis 
            Gets the system type for specified host
            
        .Description
            Gets the system type info for specified host
            
        .Parameter ComputerName
            Name of the Computer to get the System Type from (Default is localhost.)
            
        .Example
            Get-SystemType
            Description
            -----------
            Gets System Type from local machine
    
        .Example
            Get-SystemType -ComputerName MyServer
            Description
            -----------
            Gets System Type from MyServer
            
        .Example
            $Servers | Get-SystemType
            Description
            -----------
            Gets System Type for each machine in the pipeline
            
        .OUTPUTS
            PSObject
            
        .Notes
            NAME:      Get-SystemType 
            AUTHOR:    YetiCentral\bshell
            Website:   www.bsonposh.com
            #Requires -Version 2.0
    #>
	
	[Cmdletbinding()]
	Param (
		[alias('dnsHostName')]
		[Parameter(ValueFromPipelineByPropertyName = $true, ValueFromPipeline = $true)]
		[string]$ComputerName = $Env:COMPUTERNAME
	)
	
	Begin
	{
		
		function ConvertTo-ChassisType($Type)
		{
			switch ($Type)
			{
				1    { "Other" }
				2    { "Unknown" }
				3    { "Desktop" }
				4    { "Low Profile Desktop" }
				5    { "Pizza Box" }
				6    { "Mini Tower" }
				7    { "Tower" }
				8    { "Portable" }
				9    { "Laptop" }
				10    { "Notebook" }
				11    { "Hand Held" }
				12    { "Docking Station" }
				13    { "All in One" }
				14    { "Sub Notebook" }
				15    { "Space-Saving" }
				16    { "Lunch Box" }
				17    { "Main System Chassis" }
				18    { "Expansion Chassis" }
				19    { "SubChassis" }
				20    { "Bus Expansion Chassis" }
				21    { "Peripheral Chassis" }
				22    { "Storage Chassis" }
				23    { "Rack Mount Chassis" }
				24    { "Sealed-Case PC" }
			}
		}
		function ConvertTo-SecurityStatus($Status)
		{
			switch ($Status)
			{
				1    { "Other" }
				2    { "Unknown" }
				3    { "None" }
				4    { "External Interface Locked Out" }
				5    { "External Interface Enabled" }
			}
		}
		
	}
	Process
	{
		
		Write-Verbose " [Get-SystemType] :: Process Start"
		if ($ComputerName -match "(.*)(\$)$")
		{
			$ComputerName = $ComputerName -replace "(.*)(\$)$", '$1'
		}
		if (Test-Host $ComputerName -TCPPort 135)
		{
			try
			{
				Write-Verbose " [Get-SystemType] :: Getting System (Enclosure) Type info use WMI"
				$SystemInfo = Get-WmiObject Win32_SystemEnclosure -ComputerName $ComputerName
				$CSInfo = Get-WmiObject -Query "Select Model FROM Win32_ComputerSystem" -ComputerName $ComputerName
				
				Write-Verbose " [Get-SystemType] :: Creating Hash Table"
				$myobj = @{ }
				Write-Verbose " [Get-SystemType] :: Setting ComputerName   - $ComputerName"
				$myobj.ComputerName = $ComputerName
				
				Write-Verbose " [Get-SystemType] :: Setting Manufacturer   - $($SystemInfo.Manufacturer)"
				$myobj.Manufacturer = $SystemInfo.Manufacturer
				
				Write-Verbose " [Get-SystemType] :: Setting Module   - $($CSInfo.Model)"
				$myobj.Model = $CSInfo.Model
				
				Write-Verbose " [Get-SystemType] :: Setting SerialNumber   - $($SystemInfo.SerialNumber)"
				$myobj.SerialNumber = $SystemInfo.SerialNumber
				
				Write-Verbose " [Get-SystemType] :: Setting SecurityStatus - $($SystemInfo.SecurityStatus)"
				$myobj.SecurityStatus = ConvertTo-SecurityStatus $SystemInfo.SecurityStatus
				
				Write-Verbose " [Get-SystemType] :: Setting Type           - $($SystemInfo.ChassisTypes)"
				$myobj.Type = ConvertTo-ChassisType $SystemInfo.ChassisTypes
				
				Write-Verbose " [Get-SystemType] :: Creating Custom Object"
				$obj = New-Object PSCustomObject -Property $myobj
				$obj.PSTypeNames.Clear()
				$obj.PSTypeNames.Add('BSonPosh.SystemType')
				$obj
			}
			catch
			{
				Write-Verbose " [Get-SystemType] :: [$ComputerName] Failed with Error: $($Error[0])"
			}
		}
		
	}
	
}

#endregion 

#region Get-RebootTime 

function Get-RebootTime
{
    <#
        .Synopsis 
            Gets the reboot time for specified host.
            
        .Description
            Gets the reboot time for specified host.
            
        .Parameter ComputerName
            Name of the Computer to get the reboot time from (Default is localhost.)
            
        .Example
            Get-RebootTime
            Description
            -----------
            Gets OS Version from local     
        
        .Example
            Get-RebootTime -Last
            Description
            -----------
            Gets last reboot time from local machine

        .Example
            Get-RebootTime -ComputerName MyServer
            Description
            -----------
            Gets reboot time from MyServer
            
        .Example
            $Servers | Get-RebootTime
            Description
            -----------
            Gets reboot time for each machine in the pipeline
            
        .OUTPUTS
            PSCustomObject
            
        .INPUTS
            System.String
            
        .Link
            N/A
            
        .Notes
            NAME:      Get-RebootTime
            AUTHOR:    bsonposh
            Website:   http://www.bsonposh.com
            Version:   1
            #Requires -Version 2.0
    #>
	
	[cmdletbinding()]
	Param (
		[alias('dnsHostName')]
		[Parameter(ValueFromPipelineByPropertyName = $true, ValueFromPipeline = $true)]
		[string]$ComputerName = $Env:COMPUTERNAME,
		[Parameter()]
		[Switch]$Last
	)
	process
	{
		
		if ($ComputerName -match "(.*)(\$)$")
		{
			$ComputerName = $ComputerName -replace "(.*)(\$)$", '$1'
		}
		if (Test-Host $ComputerName -TCPPort 135)
		{
			try
			{
				if ($Last)
				{
					$date = Get-WmiObject Win32_OperatingSystem -ComputerName $ComputerName -ea STOP | foreach{ $_.LastBootUpTime }
					$RebootTime = [System.DateTime]::ParseExact($date.split('.')[0], 'yyyyMMddHHmmss', $null)
					$myobj = @{ }
					$myobj.ComputerName = $ComputerName
					$myobj.RebootTime = $RebootTime
					
					$obj = New-Object PSObject -Property $myobj
					$obj.PSTypeNames.Clear()
					$obj.PSTypeNames.Add('BSonPosh.RebootTime')
					$obj
				}
				else
				{
					$Query = "Select * FROM Win32_NTLogEvent WHERE SourceName='eventlog' AND EventCode='6009'"
					Get-WmiObject -Query $Query -ea 0 -ComputerName $ComputerName | foreach {
						$myobj = @{ }
						$RebootTime = [DateTime]::ParseExact($_.TimeGenerated.Split(".")[0], 'yyyyMMddHHmmss', $null)
						$myobj.ComputerName = $ComputerName
						$myobj.RebootTime = $RebootTime
						
						$obj = New-Object PSObject -Property $myobj
						$obj.PSTypeNames.Clear()
						$obj.PSTypeNames.Add('BSonPosh.RebootTime')
						$obj
					}
				}
				
			}
			catch
			{
				Write-Host " Host [$ComputerName] Failed with Error: $($Error[0])" -ForegroundColor Red
			}
		}
		else
		{
			Write-Host " Host [$ComputerName] Failed Connectivity Test " -ForegroundColor Red
		}
		
	}
}

#endregion 


#Calculate uptime for server
function get-UptimeCalc
{
	param (
		$computername = $env:computername
	)
	$osname = Get-CimInstance win32_operatingsystem -ComputerName $computername -ea silentlycontinue
	if ($osname)
	{
		$lastbootuptime = $osname.LastBootUpTime
		$LocalDateTime = $osname.LocalDateTime
		$up = $LocalDateTime - $lastbootuptime
		$uptime = "$($up.Days) days, $($up.Hours)h, $($up.Minutes)mins"
		$output = new-object psobject
		$output |Add-Member noteproperty LastBootUptime $LastBootuptime
		$output |Add-Member noteproperty ComputerName $computername
		$output |Add-Member noteproperty uptime $uptime
		$output | Select-Object computername, LastBootuptime, Uptime
	}
	else
	{
		$output = New-Object psobject
		$output = new-object psobject
		$output |Add-Member noteproperty LastBootUptime "Not Available"
		$output |Add-Member noteproperty ComputerName $computername
		$output |Add-Member noteproperty uptime "Not Available"
		$output | Select-Object computername, LastBootUptime, Uptime
	}
}
# Get data from ini-files
function Get-IniFile
{
	param (
		[parameter(Mandatory = $true)]
		[string]$filePath
	)
	
	$anonymous = "NoSection"
	
	$ini = @{ }
	switch -regex -file $filePath
	{
		"^\[(.+)\]$" # Section  
		{
			$section = $matches[1]
			$ini[$section] = @{ }
			$CommentCount = 0
		}
		
		"^(;.*)$" # Comment  
		{
			if (!($section))
			{
				$section = $anonymous
				$ini[$section] = @{ }
			}
			$value = $matches[1]
			$CommentCount = $CommentCount + 1
			$name = "Comment" + $CommentCount
			$ini[$section][$name] = $value
		}
		
		"(.+?)\s*=\s*(.*)" # Key  
		{
			if (!($section))
			{
				$section = $anonymous
				$ini[$section] = @{ }
			}
			$name, $value = $matches[1 .. 2]
			$ini[$section][$name] = $value
		}
	}
	
	return $ini
}
#Sample function that provides the location of the script
function Get-ScriptDirectory
{
<#
	.SYNOPSIS
		Get-ScriptDirectory returns the proper location of the script.

	.OUTPUTS
		System.String
	
	.NOTES
		Returns the correct path within a packaged executable.
#>
	[OutputType([string])]
	param ()
	if ($null -ne $hostinvocation)
	{
		Split-Path $hostinvocation.MyCommand.path
	}
	else
	{
		Split-Path $script:MyInvocation.MyCommand.Path
	}
}

#Sample variable that provides the location of the script
[string]$ScriptDirectory = Get-ScriptDirectory

Function Write-Log
{
	[CmdletBinding()]
	Param (
		[Parameter(Mandatory = $False)]
		[ValidateSet("INFO", "WARN", "ERROR", "FATAL", "DEBUG")]
		[String]$Level = "INFO",
		[Parameter(Mandatory = $True)]
		[string]$Message
	)
	
	$Stamp = (Get-Date).toString("yyyy/MM/dd HH:mm:ss")
	$Line = "$Stamp $Level $Message"
	"$Stamp $Level $Message" | Out-File -Encoding utf8 $logfile -Append
}
function Update-DataGridView
{
	<#
	.SYNOPSIS
		This functions helps you load items into a DataGridView.

	.DESCRIPTION
		Use this function to dynamically load items into the DataGridView control.

	.PARAMETER  DataGridView
		The DataGridView control you want to add items to.

	.PARAMETER  Item
		The object or objects you wish to load into the DataGridView's items collection.
	
	.PARAMETER  DataMember
		Sets the name of the list or table in the data source for which the DataGridView is displaying data.

	.PARAMETER AutoSizeColumns
	    Resizes DataGridView control's columns after loading the items.
	#>
	Param (
		[ValidateNotNull()]
		[Parameter(Mandatory = $true)]
		[System.Windows.Forms.DataGridView]$DataGridView,
		[ValidateNotNull()]
		[Parameter(Mandatory = $true)]
		$Item,
		[Parameter(Mandatory = $false)]
		[string]$DataMember,
		[System.Windows.Forms.DataGridViewAutoSizeColumnsMode]$AutoSizeColumns = 'None'
	)
	$DataGridView.SuspendLayout()
	$DataGridView.DataMember = $DataMember
	
	if ($null -eq $Item)
	{
		$DataGridView.DataSource = $null
	}
	elseif ($Item -is [System.Data.DataSet] -and $Item.Tables.Count -gt 0)
	{
		$DataGridView.DataSource = $Item.Tables[0]
	}
	elseif ($Item -is [System.ComponentModel.IListSource]`
		-or $Item -is [System.ComponentModel.IBindingList] -or $Item -is [System.ComponentModel.IBindingListView])
	{
		$DataGridView.DataSource = $Item
	}
	else
	{
		$array = New-Object System.Collections.ArrayList
		
		if ($Item -is [System.Collections.IList])
		{
			$array.AddRange($Item)
		}
		else
		{
			$array.Add($Item)
		}
		$DataGridView.DataSource = $array
	}
	
	if ($AutoSizeColumns -ne 'None')
	{
		$DataGridView.AutoResizeColumns($AutoSizeColumns)
	}
	
	$DataGridView.ResumeLayout()
}
function ConvertTo-DataTable
{
	<#
		.SYNOPSIS
			Converts objects into a DataTable.
	
		.DESCRIPTION
			Converts objects into a DataTable, which are used for DataBinding.
	
		.PARAMETER  InputObject
			The input to convert into a DataTable.
	
		.PARAMETER  Table
			The DataTable you wish to load the input into.
	
		.PARAMETER RetainColumns
			This switch tells the function to keep the DataTable's existing columns.
		
		.PARAMETER FilterCIMProperties
			This switch removes CIM properties that start with an underline.
	
		.EXAMPLE
			$DataTable = ConvertTo-DataTable -InputObject (Get-Process)
	#>
	[OutputType([System.Data.DataTable])]
	param (
		$InputObject,
		[ValidateNotNull()]
		[System.Data.DataTable]$Table,
		[switch]$RetainColumns,
		[switch]$FilterCIMProperties)
	
	if ($null -eq $Table)
	{
		$Table = New-Object System.Data.DataTable
	}
	
	if ($null -eq $InputObject)
	{
		$Table.Clear()
		return @( ,$Table)
	}
	
	if ($InputObject -is [System.Data.DataTable])
	{
		$Table = $InputObject
	}
	elseif ($InputObject -is [System.Data.DataSet] -and $InputObject.Tables.Count -gt 0)
	{
		$Table = $InputObject.Tables[0]
	}
	else
	{
		if (-not $RetainColumns -or $Table.Columns.Count -eq 0)
		{
			#Clear out the Table Contents
			$Table.Clear()
			
			if ($null -eq $InputObject) { return } #Empty Data
			
			$object = $null
			#find the first non null value
			foreach ($item in $InputObject)
			{
				if ($null -ne $item)
				{
					$object = $item
					break
				}
			}
			
			if ($null -eq $object) { return } #All null then empty
			
			#Get all the properties in order to create the columns
			foreach ($prop in $object.PSObject.Get_Properties())
			{
				if (-not $FilterCIMProperties -or -not $prop.Name.StartsWith('__')) #filter out CIM properties
				{
					#Get the type from the Definition string
					$type = $null
					
					if ($null -ne $prop.Value)
					{
						try { $type = $prop.Value.GetType() }
						catch { Out-Null }
					}
					
					if ($null -ne $type) # -and [System.Type]::GetTypeCode($type) -ne 'Object')
					{
						[void]$table.Columns.Add($prop.Name, $type)
					}
					else #Type info not found
					{
						[void]$table.Columns.Add($prop.Name)
					}
				}
			}
			
			if ($object -is [System.Data.DataRow])
			{
				foreach ($item in $InputObject)
				{
					$Table.Rows.Add($item)
				}
				return @( ,$Table)
			}
		}
		else
		{
			$Table.Rows.Clear()
		}
		
		foreach ($item in $InputObject)
		{
			$row = $table.NewRow()
			
			if ($item)
			{
				foreach ($prop in $item.PSObject.Get_Properties())
				{
					if ($table.Columns.Contains($prop.Name))
					{
						$row.Item($prop.Name) = $prop.Value
					}
				}
			}
			[void]$table.Rows.Add($row)
		}
	}
	
	return @( ,$Table)
}
function Show-SplashScreen
{
	<#
	.SYNOPSIS
		Displays a splash screen using the specified image.
	
	.PARAMETER Image
		Mandatory Image object that is displayed in the splash screen.
	
	.PARAMETER Title
		(Optional) Sets a title for the splash screen window. 
	
	.PARAMETER Timeout
		The amount of seconds before the splash screen is closed.
		Set to 0 to leave the splash screen open indefinitely.
		Default: 2
	
	.PARAMETER ImageLocation
		The file path or url to the image.

	.PARAMETER PassThru
		Returns the splash screen form control. Use to manually close the form.
	
	.PARAMETER Modal
		The splash screen will hold up the pipeline until it closes.

	.EXAMPLE
		PS C:\> Show-SplashScreen -Image $Image -Title 'Loading...' -Timeout 3

	.EXAMPLE
		PS C:\> Show-SplashScreen -ImageLocation 'C:\Image\MyImage.png' -Title 'Loading...' -Timeout 3

	.EXAMPLE
		PS C:\> $splashScreen = Show-SplashScreen -Image $Image -Title 'Loading...' -PassThru
				#close the splash screen
				$splashScreen.Close()
	.OUTPUTS
		System.Windows.Forms.Form
	
	.NOTES
		Created by SAPIEN Technologies, Inc.

		The size of the splash screen is dependent on the image.
		The required assemblies to use this function outside of a WinForms script:
		Add-Type -AssemblyName System.Windows.Forms
		Add-Type -AssemblyName System.Drawing
#>
	[OutputType([System.Windows.Forms.Form])]
	param
	(
		[Parameter(ParameterSetName = 'Image',
				   Mandatory = $true,
				   Position = 1)]
		[ValidateNotNull()]
		[System.Drawing.Image]$Image,
		[Parameter(Mandatory = $false)]
		[string]$Title,
		[int]$Timeout = 2,
		[Parameter(ParameterSetName = 'ImageLocation',
				   Mandatory = $true,
				   Position = 1)]
		[ValidateNotNullOrEmpty()]
		[string]$ImageLocation,
		[switch]$PassThru,
		[switch]$Modal
	)
	
	#Create a splash screen form to display the image.
	$splashForm = New-Object System.Windows.Forms.Form
	
	#Create a picture box for the image
	$pict = New-Object System.Windows.Forms.PictureBox
	
	if ($Image)
	{
		$pict.Image = $Image;
	}
	else
	{
		$pict.Load($ImageLocation)
	}
	
	$pict.AutoSize = $true
	$pict.Dock = 'Fill'
	$splashForm.Controls.Add($pict)
	
	#Display a title if defined.
	if ($Title)
	{
		$splashForm.Text = $Title
		$splashForm.FormBorderStyle = 'FixedDialog'
	}
	else
	{
		$splashForm.FormBorderStyle = 'None'
	}
	
	#Set a timer
	if ($Timeout -gt 0)
	{
		$timer = New-Object System.Windows.Forms.Timer
		$timer.Interval = $Timeout * 1000
		$timer.Tag = $splashForm
		$timer.add_Tick({
				$this.Tag.Close();
				$this.Stop()
			})
		$timer.Start()
	}
	
	#Show the form
	$splashForm.AutoSize = $true
	$splashForm.AutoSizeMode = 'GrowAndShrink'
	$splashForm.ControlBox = $false
	$splashForm.StartPosition = 'CenterScreen'
	$splashForm.TopMost = $true
	
	if ($Modal) { $splashForm.ShowDialog() }
	else { $splashForm.Show() }
	
	if ($PassThru)
	{
		return $splashForm
	}
}
function Get-DiskDetails
{
	param (
		[string[]]$ComputerName = "LocalHost"
	)
	$Object = @()
	$array = New-Object System.Collections.ArrayList
	foreach ($Computer in $ComputerName)
	{
		if (Test-Connection -ComputerName $Computer -Count 1 -ea 0)
		{
			Write-Verbose "$Computer online"
			$D = Get-CimInstance win32_logicalDisk -ComputerName $Computer | select-object DeviceID, VolumeName, FreeSpace, Size, driveType | ?{ $_.DriveType -eq 3 }
			foreach ($disk in $D)
			{
				$TotalSize = $Disk.Size /1Gb -as [int]
				$InUseSize = ($Disk.Size /1Gb -as [int]) - ($Disk.Freespace / 1Gb -as [int])
				$FreeSpaceGB = $Disk.Freespace / 1Gb -as [int]
				$FreeSpacePer = ((($Disk.Freespace /1Gb -as [float]) / ($Disk.Size / 1Gb -as [float])) * 100) -as [int]
				
				$Object += New-Object PSObject -Property @{
					Name = $Computer.ToUpper(); DeviceID = $Disk.DeviceID; VolumeName = $Disk.VolumeName; SizeGB = $TotalSize; InUseGB = $InUseSize; FreeSpaceGB = $FreeSpaceGB; PercentageGB = $FreeSpacePer
				}
				
			}
		}
	}
	
	$column1 = @{ expression = "Name"; width = 30; label = "Name"; alignment = "left" }
	$column2 = @{ expression = "DeviceID"; width = 15; label = "DeviceID"; alignment = "left" }
	$column3 = @{ expression = "VolumeName"; width = 15; label = "VolumeName"; alignment = "left" }
	$column4 = @{ expression = "SizeGB"; width = 15; label = "SizeGB"; alignment = "left" }
	$column5 = @{ expression = "InUseGB"; width = 15; label = "InUseGB"; alignment = "left" }
	$column6 = @{ expression = "FreeSpaceGB"; width = 15; label = "FreeSpaceGB"; alignment = "left" }
	$column7 = @{ expression = "PercentageGB"; width = 15; label = "PercentageGB"; alignment = "left" }
	
	#$Object|format-table $column1, $column2, $column3 ,$column4, $column5, $column6,$column7 
	
	#$Object.GetEnumerator() 
	$object | format-table $column2, $column3, $column4, $column5, $column6, $column7
	$array.AddRange($Object)
	#$datagridview1.DataSource = $array
	}

#--------------------------------------------
# Variables
#--------------------------------------------

# Name of logfile
$logfile = "$ScriptDirectory\PUST.log"

# Name of xmlfile
$xmlfile = "$ScriptDirectory\PUST.XML"

# Logged on user and domain
$LoggedOnUser = $env:USERNAME
$Domain = $env:USERDOMAIN
$domainUser = $Domain + '\'+ $LoggedOnUser

# Securitygroup for start applikation
$group = "Test visma"

# get members in localgroup
$members = Get-localGroupMember -group $group | Select -ExpandProperty Name

# Get folder and zip-files from backupfolder
$ExistingBackupFolders = Get-ChildItem -Path "$InstallPath\Install\backup" | Select-Object Name

# variables from xml
[xml]$xmlvalues = Get-Content -Path $xmlfile
$installpath = $xmlvalues.Configuration.Installpath

#--------------------------------------------
# Module
#--------------------------------------------
<#
if (-not (Get-Module -name 7Zip4Powershell))
{
	Install-Module 7Zip4Powershell -Force
	Import-Module 7Zip4Powershell -Force
}
#>

#Import-Module -Name "$ScriptDirectory\Discovermodule"
