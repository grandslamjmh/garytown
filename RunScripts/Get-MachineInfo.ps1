<# Gary Blok - @gwblok - GARYTOWN.COM

Get-MachineInfo

This script is designed to grab basic info about a machine.
Note, Network Status for VPN might not work with your VPN software, tested with Pulse & Global Protect.

I'm using it as a Run Script to get information from devices over CMG, as I can't connect to them via Remote PowerShell.


#>
Function Convert-FromUnixDate ($UnixDate) {
    [timezone]::CurrentTimeZone.ToLocalTime(([datetime]'1/1/1970').AddSeconds($UnixDate))
}
Function Test-PendingReboot {
    #Pending Reboot From Adam, and I added the part for ConfigMgr
    #https://adamtheautomator.com/pending-reboot-registry/
    function Test-RegistryKey {
            [OutputType('bool')]
            [CmdletBinding()]
            param
            (
                [Parameter(Mandatory)]
                [ValidateNotNullOrEmpty()]
                [string]$Key
            )
    
            $ErrorActionPreference = 'Stop'

            if (Get-Item -Path $Key -ErrorAction Ignore) {
                $true
            }
        }

        function Test-RegistryValue {
            [OutputType('bool')]
            [CmdletBinding()]
            param
            (
                [Parameter(Mandatory)]
                [ValidateNotNullOrEmpty()]
                [string]$Key,

                [Parameter(Mandatory)]
                [ValidateNotNullOrEmpty()]
                [string]$Value
            )
    
            $ErrorActionPreference = 'Stop'

            if (Get-ItemProperty -Path $Key -Name $Value -ErrorAction Ignore) {
                $true
            }
        }

        function Test-RegistryValueNotNull {
            [OutputType('bool')]
            [CmdletBinding()]
            param
            (
                [Parameter(Mandatory)]
                [ValidateNotNullOrEmpty()]
                [string]$Key,

                [Parameter(Mandatory)]
                [ValidateNotNullOrEmpty()]
                [string]$Value
            )
    
            $ErrorActionPreference = 'Stop'

            if (($regVal = Get-ItemProperty -Path $Key -Name $Value -ErrorAction Ignore) -and $regVal.($Value)) {
                $true
            }
        }

    $tests = @(
            { Test-RegistryKey -Key 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending' }
            { Test-RegistryKey -Key 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootInProgress' }
            { Test-RegistryKey -Key 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired' }
            { Test-RegistryKey -Key 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Component Based Servicing\PackagesPending' }
            { Test-RegistryKey -Key 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\PostRebootReporting' }
            #{ Test-RegistryValueNotNull -Key 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' -Value 'PendingFileRenameOperations' }
            #{ Test-RegistryValueNotNull -Key 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' -Value 'PendingFileRenameOperations2' }
            { 
                # Added test to check first if key exists, using "ErrorAction ignore" will incorrectly return $true
                'HKLM:\SOFTWARE\Microsoft\Updates' | Where-Object { test-path $_ -PathType Container } | ForEach-Object {            
                    (Get-ItemProperty -Path $_ -Name 'UpdateExeVolatile' -ErrorAction Ignore | Select-Object -ExpandProperty UpdateExeVolatile) -ne 0 
                }
            }
            { Test-RegistryValue -Key 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce' -Value 'DVDRebootSignal' }
            { Test-RegistryKey -Key 'HKLM:\SOFTWARE\Microsoft\ServerManager\CurrentRebootAttemps' }
            { Test-RegistryValue -Key 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon' -Value 'JoinDomain' }
            { Test-RegistryValue -Key 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon' -Value 'AvoidSpnSet' }
            {
                # Added test to check first if keys exists, if not each group will return $Null
                # May need to evaluate what it means if one or both of these keys do not exist
                ( 'HKLM:\SYSTEM\CurrentControlSet\Control\ComputerName\ActiveComputerName' | Where-Object { test-path $_ } | %{ (Get-ItemProperty -Path $_ ).ComputerName } ) -ne 
                ( 'HKLM:\SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName' | Where-Object { Test-Path $_ } | %{ (Get-ItemProperty -Path $_ ).ComputerName } )
            }
            {
                # Added test to check first if key exists
                'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Services\Pending' | Where-Object { 
                    (Test-Path $_) -and (Get-ChildItem -Path $_) } | ForEach-Object { $true }
            }
        )


    foreach ($test in $tests) {
	    if (& $test) {
		    $WindowsPendingReboot = "Windows"
            #Write-Output "Windows Pending Reboot: $true"
            #Write-Output $test
	    }
    }

    if (Get-Service -Name CcmExec){
        if ((Invoke-WmiMethod -Namespace 'root\ccm\ClientSDK' -Class CCM_ClientUtilities -Name DetermineIfRebootPending).RebootPending -eq "true" ){
        $CMPendingReboot = "ConfigMgr"
        #Write-Output "CM Pending Reboot $true"
        }
    }
    if ($CMPendingReboot -or $WindowsPendingReboot){
        if ($CMPendingReboot){
            $CMPendingReboot
        }
        if ($WindowsPendingReboot){
            $WindowsPendingReboot
        }
    }
    else {Write-Output "False"}
}
Function Get-TPMVer {

$Manufacturer = (Get-WmiObject -Class:Win32_ComputerSystem).Manufacturer
if ($Manufacturer -match "HP")
    {
    if ($((Get-CimInstance -Namespace "ROOT\cimv2\Security\MicrosoftTpm" -ClassName Win32_TPM).SpecVersion) -match "1.2")
        {
        $versionInfo = (Get-CimInstance -Namespace "ROOT\cimv2\Security\MicrosoftTpm" -ClassName Win32_TPM).ManufacturerVersionInfo
        $verMaj      = [Convert]::ToInt32($versionInfo[0..1] -join '', 16)
        $verMin      = [Convert]::ToInt32($versionInfo[2..3] -join '', 16)
        $verBuild    = [Convert]::ToInt32($versionInfo[4..6] -join '', 16)
        $verRevision = 0
        [version]$ver = "$verMaj`.$verMin`.$verBuild`.$verRevision"
        Write-Output "TPM Verion: $ver | Spec: $((Get-CimInstance -Namespace "ROOT\cimv2\Security\MicrosoftTpm" -ClassName Win32_TPM).SpecVersion)"
        }
    else {Write-Output "TPM Verion: $((Get-CimInstance -Namespace "ROOT\cimv2\Security\MicrosoftTpm" -ClassName Win32_TPM).ManufacturerVersion) | Spec: $((Get-CimInstance -Namespace "ROOT\cimv2\Security\MicrosoftTpm" -ClassName Win32_TPM).SpecVersion)"}
    }

else
    {
    if ($((Get-CimInstance -Namespace "ROOT\cimv2\Security\MicrosoftTpm" -ClassName Win32_TPM).SpecVersion) -match "1.2")
        {
        Write-Output "TPM Verion: $((Get-CimInstance -Namespace "ROOT\cimv2\Security\MicrosoftTpm" -ClassName Win32_TPM).ManufacturerVersion) | Spec: $((Get-CimInstance -Namespace "ROOT\cimv2\Security\MicrosoftTpm" -ClassName Win32_TPM).SpecVersion)"
        }
    else {Write-Output "TPM Verion: $((Get-CimInstance -Namespace "ROOT\cimv2\Security\MicrosoftTpm" -ClassName Win32_TPM).ManufacturerVersion) | Spec: $((Get-CimInstance -Namespace "ROOT\cimv2\Security\MicrosoftTpm" -ClassName Win32_TPM).SpecVersion)"}
    }
}
$BIOSInfo = Get-WmiObject -Class 'Win32_Bios'

# Get the current BIOS release date and format it to datetime
$CurrentBIOSDate = [System.Management.ManagementDateTimeConverter]::ToDatetime($BIOSInfo.ReleaseDate).ToUniversalTime()

$Manufacturer = (Get-WmiObject -Class:Win32_ComputerSystem).Manufacturer
$ManufacturerBaseBoard = (Get-CimInstance -Namespace root/cimv2 -ClassName Win32_BaseBoard).Manufacturer
$ComputerModel = (Get-WmiObject -Class:Win32_ComputerSystem).Model
if ($ManufacturerBaseBoard -eq "Intel Corporation")
    {
    $ComputerModel = (Get-CimInstance -Namespace root/cimv2 -ClassName Win32_BaseBoard).Product
    }
$HPProdCode = (Get-CimInstance -Namespace root/cimv2 -ClassName Win32_BaseBoard).Product


Write-Output "Computer Name: $env:computername"
$CurrentOSInfo = Get-Item -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
$InstallDate_CurrentOS = Convert-FromUnixDate $CurrentOSInfo.GetValue('InstallDate')
$WindowsRelease = $CurrentOSInfo.GetValue('ReleaseId')
if ($WindowsRelease -eq "2009"){$WindowsRelease = $CurrentOSInfo.GetValue('DisplayVersion')}
$BuildUBR_CurrentOS = $($CurrentOSInfo.GetValue('CurrentBuild'))+"."+$($CurrentOSInfo.GetValue('UBR'))
Write-Output "Windows $WindowsRelease | $BuildUBR_CurrentOS | Installed: $InstallDate_CurrentOS"
$LastReboot = (Get-CimInstance -ClassName win32_operatingsystem).lastbootuptime
if ($LastReboot)
    {
    Write-Output "Last Reboot: $LastReboot"
    $RebootTimeDiff = (get-date) - $LastReboot
    $RebootTimeDiffHours = $RebootTimeDiff.TotalHours
    $RebootTimeDiffHoursRound = ([Math]::Round($RebootTimeDiffHours,2))
    
    if ($RebootTimeDiffHoursRound -lt 48)
        {
        Write-Output "Last Reboot $RebootTimeDiffHoursRound Hours ago"
        }
    Else
        {
        $RebootTimeDiffDays = $RebootTimeDiff.TotalDays
        $RebootTimeDiffdaysRound = ([Math]::Round($RebootTimeDiffDays,2))
        Write-Output "Last Reboot $RebootTimeDiffdaysRound days ago"
        }
    }
$PendingReboot = Test-PendingReboot
Write-Output "Pending Reboot: $PendingReboot"
try #Use WMI
    {
    $Loggedon = Get-WmiObject -ComputerName $env:COMPUTERNAME -Class Win32_Computersystem | Select-Object UserName
    $Domain,$User = $Loggedon.Username.split('\',2)
    Write-Output "Logged on User: $User"
    }
catch
    {
    Write-Output "No CONSOLE Logged on User"
    $NoConsoleUser = $True
    }

try #Use Explorer
    {
    $Users = (Get-Process -Name explorer -IncludeUserName -ErrorAction SilentlyContinue).UserName
    $LoggedOnUsers = $Null
    foreach ($User in $Users)
        {
        $UserAccount = ($User).split("\")[1]
        $LoggedOnUsers += "$($UserAccount), "
        }
    $LoggedOnUsers = $LoggedOnUsers.Substring(0,$LoggedOnUsers.Length-2)
    if ($NoConsoleUser){Write-Output "Logged on RDP User: $LoggedOnUsers"}
    }
catch
    {
    Write-Output "No Logged on User (RDP)"
    }

Write-Output "Computer Model: $ComputerModel"
if ($Manufacturer -like "H*"){Write-Output "Computer Product Code: $HPProdCode"}
Write-Output "Current BIOS Level: $($BIOSInfo.SMBIOSBIOSVersion) From Date: $CurrentBIOSDate"
Get-TPMVer
$TimeUTC = [System.DateTime]::UtcNow
$TimeCLT = get-date
Write-Output "Current Client Time: $TimeCLT"
Write-Output "Current Client UTC: $TimeUTC"
Write-Output "Time Zone: $(Get-TimeZone)"
$Locale = Get-WinSystemLocale
if ($Locale -ne "en-US"){Write-Output "WinSystemLocale: $locale"}
Get-WmiObject win32_LogicalDisk -Filter "DeviceID='C:'" | % { $FreeSpace = $_.FreeSpace/1GB -as [int] ; $DiskSize = $_.Size/1GB -as [int] }

Write-Output "DiskSize = $DiskSize, FreeSpace = $Freespace"
    #Get Volume Infomration
    try 
        {
        $SecureBootStatus = Confirm-SecureBootUEFI
        }
    catch {}
    if ($SecureBootStatus -eq $false -or $SecureBootStatus -eq $true)
        {
        $Volume = Get-Volume | Where-Object {$_.FileSystemType -eq "FAT32" -and $_.DriveType -eq "Fixed"}
        $SystemDisk = Get-Disk | Where-Object {$_.IsSystem -eq $true}
        $SystemPartition = Get-Partition -DiskNumber $SystemDisk.DiskNumber | Where-Object {$_.IsSystem -eq $true}  
        $SystemVolume = $Volume | Where-Object {$_.UniqueId -match $SystemPartition.Guid}
        $FreeMB = [MATH]::Round(($SystemVolume).SizeRemaining /1MB)
        if ($FreeMB -le 50)
            {
            Write-Output "Systvem Volume FreeSpace = $FreeMB MB"
            
            }
        else
            {Write-Output "Systvem Volume FreeSpace = $FreeMB MB"}
        }
    else
        {
        }

    
$MemorySize = [math]::Round((Get-WmiObject -Class Win32_ComputerSystem).TotalPhysicalMemory/1MB)
Write-Output "Memory size = $MemorySize MB"

if (Get-WmiObject -Class win32_battery)
        {
        if ((Get-WmiObject -Class Win32_Battery –ea 0).BatteryStatus -eq 2)
            {Write-Output "Power Status: Device is on AC Power"}
        Else
            {
            Write-Output "Power Status: Device is on Battery"
            Write-Output "Power Status: Time Remaining on Battery = $((Get-WmiObject -Class win32_battery).estimatedChargeRemaining)"
            }
        }
    if ((get-WmiObject Win32_NetworkAdapterConfiguration).defaultIPGateway -ilike '0.0.0.0')
        {Write-Output "Network Status: Device is on VPN"}
