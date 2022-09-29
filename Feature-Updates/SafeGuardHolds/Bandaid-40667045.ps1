<#  Gary Blok @gwblok GARYTOWN.COM

PLEASE TEST... this is testing only so far, I've done it on 1 machine and have really no way to confirm this is the root cause of 40667045
I also know this isn't the long term fix... I'd assume the bright minds at MS are all over it.

This is purely for testing to see if you can upgrade Win11 on a test machine that has the Safe Guard Hold ID of 40667045

Note, I ONLY tested on 1 device, pretty sure SecurityServiceConfigured Option 3 = System Guard | When I was enabling and disabling it, 3 was the value that changed.


Current SafeGuards:
40667045 - Secure Launch data not migrated on IceLake(Client), TigerLake, AlderLake devices (Wu Offer Block)
41332279 - Devices with printer using Microsoft IPP Class Driver (Wu Offer Block)

#>


#Get SafeGuardID
$SafeGuardID = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\TargetVersionUpgradeExperienceIndicators\NI22H2" -Name GatedBlockId

if ($SafeGuardID -eq "40667045"){
    #Secure Launch data not migrated on IceLake(Client), TigerLake, AlderLake devices (Wu Offer Block)
    #DeviceGuard info: https://www.tenforums.com/tutorials/68926-verify-if-device-guard-enabled-disabled-windows-10-a.html
    $DeviceGuard = Get-CimInstance –ClassName Win32_DeviceGuard –Namespace root\Microsoft\Windows\DeviceGuard
    if ($DeviceGuard.SecurityServicesConfigured -contains 3){
        if ($DeviceGuard.SecurityServicesRunning -notcontains 3){
            Write-Output "System Guard is configured and NOT running, this has caused me issues.. disabling for now...."
                #Disable System Guard
            if ((Get-ItemPropertyValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\SystemGuard" -Name Managed -ErrorAction SilentlyContinue) -eq 1){
                Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\SystemGuard" -Name Managed -Value 0
            }

            if ((Get-ItemPropertyValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\SystemGuard" -Name Enabled -ErrorAction SilentlyContinue) -eq 1){
                write-output "Disabling System Guard via Registry - HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\SystemGuard"
                Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\SystemGuard" -Name Enabled -Value 0

            }
        }
        else {
        Write-Output "System Guard is configured and Running, I haven't been able to test this scenario.. "
        Write-Output "I would hope this is good and there is no safeguard, however, due to the logic in this script, I know there is...."
        Write-Output "Feel free to update this script to now disable System Guard if you want to try it out"

        }

    }
    else
        {
        Write-Output "System Guard not Configured"
        }

    #Trigger Appraiser

    $TaskName = "Microsoft Compatibility Appraiser"
    $Task = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    if ($Task -ne $null){
        Write-Output "Triggering Task $($Task.TaskName)"
        Start-ScheduledTask -InputObject $Task
    }
    else {
        Write-Output "No Task found with name: $TaskName"
    }

    Start-Sleep -Seconds 60

    $SafeGuardIDConfirm = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\TargetVersionUpgradeExperienceIndicators\NI22H2" -Name GatedBlockId
    if ($SafeGuardIDConfirm -eq "None"){
        Write-Output "Cleared SafeGuard ID... until System Guard is enabled again, probably by policy... this is a BANDAID, not a long term fix"
    }
}


if ($SafeGuardID -eq "41332279"){
    
    # Devices with printer using Microsoft IPP Class Driver (Wu Offer Block)
    
    # Working on Method currently to detect the driver, then uninstall... need more test machines...
    $InstalledDrivers = Get-WmiObject Win32_PnpSignedDriver
    $IPPPrinter = $InstalledDrivers | Where-Object {$_.DeviceName -match 'Microsoft IPP Class Driver'}
    $InfName = $IPPPrinter.InfName
    pnputil /delete-driver $InfName /uninstall /force
    
    #Trigger Appraiser

    $TaskName = "Microsoft Compatibility Appraiser"
    $Task = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    if ($Task -ne $null){
        Write-Output "Triggering Task $($Task.TaskName)"
        Start-ScheduledTask -InputObject $Task
    }
    else {
        Write-Output "No Task found with name: $TaskName"
    }

    Start-Sleep -Seconds 60

    $SafeGuardIDConfirm = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\TargetVersionUpgradeExperienceIndicators\NI22H2" -Name GatedBlockId
    if ($SafeGuardIDConfirm -eq "None"){
        Write-Output "Cleared SafeGuard ID 41332279... Microsoft IPP Class Driver should auto reinstall during the windows upgrade."
    }
}
