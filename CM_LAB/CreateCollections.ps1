<# GARY BLOK - @gwblok - GARYTOWN.COM

Creates Folder Structure & Operational Collections

Update $CompanyName


Collections:
All Workstations
Operating System Builds (1 Per Build starting with 1809)
Fast Policy (Query based on machines created in last 24 hours)


#>

#Get SiteCode
$SiteCode = Get-PSDrive -PSProvider CMSITE
$ProviderMachineName = (Get-PSDrive -PSProvider CMSITE).Root




#Co-Management Pilot Collections
<#
$CollectionNames = @(

@{ Name = 'CoMgmt | Compliance Policy'}
@{ Name = 'CoMgmt | Device Configuration'}
@{ Name = 'CoMgmt | Endpoint Protection'}
@{ Name = 'CoMgmt | Resource Access'}
@{ Name = 'CoMgmt | Client Apps'}
@{ Name = 'CoMgmt | Office C2R'}
@{ Name = 'CoMgmt | Windows Update'}
)


Foreach ($CollectionName in $CollectionNames){
    New-CMCollection -CollectionType Device -LimitingCollectionId $AllWorkstationCollection.CollectionID -Name $CollectionName.Name -RefreshType None -Comment "Collection for Co-Manamagemt Piloting"  |Out-Null

    }
#>

$CompanyName = "GARYTOWN"

#Create Folders in CM
$DeviceFolderNames = @(

@{ Name = "$CompanyName"; Parent = 'Root'}
@{ Name = 'Default CM'; Parent = 'Root'}
@{ Name = 'Administration'; Parent = "$CompanyName"}
@{ Name = 'Integration Test'; Parent = "$CompanyName"}
@{ Name = 'Retired'; Parent = "$CompanyName"}
@{ Name = 'User Test (UAT)'; Parent = "$CompanyName"}
@{ Name = 'Operating Systems'; Parent = "$CompanyName\Administration"}
)
Foreach ($FolderName in $DeviceFolderNames){
    $CollectionFolderName = $FolderName.Name
    $ParentFolderName = $FolderName.Parent
    Write-Output "Starting $CollectionFolderName | $ParentFolderName"
    if ($ParentFolderName -eq "Root"){
        #Create Collection Folder
        If ((-not (Test-Path -Path ($SiteCode.Name +":\DeviceCollection\$CollectionFolderName"))))
            {
            Write-host "Device collection folder name $CollectionFolderName was not found. Creating folder..." -ForegroundColor Green
            New-Item -Name $CollectionFolderName -Path ($SiteCode.Name +":\DeviceCollection")
            $FolderPath = ($SiteCode.Name +":\DeviceCollection\$CollectionFolderName")
            Write-host "Device collection folder $CollectionFolderName created." -ForegroundColor Green
        }
        elseif ((Test-Path -Path ($SiteCode.Name +":\DeviceCollection\$CollectionFolderName")))
            {
            Write-host "Device collection folder name $CollectionFolderName already exists." -ForegroundColor Yellow
            $FolderPath = ($SiteCode.Name +":\DeviceCollection\$CollectionFolderName")
        }
    }
    else {
        #Create Collection Folder
        If ((-not (Test-Path -Path ($SiteCode.Name +":\DeviceCollection\$ParentFolderName\$CollectionFolderName"))))
            {
            Write-host "Device collection folder name $CollectionFolderName was not found. Creating folder..." -ForegroundColor Green
            New-Item -Name $CollectionFolderName -Path ($SiteCode.Name +":\DeviceCollection\$ParentFolderName")
            $FolderPath = ($SiteCode.Name +":\DeviceCollection\$ParentFolderName\$CollectionFolderName")
            Write-host "Device collection folder $CollectionFolderName created." -ForegroundColor Green
        }
        elseif ((Test-Path -Path ($SiteCode.Name +":\DeviceCollection\$ParentFolderName\$CollectionFolderName")))
            {
            Write-host "Device collection folder name $CollectionFolderName already exists." -ForegroundColor Yellow
            $FolderPath = ($SiteCode.Name +":\DeviceCollection\$ParentFolderName\$CollectionFolderName")
        }
    }
}

#Move Default CM Collections to "CM Default" Folder
$DefaultCMCollections = Get-CMDeviceCollection | Where-Object {$_.collectionid -match "SMS"}
$DefaultFolderPath = ($SiteCode.Name +":\DeviceCollection\Default CM")
ForEach ($DefaultCMCollection in $DefaultCMCollections){
    Move-CMObject -FolderPath $DefaultFolderPath -InputObject $(Get-CMDeviceCollection -Id $DefaultCMCollection.collectionid)
    }

#Create Fast Policy Collection in $CompanyName \ Administration Folder
$CollectionName = "Fast Policy"
$CollectionLimitingCol = $(Get-CMDeviceCollection -Name "All Desktop and Server Clients")
$CollectionLocation = ($SiteCode.Name +":\DeviceCollection\$CompanyName\Administration")
$CollectionSchedule = New-CMSchedule -Start (Get-Date).DateTime -RecurInterval Minutes -RecurCount 30 
$CollectionQuery_FastPolicy = @"
select SMS_R_SYSTEM.ResourceID,SMS_R_SYSTEM.ResourceType,SMS_R_SYSTEM.Name,SMS_R_SYSTEM.SMSUniqueIdentifier,SMS_R_SYSTEM.ResourceDomainORWorkgroup,SMS_R_SYSTEM.Client from SMS_R_System where DateDiff(dd,SMS_R_System.CreationDate, GetDate()) <1
"@
$CurrentCollectionID = (Get-CMCollection -Name $CollectionName).CollectionID
if ($CurrentCollectionID -eq $null){
    Write-host "Creating Fast Policy Collection" -ForegroundColor Green

    New-CMDeviceCollection -Name $CollectionName -Comment "New Machines Setup Collection (Fast Policy)" -LimitingCollectionId $CollectionLimitingCol.CollectionID -RefreshType Both -RefreshSchedule $CollectionSchedule
    Add-CMDeviceCollectionQueryMembershipRule -RuleName "Query Fast Policy" -CollectionName $CollectionName -QueryExpression $CollectionQuery_FastPolicy | Out-Null
    Move-CMObject -FolderPath $CollectionLocation -InputObject $(Get-CMDeviceCollection -Name $CollectionName)
    }
else {Write-Host "Collection Already Created" -ForegroundColor Yellow}



#Confirm All Workstation Collection, or create it if needed
$CollectionSchedule = New-CMSchedule -Start (Get-Date).DateTime -RecurInterval Days -RecurCount 7
$CollectionLocation = ($SiteCode.Name +":\DeviceCollection\$CompanyName\Administration")
$CollectionName = "All Workstations"
$AllWorkstationCollection = Get-CMCollection -Name $CollectionName
if ($AllWorkstationCollection -eq $Null)
    {
$CollectionQueryAllWorkstations = @"
select SMS_R_System.Name from  SMS_R_System where SMS_R_System.OperatingSystemNameandVersion like "Microsoft Windows NT Workstation%"
"@     
    
    New-CMDeviceCollection -Name $CollectionName -Comment "Collection of all workstation machines" -LimitingCollectionName "All Systems" -RefreshSchedule $CollectionSchedule -RefreshType 2 |Out-Null
    Add-CMDeviceCollectionQueryMembershipRule -RuleName "All Workstations" -CollectionName $CollectionName -QueryExpression $CollectionQueryAllWorkstations | Out-Null
    $AllWorkstationCollection = Get-CMCollection -Name $CollectionName
    Write-Host "Created All Workstations Collection ID: $($AllWorkstationCollection.CollectionID), which will be used as the limiting collections moving forward" -ForegroundColor Green
    Move-CMObject -FolderPath $CollectionLocation -InputObject $(Get-CMDeviceCollection -Name $CollectionName)

    }
else {Write-Host "Found All Workstations Collection ID: $($AllWorkstationCollection.CollectionID), which will be used as the limiting collections moving forward" -ForegroundColor Green}


#Operating Systems Collections

$CollectionSchedule = New-CMSchedule -Start (Get-Date).DateTime -RecurInterval Days -RecurCount 7
$CollectionLocation = ($SiteCode.Name +":\DeviceCollection\$CompanyName\Administration\Operating Systems")
$CollectionLimitingCol = "All Workstations"
$OSCollections = @(

@{ Name = 'Windows 10 1809'; Build = '17763'}
@{ Name = 'Windows 10 1903'; Build = '18362'}
@{ Name = 'Windows 10 1909'; Build = '18363'}
@{ Name = 'Windows 10 20H1'; Build = '19041'}
@{ Name = 'Windows 10 20H2'; Build = '19042'}
@{ Name = 'Windows 10 21H1'; Build = '19043'}
@{ Name = 'Windows 10 21H2'; Build = '19044'}
@{ Name = 'Windows 10 22H2'; Build = '19045'}

@{ Name = 'Windows 11 21H2'; Build = '22000'}
@{ Name = 'Windows 11 22H2'; Build = '22621'}
)

ForEach ($OSCollection in $OSCollections){
    $CollectionName = $OSCollection.Name
    $PreCheck = Get-CMCollection -Name $CollectionName
    if ($PreCheck -eq $Null){
        $Build = $OSCollection.Build
        $Comment = "Query based on Build $Build"
$CollectionQueryBuild = @"
select distinct SMS_R_SYSTEM.ResourceID,SMS_R_SYSTEM.ResourceType,SMS_R_SYSTEM.Name,SMS_R_SYSTEM.SMSUniqueIdentifier,SMS_R_SYSTEM.ResourceDomainORWorkgroup,SMS_R_SYSTEM.Client from SMS_R_System inner join SMS_G_System_OPERATING_SYSTEM on SMS_G_System_OPERATING_SYSTEM.ResourceID = SMS_R_System.ResourceId where SMS_G_System_OPERATING_SYSTEM.BuildNumber = "$Build"
"@

        New-CMDeviceCollection -Name $CollectionName -Comment $Comment -LimitingCollectionName $CollectionLimitingCol -RefreshSchedule $CollectionSchedule -RefreshType 2 |Out-Null
        Add-CMDeviceCollectionQueryMembershipRule -RuleName "System Build $Build" -CollectionName $CollectionName -QueryExpression $CollectionQueryBuild | Out-Null
        $Confirm = Get-CMCollection -Name $CollectionName
        Write-Host "Created Collection $CollectionName Collection ID: $($Confirm.CollectionID)" -ForegroundColor Green
        Move-CMObject -FolderPath $CollectionLocation -InputObject $(Get-CMDeviceCollection -Name $CollectionName)
    }
    else {Write-Host "Collection Already Created: $($PreCheck.CollectionID)" -ForegroundColor Yellow}
}
     
    
