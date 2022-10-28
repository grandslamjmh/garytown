$Schedule = New-CMSchedule -Start (Get-Date).DateTime -RecurInterval Days -RecurCount 7
$LimitingCollection = "All Workstations"  #Creates this later if does not exist
#Confirm All Workstation Collection, or create it if needed
$AllWorkstationCollection = Get-CMCollection -Name $LimitingCollection
if ($AllWorkstationCollection -eq $Null)
    {
$CollectionQueryAllWorkstations = @"
select SMS_R_System.Name from  SMS_R_System where SMS_R_System.OperatingSystemNameandVersion like "Microsoft Windows NT Workstation%"
"@     
    
    New-CMDeviceCollection -Name $LimitingCollection -Comment "Collection of all workstation machines" -LimitingCollectionName "All Systems" -RefreshSchedule $Schedule -RefreshType 2 |Out-Null
    Add-CMDeviceCollectionQueryMembershipRule -RuleName "All Workstations" -CollectionName $LimitingCollection -QueryExpression $CollectionQueryAllWorkstations | Out-Null
    $AllWorkstationCollection = Get-CMCollection -Name $LimitingCollection
    Write-Host "Created All Workstations Collection ID: $($AllWorkstationCollection.CollectionID), which will be used as the limiting collections moving forward" -ForegroundColor Green
    }
else {Write-Host "Found All Workstations Collection ID: $($AllWorkstationCollection.CollectionID), which will be used as the limiting collections moving forward" -ForegroundColor Green}


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
