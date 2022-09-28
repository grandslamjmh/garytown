<# Gary Blok @gwblok GARYTOWN.COM
Based on https://github.com/AdamGrossTX/FU.WhyAmIBlocked/blob/master/Get-SafeguardHoldInfo.ps1 by Adam Gross
This script is nealy 100% copied from the link above, then I added the last part to build a database and export to JSON.
#>

#requires -modules FU.WhyAmIBlocked

#Run this on the client to pull the appraiser db info and client safeguard hold IDs.
#Or run CMPivot to pull this info from the registry

#CMPIVOT Query
<#
Registry('HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\TargetVersionUpgradeExperienceIndicators\*') | where Property == 'GatedBlockId' and Value != '' and Value != 'None'
| join kind=inner (
		Registry('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\OneSettings\compat\appraiser\*') 
		| where Property == 'ALTERNATEDATALINK')
| join kind=inner (
		Registry('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\OneSettings\compat\appraiser\*') 
		| where Property == 'ALTERNATEDATAVERSION')
| project Device,GatedBlockID=Value,ALTERNATEDATALINK=Value1,ALTERNATEDATAVERSION=Value2
#>

$Path = 'C:\Temp'

function Get-ClientSafeguardHoldInfo {
    param(
        [parameter(mandatory = $true)]
        [string]$OS
    )
    try {
        $SettingsKey = Get-Item -Path Registry::"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\OneSettings\compat\appraiser\Settings"
        $TargetVersionUpgradeExperienceIndicatorsKeys = Get-ChildItem -Path Registry::"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\TargetVersionUpgradeExperienceIndicators" -ErrorAction SilentlyContinue | Where-Object { $_.PSChildName -eq $OS }
        $Settings = @{
            ALTERNATEDATALINK    = $SettingsKey | Get-ItemPropertyValue -Name "ALTERNATEDATALINK"
            ALTERNATEDATAVERSION = $SettingsKey | Get-ItemPropertyValue -Name "ALTERNATEDATAVERSION"
            GatedBlockId         = ($TargetVersionUpgradeExperienceIndicatorsKeys | Get-ItemProperty -Name "GatedBlockId" -ErrorAction SilentlyContinue).GatedBlockId
        }

        return $Settings
    }
    catch {
        throw $_
    }
}

#Pass in client info to get details
function Get-SafeGuardHoldDetails {
    Param (
        [parameter(Mandatory = $true)]
        [string]$AppraiserURL,
        
        [parameter(Mandatory = $true)]
        [int]$AppraiserVersion,

        [parameter(Mandatory = $false)]
        [string[]]$SafeGuardHoldId,

        $Path = "C:\Temp"
    )

    $AppriaserRoot = $Path
    try {[void][System.IO.Directory]::CreateDirectory($AppriaserRoot)}
    catch {throw}

    $ExistingXML = Get-ChildItem -Path $AppriaserRoot\*.xml -Recurse -File | Where-Object { $_.Name -like "*$AppraiserVersion*" } -ErrorAction SilentlyContinue

    if (-Not $ExistingXML) {
        $LinkParts = $AppraiserURL.Split("/")
        $OutFileName = "$($AppraiserVersion)_$($LinkParts[$LinkParts.Count-1])"
        $OutFilePath = "$AppriaserRoot\AppraiserData"

        if (-not (Test-Path $OutFilePath)) {
            New-Item -Path $OutFilePath -ItemType Directory -Force -ErrorAction SilentlyContinue
        }
        
        Invoke-WebRequest -URI $AppraiserURL -OutFile "$OutFilePath\$OutFileName"
    
        Export-FUXMLFromSDB -AlternateSourcePath $OutFilePath -Path $AppriaserRoot
        $ExistingXML = Get-ChildItem -Path $AppriaserRoot\*.xml -Recurse -File | Where-Object { $_.Name -like "*$AppraiserVersion*" } -ErrorAction SilentlyContinue
    }

    $DBBlocks = if ($ExistingXML) {
        [xml]$Content = Get-Content -Path $ExistingXML -Raw

        $OSUpgrade = $Content.SelectNodes("//SDB/DATABASE/OS_UPGRADE")
        $GatedBlockOSU = $OSUpgrade | Where-Object { $_.DATA.Data_String.'#text' -eq 'GatedBlock' } 
    
        $GatedBlockOSU | ForEach-Object {
            @{
                AppName       = $_.App_Name.'#text'
                BlockType     = $_.Data[0].Data_String.'#text'
                SafeguardId   = $_.Data[1].Data_String.'#text'
                NAME          = $_.NAME.'#text'
                APP_NAME      = $_.APP_NAME.'#text'
                VENDOR        = $_.VENDOR.'#text'
                EXE_ID        = $_.EXE_ID.'#text'
                DEST_OS_GTE   = $_.DEST_OS_GTE.'#text'
                DEST_OS_LT    = $_.DEST_OS_LT.'#text'
                MATCHING_FILE = $_.MATCHING_FILE.'#text'
                PICK_ONE      = $_.PICK_ONE.'#text'
                INNERXML      = $_.InnerXML
            }
        }
    
        $MIB = $Content.SelectNodes("//SDB/DATABASE/MATCHING_INFO_BLOCK")
        $GatedBlockMIB = $MIB | Where-Object { $_.DATA.Data_String.'#text' -eq 'GatedBlock' }
        $GatedBlockMIB | ForEach-Object {
            @{
                AppName         = $_.App_Name.'#text'
                BlockType       = $_.Data[0].Data_String.'#text'
                SafeguardId     = $_.Data[1].Data_String.'#text'
                APP_NAME        = $_.APP_NAME.'#text'
                DEST_OS_GTE     = $_.DEST_OS_GTE.'#text'
                DEST_OS_LT      = $_.DEST_OS_LT.'#text'
                EXE_ID          = $_.EXE_ID.'#text'
                MATCH_PLUGIN    = $_.MATCH_PLUGIN.Name.'#text'
                MATCHING_DEVICE = $_.MATCHING_DEVICE.Name.'#text'
                MATCHING_REG    = $_.MATCHING_REG.Name.'#text'
                NAME            = $_.NAME.'#text'
                PICK_ONE        = $_.PICK_ONE.Name.'#text'
                SOURCE_OS_LTE   = $_.SOURCE_OS_LTE.'#text'
                VENDOR          = $_.VENDOR.'#text'
                INNERXML        = $_.InnerXML
            }
        }
    } Select-Object -Unique * | Sort-Object AppName


    if ($SafeGuardHoldId) {
        $DBBlocks | Where-Object { $_.SafeguardId -in $SafeGuardHoldId } | ForEach-Object { [PSCustomObject]$_ }
    }
    else {
        $DBBlocks | ForEach-Object { [PSCustomObject]$_ }
    }
}

#$Settings = Get-ClientSafeguardHoldInfo -OS "CO21H2"

#Run this with a list of ids to get specific entries
#Get-SafeGuardHoldDetails -AppraiserURL $Settings.ALTERNATEDATALINK -AppraiserVersion $Settings.ALTERNATEDATAVERSION -SafeGuardHoldId $Settings.GatedBlockId 

#Run this with no ids to list all safeguard holds from the appraiser db
#Get-SafeGuardHoldDetails -AppraiserURL $Settings.ALTERNATEDATALINK -AppraiserVersion $Settings.ALTERNATEDATAVERSION



$SettingsTable = @(
@{ ALTERNATEDATALINK = 'http://adl.windows.com/appraiseradl/2021_01_14_02_02_AMD64.cab'; ALTERNATEDATAVERSION = '2397'}
@{ ALTERNATEDATALINK = 'http://adl.windows.com/appraiseradl/2021_01_28_04_03_AMD64.cab'; ALTERNATEDATAVERSION = '2464'}
@{ ALTERNATEDATALINK = 'http://adl.windows.com/appraiseradl/2020_12_17_05_02_AMD64.cab'; ALTERNATEDATAVERSION = '2395'}
@{ ALTERNATEDATALINK = 'http://adl.windows.com/appraiseradl/2021_02_12_02_03_AMD64.cab'; ALTERNATEDATAVERSION = '2465'}
@{ ALTERNATEDATALINK = 'http://adl.windows.com/appraiseradl/2021_02_12_02_02_AMD64.cab'; ALTERNATEDATAVERSION = '2399'}
@{ ALTERNATEDATALINK = 'http://adl.windows.com/appraiseradl/2022_09_22_04_01_AMD64.cab'; ALTERNATEDATAVERSION = '2542'}
@{ ALTERNATEDATALINK = 'http://adl.windows.com/appraiseradl/2020_11_24_07_03_AMD64.cab'; ALTERNATEDATAVERSION = '2459'}
@{ ALTERNATEDATALINK = 'http://adl.windows.com/appraiseradl/2021_01_28_04_02_AMD64.cab'; ALTERNATEDATAVERSION = '2398'}
@{ ALTERNATEDATALINK = 'http://adl.windows.com/appraiseradl/2020_12_17_05_03_AMD64.cab'; ALTERNATEDATAVERSION = '2461'}
@{ ALTERNATEDATALINK = 'http://adl.windows.com/appraiseradl/2020_11_24_07_02_AMD64.cab'; ALTERNATEDATAVERSION = '2393'}
@{ ALTERNATEDATALINK = 'http://adl.windows.com/appraiseradl/2022_09_13_04_01_AMD64.cab'; ALTERNATEDATAVERSION = '2541'}
@{ ALTERNATEDATALINK = 'http://adl.windows.com/appraiseradl/2020_12_10_07_02_AMD64.cab'; ALTERNATEDATAVERSION = '2394'}
@{ ALTERNATEDATALINK = 'http://adl.windows.com/appraiseradl/2021_01_07_05_03_AMD64.cab'; ALTERNATEDATAVERSION = '2462'}
@{ ALTERNATEDATALINK = 'http://adl.windows.com/appraiseradl/2021_01_14_02_03_AMD64.cab'; ALTERNATEDATAVERSION = '2463'}
@{ ALTERNATEDATALINK = 'http://adl.windows.com/appraiseradl/2021_01_07_05_02_AMD64.cab'; ALTERNATEDATAVERSION = '2396'}
@{ ALTERNATEDATALINK = 'http://adl.windows.com/appraiseradl/2020_10_01_04_02_AMD64.cab'; ALTERNATEDATAVERSION = '2387'}
@{ ALTERNATEDATALINK = 'http://adl.windows.com/appraiseradl/2020_12_10_07_03_AMD64.cab'; ALTERNATEDATAVERSION = '2460'}
@{ ALTERNATEDATALINK = 'http://adl.windows.com/appraiseradl/2020_06_17_03_02_AMD64.cab'; ALTERNATEDATAVERSION = '2375'}
@{ ALTERNATEDATALINK = 'http://adl.windows.com/appraiseradl/2020_06_26_06_02_AMD64.cab'; ALTERNATEDATAVERSION = '2376'}
@{ ALTERNATEDATALINK = 'http://adl.windows.com/appraiseradl/2021_07_29_02_02_AMD64.cab'; ALTERNATEDATAVERSION = '2501'}
@{ ALTERNATEDATALINK = 'http://adl.windows.com/appraiseradl/2021_03_11_04_02_AMD64.cab'; ALTERNATEDATAVERSION = '2401'}
@{ ALTERNATEDATALINK = 'http://adl.windows.com/appraiseradl/2020_02_20_06_05_AMD64.cab'; ALTERNATEDATAVERSION = '2360'}
@{ ALTERNATEDATALINK = 'http://adl.windows.com/appraiseradl/2020_05_28_05_02_AMD64.cab'; ALTERNATEDATAVERSION = '2372'}
@{ ALTERNATEDATALINK = 'http://adl.windows.com/appraiseradl/2022_02_10_04_01_AMD64.cab'; ALTERNATEDATAVERSION = '2522'}
@{ ALTERNATEDATALINK = 'http://adl.windows.com/appraiseradl/2020_10_26_05_02_AMD64.cab'; ALTERNATEDATAVERSION = '2390'}
@{ ALTERNATEDATALINK = 'http://adl.windows.com/appraiseradl/2020_11_05_05_02_AMD64.cab'; ALTERNATEDATAVERSION = '2391'}
@{ ALTERNATEDATALINK = 'http://adl.windows.com/appraiseradl/2021_12_09_11_02_AMD64.cab'; ALTERNATEDATAVERSION = '2515'}
@{ ALTERNATEDATALINK = 'http://adl.windows.com/appraiseradl/2021_10_14_12_02_AMD64.cab'; ALTERNATEDATAVERSION = '2509'}
@{ ALTERNATEDATALINK = 'http://adl.windows.com/appraiseradl/2022_02_24_04_01_AMD64.cab'; ALTERNATEDATAVERSION = '2523'}
@{ ALTERNATEDATALINK = 'http://adl.windows.com/appraiseradl/2022_08_24_03_01_AMD64.cab'; ALTERNATEDATAVERSION = '2540'}
@{ ALTERNATEDATALINK = 'http://adl.windows.com/appraiseradl/2022_01_20_02_01_AMD64.cab'; ALTERNATEDATAVERSION = '2519'}
@{ ALTERNATEDATALINK = 'http://adl.windows.com/appraiseradl/2022_04_28_02_01_AMD64.cab'; ALTERNATEDATAVERSION = '2528'}
@{ ALTERNATEDATALINK = 'http://adl.windows.com/appraiseradl/2022_01_27_03_01_AMD64.cab'; ALTERNATEDATAVERSION = '2521'}
@{ ALTERNATEDATALINK = 'http://adl.windows.com/appraiseradl/2022_01_21_03_01_AMD64.cab'; ALTERNATEDATAVERSION = '2520'}
@{ ALTERNATEDATALINK = 'http://adl.windows.com/appraiseradl/2022_06_02_12_01_AMD64.cab'; ALTERNATEDATAVERSION = '2530'}
@{ ALTERNATEDATALINK = 'http://adl.windows.com/appraiseradl/2022_03_24_04_01_AMD64.cab'; ALTERNATEDATAVERSION = '2524'}
@{ ALTERNATEDATALINK = 'http://adl.windows.com/appraiseradl/2021_12_16_03_01_AMD64.cab'; ALTERNATEDATAVERSION = '2430'}

)

$SafeGuardHoldCombined = @()
foreach ($Settings in $SettingsTable){
    $SafeGuardHoldDataWorking  = $null
    $SafeGuardHoldDataWorking = Get-SafeGuardHoldDetails -AppraiserURL $Settings.ALTERNATEDATALINK -AppraiserVersion $Settings.ALTERNATEDATAVERSION -Path $Path
    $SafeGuardHoldCombined += $SafeGuardHoldDataWorking 
}

$SafeGuardHoldIDs = $SafeGuardHoldCombined.SafeguardID | Select-Object -Unique
$SafeGuardHoldDatabase = @()
ForEach ($SafeGuardHoldID in $SafeGuardHoldIDs){
    $SafeGuardHoldWorking = $null
    $SafeGuardHoldWorking = $SafeGuardHoldCombined | Where-Object {$_.SafeguardID -eq $SafeGuardHoldID} | Select-Object -Unique
    $SafeGuardHoldDatabase += $SafeGuardHoldWorking 
}

$SafeGuardHoldDatabase | ConvertTo-Json | Out-File "$Path\SafeGuardHoldDataBase.json"


#Testing Vars:
#$SafeGuardHoldID = '25178825'
