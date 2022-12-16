<# Gary Blok @gwblok GARYTOWN.COM
Based on https://github.com/AdamGrossTX/FU.WhyAmIBlocked/blob/master/Get-SafeguardHoldInfo.ps1 by Adam Gross
#>

<#

requires -modules FU.WhyAmIBlocked
Run CMPivot to pull this info from the registry & Add to "SettingsTable" anything that is missing.
I typically copy and paste the results from CMPivot into Excel only keeping the two columns "ALTERNATEDATALINK & ALTERNATEDATAVERSION"
  While in Excel, delete duplicates (Data Tab), then Sort on Version
  I then compare the item in Excel with the Settings Table and add anything new to the Settings Table.
  If you find anything I don't have, please contact me on Twitter @gwblok or GMAIL - garywblok and send me the ones I don't have listed below.


#>
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


<# Updates
22.10.28 - Added more rows to the Lookup.
22.11.22 - Added more rows to the Lookup
22.11.22 - Rewrote process to be more efficent. 
  - Removed Unused function
  - Removed function and just incorporated the code into the script
  - Skips Items that were already completed in a previous run
    - Skips downloading and extracting the XML, still parses XML and adds info to the Database.


#>

$SettingsTable = @(
@{ ALTERNATEDATALINK = 'http://adl.windows.com/appraiseradl/2020_02_20_06_05_AMD64.cab'; ALTERNATEDATAVERSION = '2360'}
@{ ALTERNATEDATALINK = 'http://adl.windows.com/appraiseradl/2020_05_28_05_02_AMD64.cab'; ALTERNATEDATAVERSION = '2372'}
@{ ALTERNATEDATALINK = 'http://adl.windows.com/appraiseradl/2020_06_17_03_02_AMD64.cab'; ALTERNATEDATAVERSION = '2375'}
@{ ALTERNATEDATALINK = 'http://adl.windows.com/appraiseradl/2020_06_26_06_02_AMD64.cab'; ALTERNATEDATAVERSION = '2376'}
@{ ALTERNATEDATALINK = 'http://adl.windows.com/appraiseradl/2020_07_09_05_02_AMD64.cab'; ALTERNATEDATAVERSION = '2377'} # From Robert Stein (@RaslDasl)
@{ ALTERNATEDATALINK = 'http://adl.windows.com/appraiseradl/2020_07_23_05_02_AMD64.cab'; ALTERNATEDATAVERSION = '2379'}
@{ ALTERNATEDATALINK = 'http://adl.windows.com/appraiseradl/2020_10_01_04_02_AMD64.cab'; ALTERNATEDATAVERSION = '2387'}
@{ ALTERNATEDATALINK = 'http://adl.windows.com/appraiseradl/2020_10_26_05_02_AMD64.cab'; ALTERNATEDATAVERSION = '2390'}
@{ ALTERNATEDATALINK = 'http://adl.windows.com/appraiseradl/2020_11_05_05_02_AMD64.cab'; ALTERNATEDATAVERSION = '2391'}
@{ ALTERNATEDATALINK = 'http://adl.windows.com/appraiseradl/2020_11_24_07_02_AMD64.cab'; ALTERNATEDATAVERSION = '2393'}
@{ ALTERNATEDATALINK = 'http://adl.windows.com/appraiseradl/2020_12_10_07_02_AMD64.cab'; ALTERNATEDATAVERSION = '2394'}
@{ ALTERNATEDATALINK = 'http://adl.windows.com/appraiseradl/2020_12_17_05_02_AMD64.cab'; ALTERNATEDATAVERSION = '2395'}
@{ ALTERNATEDATALINK = 'http://adl.windows.com/appraiseradl/2021_01_07_05_02_AMD64.cab'; ALTERNATEDATAVERSION = '2396'}
@{ ALTERNATEDATALINK = 'http://adl.windows.com/appraiseradl/2021_01_14_02_02_AMD64.cab'; ALTERNATEDATAVERSION = '2397'}
@{ ALTERNATEDATALINK = 'http://adl.windows.com/appraiseradl/2021_01_28_04_02_AMD64.cab'; ALTERNATEDATAVERSION = '2398'}
@{ ALTERNATEDATALINK = 'http://adl.windows.com/appraiseradl/2021_02_12_02_02_AMD64.cab'; ALTERNATEDATAVERSION = '2399'}
@{ ALTERNATEDATALINK = 'http://adl.windows.com/appraiseradl/2021_03_04_04_02_AMD64.cab'; ALTERNATEDATAVERSION = '2400'}
@{ ALTERNATEDATALINK = 'http://adl.windows.com/appraiseradl/2021_03_11_04_02_AMD64.cab'; ALTERNATEDATAVERSION = '2401'}
@{ ALTERNATEDATALINK = 'http://adl.windows.com/appraiseradl/2021_12_16_03_01_AMD64.cab'; ALTERNATEDATAVERSION = '2430'}
@{ ALTERNATEDATALINK = 'http://adl.windows.com/appraiseradl/2020_11_24_07_03_AMD64.cab'; ALTERNATEDATAVERSION = '2459'}
@{ ALTERNATEDATALINK = 'http://adl.windows.com/appraiseradl/2020_12_10_07_03_AMD64.cab'; ALTERNATEDATAVERSION = '2460'}
@{ ALTERNATEDATALINK = 'http://adl.windows.com/appraiseradl/2020_12_17_05_03_AMD64.cab'; ALTERNATEDATAVERSION = '2461'}
@{ ALTERNATEDATALINK = 'http://adl.windows.com/appraiseradl/2021_01_07_05_03_AMD64.cab'; ALTERNATEDATAVERSION = '2462'}
@{ ALTERNATEDATALINK = 'http://adl.windows.com/appraiseradl/2021_01_14_02_03_AMD64.cab'; ALTERNATEDATAVERSION = '2463'}
@{ ALTERNATEDATALINK = 'http://adl.windows.com/appraiseradl/2021_01_28_04_03_AMD64.cab'; ALTERNATEDATAVERSION = '2464'}
@{ ALTERNATEDATALINK = 'http://adl.windows.com/appraiseradl/2021_02_12_02_03_AMD64.cab'; ALTERNATEDATAVERSION = '2465'}
@{ ALTERNATEDATALINK = 'http://adl.windows.com/appraiseradl/2021_07_29_02_02_AMD64.cab'; ALTERNATEDATAVERSION = '2501'}
@{ ALTERNATEDATALINK = 'http://adl.windows.com/appraiseradl/2021_10_14_12_02_AMD64.cab'; ALTERNATEDATAVERSION = '2509'}
@{ ALTERNATEDATALINK = 'http://adl.windows.com/appraiseradl/2021_12_09_11_02_AMD64.cab'; ALTERNATEDATAVERSION = '2515'}
@{ ALTERNATEDATALINK = 'http://adl.windows.com/appraiseradl/2022_01_20_02_01_AMD64.cab'; ALTERNATEDATAVERSION = '2519'}
@{ ALTERNATEDATALINK = 'http://adl.windows.com/appraiseradl/2022_01_21_03_01_AMD64.cab'; ALTERNATEDATAVERSION = '2520'}
@{ ALTERNATEDATALINK = 'http://adl.windows.com/appraiseradl/2022_01_27_03_01_AMD64.cab'; ALTERNATEDATAVERSION = '2521'}
@{ ALTERNATEDATALINK = 'http://adl.windows.com/appraiseradl/2022_02_10_04_01_AMD64.cab'; ALTERNATEDATAVERSION = '2522'}
@{ ALTERNATEDATALINK = 'http://adl.windows.com/appraiseradl/2022_02_24_04_01_AMD64.cab'; ALTERNATEDATAVERSION = '2523'}
@{ ALTERNATEDATALINK = 'http://adl.windows.com/appraiseradl/2022_03_24_04_01_AMD64.cab'; ALTERNATEDATAVERSION = '2524'}
@{ ALTERNATEDATALINK = 'http://adl.windows.com/appraiseradl/2022_04_28_02_01_AMD64.cab'; ALTERNATEDATAVERSION = '2528'}
@{ ALTERNATEDATALINK = 'http://adl.windows.com/appraiseradl/2022_06_02_12_01_AMD64.cab'; ALTERNATEDATAVERSION = '2530'}
@{ ALTERNATEDATALINK = 'http://adl.windows.com/appraiseradl/2022_08_24_03_01_AMD64.cab'; ALTERNATEDATAVERSION = '2540'}
@{ ALTERNATEDATALINK = 'http://adl.windows.com/appraiseradl/2022_09_13_04_01_AMD64.cab'; ALTERNATEDATAVERSION = '2541'}
@{ ALTERNATEDATALINK = 'http://adl.windows.com/appraiseradl/2022_09_22_04_01_AMD64.cab'; ALTERNATEDATAVERSION = '2542'}
@{ ALTERNATEDATALINK = 'http://adl.windows.com/appraiseradl/2022_09_29_02_01_AMD64.cab'; ALTERNATEDATAVERSION = '2543'}
@{ ALTERNATEDATALINK = 'http://adl.windows.com/appraiseradl/2022_10_06_01_01_AMD64.cab'; ALTERNATEDATAVERSION = '2544'}
@{ ALTERNATEDATALINK = 'http://adl.windows.com/appraiseradl/2022_10_13_02_01_AMD64.cab'; ALTERNATEDATAVERSION = '2545'}
@{ ALTERNATEDATALINK = 'http://adl.windows.com/appraiseradl/2022_10_20_12_01_AMD64.cab'; ALTERNATEDATAVERSION = '2546'}
@{ ALTERNATEDATALINK = 'http://adl.windows.com/appraiseradl/2022_10_27_03_01_AMD64.cab'; ALTERNATEDATAVERSION = '2547'}
@{ ALTERNATEDATALINK = 'http://adl.windows.com/appraiseradl/2022_11_03_03_01_AMD64.cab'; ALTERNATEDATAVERSION = '2548'}
@{ ALTERNATEDATALINK = 'http://adl.windows.com/appraiseradl/2022_11_10_04_01_AMD64.cab'; ALTERNATEDATAVERSION = '2549'}
@{ ALTERNATEDATALINK = 'http://adl.windows.com/appraiseradl/2022_11_10_04_01_X86.cab'; ALTERNATEDATAVERSION = '254986'} # From Robert Stein (@RaslDasl)
@{ ALTERNATEDATALINK = 'http://adl.windows.com/appraiseradl/2022_11_22_03_01_AMD64.cab'; ALTERNATEDATAVERSION = '2550'} # From Tyler Cox (@_Tcox8)
@{ ALTERNATEDATALINK = 'http://adl.windows.com/appraiseradl/2022_12_01_04_01_AMD64.cab'; ALTERNATEDATAVERSION = '2551'}
@{ ALTERNATEDATALINK = 'http://adl.windows.com/appraiseradl/2022_12_14_03_01_AMD64.cab'; ALTERNATEDATAVERSION = '2552'} 
@{ ALTERNATEDATALINK = 'http://adl.windows.com/appraiseradl/2022_10_27_03_02_AMD64.cab'; ALTERNATEDATAVERSION = '2614'}
@{ ALTERNATEDATALINK = 'http://adl.windows.com/appraiseradl/2022_11_10_04_02_AMD64.cab'; ALTERNATEDATAVERSION = '2616'}

)

$Path = "C:\Temp"
$AppriaserRoot = $Path
try {[void][System.IO.Directory]::CreateDirectory($AppriaserRoot)}
catch {throw}
    
#Download all Appraiser CAB Files
$SafeGuardHoldCombined = @()
$Count = 0
$TotalCount = $SettingsTable.Count
ForEach ($Item in $SettingsTable){  
    $Count = $Count + 1 
    $AppraiserURL = $Item.ALTERNATEDATALINK
    $AppraiserVersion = $Item.ALTERNATEDATAVERSION
    Write-Host "---------------------------------------------------------------------------" -ForegroundColor DarkGray
    Write-Host "Starting on Version $AppraiserVersion, $Count of $TotalCount Items" -ForegroundColor Magenta
    $OutFilePath = "$AppriaserRoot\AppraiserData\$AppraiserVersion"
    $ExistingCAB = Get-ChildItem -Path $AppriaserRoot\*.cab -Recurse -File | Where-Object { $_.Name -like "*$AppraiserVersion*" } -ErrorAction SilentlyContinue
    if (-Not $ExistingCAB) {
        $LinkParts = $AppraiserURL.Split("/")
        $OutFileName = "$($AppraiserVersion)_$($LinkParts[$LinkParts.Count-1])"
        if (-not (Test-Path $OutFilePath)) {New-Item -Path $OutFilePath -ItemType Directory -Force -ErrorAction SilentlyContinue | Out-Null}     
        Invoke-WebRequest -URI $AppraiserURL -OutFile "$OutFilePath\$OutFileName"
    }
    $ExistingXMLS = Get-ChildItem -Path $AppriaserRoot\*.xml -Recurse -File | Where-Object { $_.Name -like "*$AppraiserVersion*" } -ErrorAction SilentlyContinue
    if (-Not $ExistingXMLS){
        Export-FUXMLFromSDB -AlternateSourcePath $OutFilePath -Path $AppriaserRoot
    }
    foreach ($ExistingXML in $ExistingXMLS){
        $SafeGuardHoldDataWorking  = $null
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
    $SafeGuardHoldDataWorking  = $DBBlocks | ForEach-Object { [PSCustomObject]$_ }
    $SafeGuardHoldCombined += $SafeGuardHoldDataWorking
    }

}
Write-Host "Found $($SafeGuardHoldCombined.Count) Safeguard hold Items contained in the $TotalCount Appraiser DB Versions, exported to $Path\SafeGuardHoldCombinedDataBase.json" -ForegroundColor Green
$SafeGuardHoldCombined | ConvertTo-Json | Out-File "$Path\SafeGuardHoldCombinedDataBase.json"

#Get Unique based on ID.  Assuming that all all safeguards with the same number are unique.
Write-Host " Building Database of Unique Safeguard IDs...." -ForegroundColor Magenta
$SafeGuardHoldIDs = $SafeGuardHoldCombined.SafeguardID | Select-Object -Unique
$SafeGuardHoldDatabase = @()
ForEach ($SafeGuardHoldID in $SafeGuardHoldIDs){
    $SafeGuardHoldWorking = $null
    $SafeGuardHoldWorking = $SafeGuardHoldCombined | Where-Object {$_.SafeguardID -eq $SafeGuardHoldID} | Select-Object -Unique
    $SafeGuardHoldDatabase += $SafeGuardHoldWorking 
}

$SafeGuardHoldDatabase | ConvertTo-Json | Out-File "$Path\SafeGuardHoldDataBase.json"

Write-Host "Found $($SafeGuardHoldDatabase.Count) unique Safeguard hold Items, exported to $Path\SafeGuardHoldDataBase.json" -ForegroundColor Green
