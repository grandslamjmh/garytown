function Test-MeteredConnection {
$OnMeteredConnection = $null
$MeteredConnectionStatus = $null
[void][Windows.Networking.Connectivity.NetworkInformation, Windows, ContentType = WindowsRuntime]
$costs = [Windows.Networking.Connectivity.NetworkInformation]::GetConnectionProfiles().GetConnectionCost()
foreach ($cost in $costs){
    $MeteredConnectionStatus = $cost.ApproachingDataLimit -or $cost.OverDataLimit -or $cost.Roaming -or $cost.BackgroundDataUsageRestricted -or ($cost.NetworkCostType -ne "Unrestricted")
    #Write-Output $MeteredConnectionStatus
    if ($MeteredConnectionStatus -eq $true){
        $OnMeteredConnection = $true
    }
}
if (!($OnMeteredConnection)){$OnMeteredConnection = $false}
return $OnMeteredConnection
}

