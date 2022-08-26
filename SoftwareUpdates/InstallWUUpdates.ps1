# Gary Blok | Nathan Ziehnert
# Triggers Download of MS Updates and Installs them
$WUDownloader=(New-Object -ComObject Microsoft.Update.Session).CreateUpdateDownloader()
$WUInstaller=(New-Object -ComObject Microsoft.Update.Session).CreateUpdateInstaller()
$WUUpdates=New-Object -ComObject Microsoft.Update.UpdateColl
((New-Object -ComObject Microsoft.Update.Session).CreateupdateSearcher().Search("IsInstalled=0 and Type='Software'")).Updates|%{
    if(!$_.EulaAccepted){$_.EulaAccepted=$true}
    if ($_.Title -notmatch "Preview"){[void]$WUUpdates.Add($_)}
}

if ($WUUpdates.Count -ge 1){
    $WUInstaller.ForceQuiet=$true
    $WUInstaller.Updates=$WUUpdates
    $WUDownloader.Updates=$WUUpdates
    write-host "Downloading " $WUDownloader.Updates.count "Updates"
    foreach ($update in $WUInstaller.Updates){Write-Host "$($update.Title)"}
    $WUDownloader.Download()
    write-host "Installing " $WUInstaller.Updates.count "Updates"
    $Install = $WUInstaller.Install()
} 
else {
    write-host "No updates detected"
}
