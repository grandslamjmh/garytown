#Setup Features
$Features = @("FS-Data-Deduplication", "BranchCache", "NET-Framework-Core", "BITS", "BITS-IIS-Ext", "BITS-Compact-Server", "RDC", "WAS-Process-Model", "WAS-Config-APIs", "WAS-Net-Environment", "Web-Server", "Web-ISAPI-Ext", "Web-ISAPI-Filter", "Web-Net-Ext", "Web-Net-Ext45", "Web-ASP-Net", "Web-ASP-Net45", "Web-ASP", "Web-Windows-Auth", "Web-Basic-Auth", "Web-URL-Auth", "Web-IP-Security", "Web-Scripting-Tools", "Web-Mgmt-Service", "Web-Stat-Compression", "Web-Dyn-Compression", "Web-Metabase", "Web-WMI", "Web-HTTP-Redirect", "Web-Log-Libraries", "Web-HTTP-Tracing", "UpdateServices-RSAT", "UpdateServices-API", "UpdateServices-UI")
ForEach ($Feature in $Features){
    write-host "Starting $Feature"
    Install-WindowsFeature -Name $Feature -IncludeAllSubFeature -IncludeManagementTools
}

#Inbound
$DescriptionInbound = "CM SQL & SQL Service Broker (1433 & 4022) Inbound Rule"
New-NetFirewallRule -DisplayName "CM SQL Inbound" -Direction Inbound -Profile Domain -Action Allow -LocalPort 1433,4022 -Protocol TCP -Description $DescriptionInbound

#Outbound
$DescriptionOutbound = "CM SQL & SQL Service Broker (1433 & 4022) Outbound Rule"
New-NetFirewallRule -DisplayName "CM SQL Outbound" -Direction Outbound -Profile Domain -Action Allow -LocalPort 1433,4022 -Protocol TCP -Description $DescriptionOutbound
