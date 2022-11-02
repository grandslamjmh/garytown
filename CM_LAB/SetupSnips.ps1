#Inbound
$DescriptionInbound = "CM SQL & SQL Service Broker (1433 & 4022) Inbound Rule"
New-NetFirewallRule -DisplayName "CM SQL Inbound" -Direction Inbound -Profile Domain -Action Allow -LocalPort 1433,4022 -Protocol TCP -Description $DescriptionInbound

#Outbound
$DescriptionOutbound = "CM SQL & SQL Service Broker (1433 & 4022) Outbound Rule"
New-NetFirewallRule -DisplayName "CM SQL Outbound" -Direction Outbound -Profile Domain -Action Allow -LocalPort 1433,4022 -Protocol TCP -Description $DescriptionOutbound
