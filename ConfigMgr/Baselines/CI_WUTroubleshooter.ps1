# Gary Blok - GARYTOWN.COM - @gwblok
#Runs Windows Update Troubleshoot and detects issue.  No Remediation

$Compliance = $true
$RegKey = "HKLM:\SOFTWARE\GARYTOWN"


$WorkingFolder = "$env:TEMP\WUDiag"
if(!(Test-Path -Path $WorkingFolder)){New-Item -Path $WorkingFolder -ItemType Directory -Force |Out-Null}
Get-TroubleshootingPack -Path C:\Windows\diagnostics\system\WindowsUpdate | Invoke-TroubleshootingPack -Unattended -Result $WorkingFolder 
[XML]$Result = Get-Content "$WorkingFolder\ResultReport.xml" -Verbose
[XML]$Debug = Get-Content "$WorkingFolder\DebugReport.xml" -Verbose

$DiagStatus = (($Debug.DebugReport.Functions.Function | Where-Object {$_.name -eq "Diagnose"}).data | Where-Object {$_.id -eq "StatusCode"}).'#text'
$RootCauses = $Result.ResultReport.Package.Problem.RootCauseInformation.RootCause

if ($DiagStatus -ne "0x0"){$Compliance = $false}

Foreach ($RootCause in $RootCauses){
    #Write-Output "Test: $($RootCause.name)"
    #Write-Output "Status: $($RootCause.data[1].'#text')"
    if (!(($($RootCause.data[1].'#text') -eq "Not Checked") -or ($($RootCause.data[1].'#text') -eq "Not Detected"))){
    $Compliance = $false
    }
}
if ($Compliance -eq $false){
    $Date = Get-Date -Format "MM/dd/yyyy HH:MM:ss"
    if (!(Test-Path -Path $RegKey)){New-Item -Path $RegKey -Force}
    New-ItemProperty -Path $RegKey -Name "WUTestFailed" -PropertyType String -Value $Date -Force
}
else{
    if (Test-Path -Path $RegKey){
        if ((Get-ItemProperty -Path $RegKey -Name "WUTestFailed" -ErrorAction SilentlyContinue) -ne $null){
            Remove-ItemProperty -Path $RegKey -Name "WUTestFailed" -Force
        }
    }
}

Return $Compliance
