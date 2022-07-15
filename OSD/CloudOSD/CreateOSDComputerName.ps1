<# Gary Blok @gwblok Recast Software
Generate Generic Computer Name based on Model Name... doesn't work well in Production as it names the machine after the model, so if you have more than one model.. it will get the same name.
This is used in my lab to name the PCs after the model, which makes life easier for me.

It creates randomly generated names for VMs following the the pattern "VM-CompanyName-Random 5 digit Number" - You would need to change how many digits this is if you have a longer company name.

NOTES.. Computer name can NOT be longer than 15 charaters.  There is no checking to ensure the name is under that limit.


#>

try {
$tsenv = new-object -comobject Microsoft.SMS.TSEnvironment
    }
catch{
Write-Output "Not in TS"
    }

$Manufacturer = (Get-WmiObject -Class:Win32_ComputerSystem).Manufacturer
$Model = (Get-WmiObject -Class:Win32_ComputerSystem).Model
$CompanyName = "GARYTOWN"

if ($Manufacturer -match "Lenovo")
    {
    $Model = ((Get-CimInstance -ClassName Win32_ComputerSystemProduct).Version).split(" ")[1]
    $ComputerName = "$($Manufacturer)-$($Model)"
    }
elseif (($Manufacturer -match "HP") -or ($Manufacturer -match "Hew")){
    $Manufacturer = "HP"
    
    if ($Model-match "EliteDesk"){$Model = $Model.replace("EliteDesk","ED")}
    elseif($Model-match "EliteBook"){$Model = $Model.replace("EliteBook","EB")}
    elseif($Model-match "ProDesk"){$Model = $Model.replace("ProDesk","PD")}
    elseif($Model-match "ProBook"){$Model = $Model.replace("ProBook","PB")}
    $Model = $model.replace(" ","-")
    $ComputerName = $Model.Substring(0,12)
    }
elseif($Manufacturer -match "Dell"){
    $Manufacturer = "Dell"
    $Model = (Get-WmiObject -Class:Win32_ComputerSystem).Model
    if ($Model-match "Latitude"){$Model = $Model.replace("Latitude","L")}
    elseif($Model-match "OptiPlex"){$Model = $Model.replace("OptiPlex","O")}
    elseif($Model-match "Precision"){$Model = $Model.replace("Precision","P")}
    $Model = $model.replace(" ","-")
    if($Model-match "Tower"){
        $Model = $Model.replace("Tower","T")
        $Keep = $Model.Split("-") | select -First 3
        $ComputerName = "$($Manufacturer)-$($Keep[0])-$($Keep[1])-$($Keep[2])"
        }
    else
        {
        $Keep = $Model.Split("-") | select -First 2
        $ComputerName = "$($Manufacturer)-$($Keep[0])-$($Keep[1])"
        }
    
    }
elseif ($Manufacturer -match "Microsoft")
    {
    if ($Model -match "Virtual")
        {
        $Random = Get-Random -Maximum 99999
        $ComputerName = "VM-$($CompanyName)-$($Random )"
        if ($ComputerName.Length -gt 15){
            $ComputerName = $ComputerName.Substring(0,15)
            }
        }
    }
else {
    $Serial = (Get-WmiObject -class:win32_bios).SerialNumber
    if ($Serial.Length -ge 15)
        {
        $ComputerName = $Serial.substring(0,15)
        }
    else
        {
        $ComputerName = $Serial 
        }
    }
Write-Output "====================================================="
Write-Output "Setting OSDComputerName to $ComputerName"
if ($tsenv){$tsenv.value('OSDComputerName') = $ComputerName}
Write-Output "====================================================="
