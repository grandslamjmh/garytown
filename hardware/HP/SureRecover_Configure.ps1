<#
Installed OpenSSL Light on my desktop: https://slproweb.com/products/Win32OpenSSL.html


GUIDES Used in creation of this script content:

    Initiallizing SPM (Secure Platform Module):
    https://developers.hp.com/hp-client-management/blog/hp-secure-platform-management-hp-client-management-script-library

    Sure Recover Doc: http://h10032.www1.hp.com/ctg/Manual/c06579216.pdf

    Provisioning and Configuring HP Sure Recover with HP Client Management Script Library
    https://developers.hp.com/hp-client-management/blog/provisioning-and-configuring-hp-sure-recover-hp-client-management-script-library

    Provisioning a HP Sure Recover Custom Image in a Modern Managed Cloud Environment
    https://developers.hp.com/hp-client-management/blog/provisioning-hp-sure-recover-custom-image-modern-managed-cloud-environment






THINGS YOU NEED TO DO:
Figure out where you want to store this stuff, I'd recommend a file server, and backups, as you won't want to lose the certs you'll be creating.
Folder Stucture:

Root\SureRecover\$Build\Split

Copy your Image (WIM FILE) to the $ImagePath (Root\SureRecover\$Build)
I'm using the build Number as my Directory Structure (22621)
    example: Root\SureRecover\22621\Split


Have your Web Server ready
Update the $URL below to where you move your $Split folder contents to, along with the manifest file and manifest signature


Once you've created your payload files, you can deploy them to your test machine
Set-HPSecurePlatformPayload -PayloadFile "$SureRecoverWorkingpath\SPEKPP.dat"
Set-HPSecurePlatformPayload -PayloadFile "$SureRecoverWorkingpath\SPSKPP.dat"
Set-HPSecurePlatformPayload -PayloadFile "$SureRecoverWorkingpath\OSpayload.dat"

NOTE:  I tried to build these on a VM, but it didn't go well, I had to build the payload files on an HP Device.
#>



$Build = '19045' # Windows 11 22H2
$HPProdCode = '83B2'

#$URL = "http://hpsr.lab.garytown.com/$($build)/custom.mft"
$URL = "http://hpsr.lab.garytown.com/$($HPProdCode)/$($build)/custom.mft"
$AgentURL = "http://hpsr.lab.garytown.com/Agent"
$ProdWebServerRootPath = "\\cm.lab.garytown.com\e$\HPSR"
$ProdWebServerImagePath = "$ProdWebServerRootPath\$HPProdCode\$Build"
$SureRecoverWorkingpath = '\\nas\public\HP_Stuff\HPSR\HPSRStaging'
$ImagePath = "$SureRecoverWorkingpath\$HPProdCode\$Build"
$DatFilePath = "$SureRecoverWorkingpath\$HPProdCode\$($Build)_DAT"
$SplitPath = "$($ImagePath)Split"
$AgentPath = "$SureRecoverWorkingpath\Agent"
$OpenSLLFilePath = 'C:\Program Files\OpenSSL-Win64\bin\openssl.exe'


if (!(Test-Path -path $SureRecoverWorkingpath)){ new-item -Path $SureRecoverWorkingpath -ItemType Directory -Force | Out-Null}
if (!(Test-Path -path $ImagePath)){ new-item -Path $ImagePath -ItemType Directory -Force | Out-Null}
#if (!(Test-Path -path $SplitPath)){ new-item -Path $SplitPath -ItemType Directory -Force | Out-Null}
if (!(Test-Path -path $DatFilePath)){ new-item -Path $DatFilePath -ItemType Directory -Force | Out-Null}
Set-Location -Path $SureRecoverWorkingpath

#Generate Private & Public PEM Files - Do this Once and don't do it again... just don't lose those files
<#
#Path to OpenSSL Light Installation

#Create the Endoresement & Signing Certs (Creates them in the path this is running, which should be your Working Path)
$arg1 = 'req -x509 -nodes -newkey rsa:2048 -keyout key.pem -out cert.pem -days 3650 -subj "/C=US/ST=MN/L=Glenwood/O=GARYTOWN/OU=IT/CN=lab.garytown.com"'
$arg2 = 'pkcs12  -inkey key.pem -in cert.pem -export -keypbe PBE-SHA1-3DES -certpbe PBE-SHA1-3DES -out kek.pfx -name "HP Secure Platform Key Endorsement Certificate"  -passout pass:P@ssw0rd'
$arg3 = 'req -x509 -nodes -newkey rsa:2048 -keyout key.pem -out cert.pem -days 3650 -subj "/C=US/ST=MN/L=Glenwood/O=GARYTOWN/OU=IT/CN=lab.garytown.com"'
$arg4 = 'pkcs12 -inkey key.pem -in cert.pem -export -keypbe PBE-SHA1-3DES -certpbe PBE-SHA1-3DES -out sk.pfx -name "HP Secure Platform Signing Key Certificate" -passout pass:P@ssw0rd'

Start-Process -FilePath $OpenSLLFilePath -ArgumentList $arg1 -PassThru -NoNewWindow -Wait
Start-Process -FilePath $OpenSLLFilePath -ArgumentList $arg2 -PassThru -NoNewWindow -Wait
Start-Process -FilePath $OpenSLLFilePath -ArgumentList $arg3 -PassThru -NoNewWindow -Wait
Start-Process -FilePath $OpenSLLFilePath -ArgumentList $arg4 -PassThru -NoNewWindow -Wait

if (!(Test-Path -Path "$SureRecoverWorkingpath\my-recoverypublic.pem")){
    $arg5 = "genrsa -out $SureRecoverWorkingpath\my-recovery-private.pem 2048"
    Start-Process -FilePath $OpenSLLFilePath -ArgumentList $arg5 -PassThru -NoNewWindow -Wait
}
if (!(Test-Path -Path "$SureRecoverWorkingpath\my-recoverypublic.pem")){
    $arg6 = "rsa -in $SureRecoverWorkingpath\my-recovery-private.pem -pubout -out $SureRecoverWorkingpath\my-recoverypublic.pem"
    Start-Process -FilePath $OpenSLLFilePath -ArgumentList $arg6 -PassThru -NoNewWindow -Wait
}
#>




#Create the Custom Image

#Split the WIM File (per docs recommendations)
#dism /Split-Image /ImageFile:$($ImagePath)\install.wim /SwmFile:$($SplitPath)\22621.swm /FileSize:64



#Building Agent Manifest File:
$mftFilename = "Custom.mft"
$sigFileName = "Custom.sig"
Remove-Item -Path "$ImagePath\$mftFilename" -Force -ErrorAction SilentlyContinue
Remove-Item -Path "$ImagePath\$sigFilename" -Force -ErrorAction SilentlyContinue
$imageVersion = '22.12.02'
$header = "mft_version=1, image_version=$imageVersion"
Out-File -Encoding UTF8 -FilePath $SureRecoverWorkingpath\$mftFilename -InputObject $header
$Files = Get-ChildItem -Path $ImagePath -Recurse | Where-Object {$_.Attributes -ne 'Directory'}
$ToNatural = { [regex]::Replace($_, '\d*\....$',{ $args[0].Value.PadLeft(50) }) }
$pathToManifest = $ImagePath
$total = $Files.count
$current = 1
$Files | Sort-Object $ToNatural | ForEach-Object {
     Write-Progress -Activity "Generating manifest" -Status "$current of $total ($_)" -PercentComplete ($current / $total * 100)
     $hashObject = Get-FileHash -Algorithm SHA256 -Path $_.FullName
     $fileHash = $hashObject.Hash.ToLower()
     $filePath = $hashObject.Path.Replace($pathToManifest + '\', '')
     $fileSize = (Get-Item $_.FullName).length
     $manifestContent = "$fileHash $filePath $fileSize"
     Out-File -Encoding utf8 -FilePath $SureRecoverWorkingpath\$mftFilename -InputObject $manifestContent -Append
     $current = $current + 1
}
$content = Get-Content $SureRecoverWorkingpath\$mftFilename
$encoding = New-Object System.Text.UTF8Encoding $False
[System.IO.File]::WriteAllLines($pathToManifest + '\' + $mftFilename, 
$content, $encoding)

Move-Item  "$SureRecoverWorkingpath\$mftFilename" -Destination "$ImagePath\$mftFilename" -ErrorAction SilentlyContinue

#Sign Image Manfiest Files
$arg7 = "dgst -sha256 -sign $SureRecoverWorkingpath\my-recovery-private.pem -out $ImagePath\$sigFileName $ImagePath\$mftFilename"
$arg8 = "dgst -sha256 -verify $SureRecoverWorkingpath\my-recovery-public.pem -signature $ImagePath\$sigFileName $ImagePath\$mftFilename"
Start-Process -FilePath $OpenSLLFilePath -ArgumentList $arg7 -PassThru -NoNewWindow -Wait
Start-Process -FilePath $OpenSLLFilePath -ArgumentList $arg8 -PassThru -NoNewWindow -Wait

#Copy to Production WebServer Folder:
copy-item $ImagePath\* -Destination $ProdWebServerImagePath -Force -Verbose




$EndorsementKeyFile = "$SureRecoverWorkingpath\kek.pfx"
$SigningKeyFile = "$SureRecoverWorkingpath\sk.pfx"
$PublicKeyFile = "$SureRecoverWorkingpath\my-recovery-public.pem"
#$AgentPublicKeyFile  = $PublicKeyFile
$AgentPublicKeyFile  = "$SureRecoverWorkingpath\hpsr_agent_public_key.pem" #Default Signing Key for Default Agent

#Create the HP Secure Platform Payload Files - Provisining Secure Platform
New-HPSecurePlatformEndorsementKeyProvisioningPayload -EndorsementKeyFile $EndorsementKeyFile -EndorsementKeyPassword P@ssw0rd -OutputFile "$SureRecoverWorkingpath\SPEKPP.dat"
New-HPSecurePlatformSigningKeyProvisioningPayload -EndorsementKeyFile $EndorsementKeyFile -EndorsementKeyPassword P@ssw0rd -SigningKeyFile $SigningKeyFile -SigningKeyPassword P@ssw0rd  -OutputFile "$SureRecoverWorkingpath\SPSKPP.dat"

#Build the OSPayload file for Sure Recover Custom OS URL
New-HPSureRecoverImageConfigurationPayload -Image OS -SigningKeyFile $SigningKeyFile -SigningKeyPassword P@ssw0rd -PublicKeyFile $PublicKeyFile -Url $URL -OutputFile "$DatFilePath\OSpayload.dat"

#AgentFile - Only needed if hosting your own Agent (which is optional)
New-HPSureRecoverImageConfigurationPayload -Image Agent -SigningKeyFile $SigningKeyFile -SigningKeyPassword P@ssw0rd -PublicKeyFile $AgentPublicKeyFile  -Url $AgentURL -OutputFile "$SureRecoverWorkingpath\Agentpayload.dat" -Verbose

#Create Deprovisioning Payloads - For when you want to change your Sure Recover Settings, you need to deprovision first (or at least I've had to in my test machine)
New-HPSureRecoverDeprovisionPayload -SigningKeyFile $SigningKeyFile -SigningKeyPassword P@ssw0rd -OutputFile "$SureRecoverWorkingpath\SureRecoverDeprovision.dat"
New-HPSecurePlatformDeprovisioningPayload -Verbose -EndorsementKeyFile $EndorsementKeyFile -EndorsementKeyPassword P@ssw0rd -OutputFile "$SureRecoverWorkingpath\SecurePlatformDeprovision.dat"
