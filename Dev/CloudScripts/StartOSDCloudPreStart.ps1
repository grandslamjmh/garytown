Invoke-Expression (Invoke-RestMethod 'sandbox.osdcloud.com')
$Global:MyOSDCloud = [ordered]@{
        Restart = [bool]$False
        RecoveryPartition = [bool]$True
        DriverPackName = "None"
    }

#Launch OSDCloud
Start-OSDCloudGUIDev
