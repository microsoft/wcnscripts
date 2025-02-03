Write-Host "Detecting duplicate IP addresses on the host..."

$BaseDir = "c:\k\debug"
ipmo $BaseDir\hns.v2.psm1 -Force

while($true){
    $ipAddresses = Get-HnsEndpoint.IpAddress
    $duplicateIpAddr = $ipAddresses | Group-Object | Where-Object { $_.Count -gt 1 }

    if($duplicateIpAddr.Count -gt 0){
        break
    }

    Start-Sleep -Seconds 300
}

Write-Host "Duplicate IP addresses found on the host, collecting windows logs..."
& "$BaseDir\collect-windows-logs.ps1"