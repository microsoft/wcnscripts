Write-Host "Detecting duplicate IP addresses on the node..."

$BaseDir = "c:\k\debug"

Write-Host "Trying to load HNS module..."

ipmo $BaseDir\hns.v2.psm1 -Force | Write-Host

while($true){
    $ipAddresses = ((Get-HnsEndpoint).IpConfigurations).IpAddress

    Write-Host "IP addresses on the node:"
    foreach($ip in $ipAddresses){
        Write-Host $ip
    }

    Write-Host "Checking for duplicate IP addresses inside the loop..."
    $duplicateIpAddr = $ipAddresses | Group-Object | Where-Object { $_.Count -gt 1 }

    if($duplicateIpAddr.Count -gt 0){
        break
    }

    Start-Sleep -Seconds 300
}

Write-Host "Duplicate IP addresses found on the node, Duplicate IP addresses are:"

foreach($ip in $duplicateIpAddr){
    Write-Host $ip
}

Write-Host "Collecting Windows logs..."
$collectWindowsLogs = "$BaseDir\collect-windows-logs.ps1" 
powershell $collectWindowsLogs | Write-Host

Write-Host "Collected Windows logs are at $PWD"

Write-Host "Issue has been detected, going into infinite loop to keep the container running..."
while($true){
    Write-Host "Container is running in infinte while..."
    Start-Sleep -Seconds 3600
}