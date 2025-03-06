Write-Host "Detecting duplicate IP addresses on the node..."

$BaseDir = "c:\k\debug"

Write-Host "Trying to load HNS module..."

ipmo $BaseDir\hns.v2.psm1 -Force | Write-Host

$iter = 1

pktmon stop # Stopping if pktmon is already running

# Start pktmon
Write-Host "Starting pktmon with trace level 6 for HNS"
pktmon start --trace -p Microsoft-Windows-Host-Network-Service -l 6 -f traces.etl -s 1024

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

    $iter++

    Start-Sleep -Seconds 300
}

Write-Host "Duplicate IP addresses found on the node, Duplicate IP addresses are:"

foreach($ipGroup in $duplicateIpAddr){
    Write-Host $ipGroup.Name
}

Write-Host "Stopping pktmon..."
# Stop pktmon
pktmon stop

Write-Host "Collecting Windows logs..."
$collectWindowsLogs = "$BaseDir\collect-windows-logs.ps1" 
powershell $collectWindowsLogs | Write-Host

Write-Host "Collected Windows logs and trace are at $PWD"

while($true){
    if ($iter -Eq 1) {
		Write-Host "The issue was detected in the first iteration and it may have happened already, and log rotation may have occurred."
	} else {
		Write-Host "Issue detected. Please download and review the collected Windows logs and also traces from the following path: $PWD\traces.etl"
	}
    Start-Sleep -Seconds 3600
}