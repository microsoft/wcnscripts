function Is-CompartmentIdValid() {
	Write-Host "#===== Validating Compartment ID in Endpoint and Namespace =====#"
	Write-Host ""
	$eps = Get-HnsEndpoint
	$nss = Get-HnsNamespace
	$compsNotMatching = @()

	foreach($ep in $eps) {
		if ($ep.Resources.Allocators.CompartmendId.Length -gt 0) {
			$compId = [int]$($ep.Resources.Allocators.CompartmendId[0])
			$nsId = $ep.Namespace.ID
			foreach($ns in $nss) {
				if ($ns.ID -Eq $nsId) {
					Write-Host "IP Address : $($ep.IPAddress), NamespaceID: $nsId, EPCompID : $compId, NSCompID: $($ns.CompartmentId)"	
					if ($ns.CompartmentId -NE $compId) {
						Write-Host "CompartmentId not matching..."
						$compsNotMatching += $ep.IPAddress
					} else {
						Write-Host "CompartmentId matching..."
					}
				}
			}
		}
	}
	Write-Host ""
	if ($compsNotMatching.Length -gt 0) {
		Write-Host "CompartmentId not matching for the following IPs: $($compsNotMatching -join ', ')" -ForegroundColor Red
		return $false
	}
	return $true
}

$iter = 1
$curLoc = (Get-Location).Path
pktmon stop # Stopping if pktmon is already running

# Start pktmon
Write-Host "#===== Starting pktmon with trace level 6 for TCPIP and Host-Network-Service =====#"
pktmon start --trace -p Microsoft-Windows-TCPIP -k 0xFF -l 6 -p Microsoft-Windows-Host-Network-Service -l 6 -f traces.etl -s 2048


While(Is-CompartmentIdValid) {
	$d = Get-Date
	Write-Host "#===== Iteration: $iter completed at $d. No issue found. Waiting for 1 minute for next iteration. =====#"
	Write-Host ""
	Start-Sleep -Seconds 60
	$iter++
}

Write-Host "#===== Issue detected. Waiting for 1 minute before Stopping pktmon and collecting logs. =====#"
Start-Sleep -Seconds 60
Write-Host ""
# Stop pktmon
pktmon stop

# Collecting Windows logs
C:\k\debug\collect-windows-logs.ps1

Write-Host "Traces available in $curLoc\traces.etl"

# The below While loop will keep the script running indefinitely keeping the hpc pod alive.
# Without this, the pod will exit after the script execution and restart the process again deleting the logs.
While($true) {
	if ($iter -Eq 1) {
		Write-Host "The issue was detected on a previously corrupted node, and log rotation may have occurred."
	} else {
		Write-Host "Issue detected. Please download and review the collected Windows logs and also traces from the following path: $curLoc\traces.etl"
	}
	Start-Sleep -Seconds 3600
}
