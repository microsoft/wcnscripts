$Logfile = ".\health.log"
$minThreshold = 50

function LogMessage {
    param (
        [parameter(Mandatory=$true)][string] $message
    )
    Add-content $Logfile -value "$message"
}

function CountAvailableEphemeralPorts([string]$protocol = "TCP") {

    [uint32]$portRangeSize = 64
    # First, remove all the text bells and whistle (plain text, table headers, dashes, empty lines, ...) from netsh output 
    $tcpRanges = (netsh int ipv4 sh excludedportrange $protocol) -replace "[^0-9,\ ]", '' | ? { $_.trim() -ne "" }
 
    # Then, remove any extra space characters. Only capture the numbers representing the beginning and end of range
    $tcpRangesArray = $tcpRanges -replace "\s+(\d+)\s+(\d+)\s+", '$1,$2' | ConvertFrom-String -Delimiter ","
    #Convert from PSCustomObject to Object[] type
    $tcpRangesArray = @($tcpRangesArray)
    
    # Extract the ephemeral ports ranges
    $EphemeralPortRange = (netsh int ipv4 sh dynamicportrange $protocol) -replace "[^0-9]", '' | ? { $_.trim() -ne "" }
    $EphemeralPortStart = [Convert]::ToUInt32($EphemeralPortRange[0])
    $EphemeralPortEnd = $EphemeralPortStart + [Convert]::ToUInt32($EphemeralPortRange[1]) - 1

    # Find the external interface
    $externalInterfaceIdx = (Get-NetRoute -DestinationPrefix "0.0.0.0/0")[0].InterfaceIndex
    $hostIP = (Get-NetIPConfiguration -ifIndex $externalInterfaceIdx).IPv4Address.IPAddress

    # Extract the used TCP ports from the external interface
    $usedTcpPorts = (Get-NetTCPConnection -LocalAddress $hostIP -ErrorAction Ignore).LocalPort
    $usedTcpPorts | % { $tcpRangesArray += [pscustomobject]@{P1 = $_; P2 = $_ } }

    # Extract the used TCP ports from the 0.0.0.0 interface
    $usedTcpGlobalPorts = (Get-NetTCPConnection -LocalAddress "0.0.0.0" -ErrorAction Ignore).LocalPort
    $usedTcpGlobalPorts | % { $tcpRangesArray += [pscustomobject]@{P1 = $_; P2 = $_ } }
    # Sort the list and remove duplicates
    $tcpRangesArray = ($tcpRangesArray | Sort-Object { $_.P1 } -Unique)

    $tcpRangesList = New-Object System.Collections.ArrayList($null)
    $tcpRangesList.AddRange($tcpRangesArray)

    # Remove overlapping ranges
    for ($i = $tcpRangesList.P1.Length - 2; $i -gt 0 ; $i--) { 
        if ($tcpRangesList[$i].P2 -gt $tcpRangesList[$i + 1].P1 ) { 
            $tcpRangesList.Remove($tcpRangesList[$i + 1])
            $i++
        } 
    }

    # Remove the non-ephemeral port reservations from the list
    $filteredTcpRangeArray = $tcpRangesList | ? { $_.P1 -ge $EphemeralPortStart }
    $filteredTcpRangeArray = $filteredTcpRangeArray | ? { $_.P2 -le $EphemeralPortEnd }
    
    if ($null -eq $filteredTcpRangeArray) {
        $freeRanges = @($EphemeralPortRange[1])
    }
    else {
        $freeRanges = @()
        # The first free range goes from $EphemeralPortStart to the beginning of the first reserved range
        $freeRanges += ([Convert]::ToUInt32($filteredTcpRangeArray[0].P1) - $EphemeralPortStart)

        for ($i = 1; $i -lt $filteredTcpRangeArray.length; $i++) {
            # Subsequent free ranges go from the end of the previous reserved range to the beginning of the current reserved range
            $freeRanges += ([Convert]::ToUInt32($filteredTcpRangeArray[$i].P1) - [Convert]::ToUInt32($filteredTcpRangeArray[$i - 1].P2) - 1)
        }

        # The last free range goes from the end of the last reserved range to $EphemeralPortEnd
        $freeRanges += ($EphemeralPortEnd - [Convert]::ToUInt32($filteredTcpRangeArray[$filteredTcpRangeArray.length - 1].P2))
    }
    
    # Count the number of available free ranges
    [uint32]$freeRangesCount = 0
    ($freeRanges | % { $freeRangesCount += [Math]::Floor($_ / $portRangeSize) } )

    return $freeRangesCount
}

function CheckPortExhaustion {
    Write-Host "Checking Port Exhaustion"
    $avTcpPorts = CountAvailableEphemeralPorts -protocol TCP
    if($avTcpPorts -lt $minThreshold) {
        $message = "Available TCP ports are $avTcpPorts. Port exhaustion suspected."
        Write-Host "$message" -ForegroundColor Red
        LogMessage -message $message
        return $true
    }
    $avUdpPorts = CountAvailableEphemeralPorts -protocol UDP
    if($avTcpPorts -lt $minThreshold) {
        $message = "Available UDP ports are $avUdpPorts. Port exhaustion suspected."
        Write-Host "$message" -ForegroundColor Red
        LogMessage -message $message
        return $true
    }
    Write-Host "Available TCP Ports :  $avTcpPorts , UDP Ports : $avUdpPorts . No port exhaustion suspected." -ForegroundColor Green
    return $false
}

$i = 0
Remove-Item $Logfile -ErrorAction Ignore

While($true) {
    $i++
    Write-Host "#============== Iteration : $i"
    if(CheckPortExhaustion) {
        Write-Host "DNS Issue Found." -ForegroundColor Red
    }
    Start-Sleep -Seconds 10
}
