param (
    [Parameter(Mandatory=$false, HelpMessage="If Enabled, executes testcases for DualStatck scenarios")][bool]$DualStack = $false,
    [Parameter(Mandatory=$false, HelpMessage="If Enabled, starts packet capture for DNS packets from all compartments")][bool]$DnsPktCap = $false,
    [Parameter(Mandatory=$false, HelpMessage="Domian used to test internet connectivity")][string]$DomainName = "bing.com",
    [Parameter(Mandatory=$false, HelpMessage="This will stop printing error status in stiout if disabled")][bool]$enableStatus = $true,
    [Parameter(Mandatory=$false, HelpMessage="This will dump the vfp rule counter for those pods with mentioned prefix. Eg: -PodNamePrefixes tcp-client,tcp-server")][string[]] $PodNamePrefixes = @("tcp-client", "tcp-server"),
    [Parameter(Mandatory=$false, HelpMessage="If Enabled will dump Vfp rule counters even with Match packet counter.")][bool] $PrintMatchedRules = $false,
    [Parameter(Mandatory=$false, HelpMessage="This will dump the vfprulecounter info to stdout if set to true")][bool] $EnableVfpOutput = $false,
    [Parameter(Mandatory=$false, HelpMessage="These are ServiceIPs which will be used to verify missing LB_DSR VFP rules.")][string]$ServiceIPS = ""
)

$LogDirPrefix = "C:\k\debug\NetworkHealth\Log-"

$timeNowInUtc = Get-Date -Format u
$LogDirSuffix = $timeNowInUtc.Replace(" ", "-").Replace(":", "-")

$LogsDir = $LogDirPrefix + $LogDirSuffix

$Logfile = "$LogsDir\health.log"
$VfpRuleFile = "$LogsDir\vfpRuleCounter.log"

mkdir $LogsDir -ErrorAction Ignore

$LogsZip = "$LogsDir.zip"
$trafficTimeInS = 10

$ruleCounterMap = @{}
$cwd = Get-Location

function LogError {
    param (
        [parameter(Mandatory=$true)][string] $message
    )
    if($enableStatus) {
        Write-Host $message -ForegroundColor Red
    }
    Add-content $Logfile -value "[FAILED] $message"
}

function LogSuccess {
    param (
        [parameter(Mandatory=$true)][string] $message
    )
    Write-Host $message -ForegroundColor Green
    Add-content $Logfile -value "[SUCCESS] $message"
}

function LogVfpCounter {
    param (
        [parameter(Mandatory=$false)][string] $value = "",
        [parameter(Mandatory=$false)][bool] $error = $false
    )
    Add-Content -Path $VfpRuleFile -Value $value
    if($EnableVfpOutput) {
        if ($error -eq $true) {
            Write-Host $value -ForegroundColor Red
        }
        else {
            Write-Host $value
        }
    }
}

function NewLine {
    param (
        [parameter(Mandatory=$false)][int] $NoOfLines = 1
    )
    for ($i = 1; $i -le $NoOfLines; $i++) {
        LogVfpCounter ""
    }
}

#=========================== VFP Rule Counter Functions ================#

$InterestedPortMetrics = "TotalPackets", "TotalBytes", "DroppedPackets", "DroppedAcl", "PendingPackets", "TcpFinPackets", "TcpResetPackets", "TcpConnectionsVerified", "TcpConnectionsTimedOut", "TcpConnectionsResets", "TcpConnectionsResetHalfTTL", "TcpConnectionsResetBySyn", "TcpConnectionsResetByInjectedReset", "TcpConnectionsClosedByFin", "TcpHalfOpenTimeouts"

$DIRECTIONS = "EGRESS", "INGRESS"

$ruleCounterMap = @{}

class Pod {
    [string]$Name
    [string]$IPAddress
    [string]$MacAddress
    [string]$VfpPortGuid
    [string]$EndpointId
    [hashtable] $NetworkMetrics = @{}
}

function GetPortCounter {
    param (
        [parameter(Mandatory=$true)][string] $portId
    )
    LogVfpCounter "  #== Port Counters ==#"
    NewLine 1
    $portCounterObj = vfpctrl.exe /port $portId /get-port-counter /format 1 | ConvertFrom-Json
    $portCounters = $portCounterObj.InformationArray.PortCounters
    foreach ($portCounter in $portCounters) {
        foreach ($metric in $InterestedPortMetrics) {
            $value = $portCounter.$metric
            $direction = $DIRECTIONS[$portCounter.Direction]
            $metric = ($metric).ToUpper().Replace(" ", "-")
            if (($metric -contains "DROPPED") -and ($value -gt 0)) {
                LogVfpCounter "  $direction-$metric : $value" -error $true
            }
            else {
                LogVfpCounter "  $direction-$metric : $value"
            }
        }
    }
}

function GetRuleCounter {
    param (
        [parameter(Mandatory=$true)][string] $portId
    )
    $vfpPacketDropFound = $false
    NewLine 1
    LogVfpCounter "  #== Rule Counters ==#"
    NewLine 1
    $ruleCounterObj = vfpctrl.exe /port $portId /get-rule-counter /format 1 | ConvertFrom-Json
    $layers = $ruleCounterObj.Layers
    foreach ($layer in $layers) {
        $layerName = $layer.Name
        $groups = $layer.Groups

        foreach ($group in $groups) {
            $groupName = $group.Name

            $rules = $group.Rules
            foreach ($rule in $rules) {

                $ruleId = $rule.Name
                if (($rule.Id).Length -gt 0) {
                    $ruleId = $rule.Id
                }

                $ruleKey = "$portId-$layerName-$groupName-$ruleId"
                $oldRule = $ruleCounterMap[$ruleKey]

                $informationArray = $rule.InformationArray

                $rule.PSObject.Properties.Remove('$type')
                $rule.PSObject.Properties.Remove('Type')
                $rule.PSObject.Properties.Remove('SubType')
                $rule.PSObject.Properties.Remove('MssDelta')
                $rule.PSObject.Properties.Remove('ReverseMssDelta')
                $rule.PSObject.Properties.Remove('RuleFlags')
                $rule.PSObject.Properties.Remove('PaRouteRuleFlags')
                $rule.PSObject.Properties.Remove('CachePruningThreshold')
                $rule.PSObject.Properties.Remove('InformationArray')
                $rule.PSObject.Properties.Remove('NumHeaders')
                $rule.PSObject.Properties.Remove('PartialRewriteTypes')

                if ($informationArray.Count -gt 0) {
                    $rule | Add-Member -MemberType NoteProperty -Name RuleCounters -Value $informationArray[0].RuleCounters
                }

                $ruleJson = $rule | ConvertTo-Json -Depth 10

                if ($informationArray.Count -gt 0) {

                    $ruleCounters = $informationArray[0].RuleCounters
                    $matchedPackets = $ruleCounters.MatchedPackets
                    $droppedPackets = $ruleCounters.DroppedPackets
                    $pendingPackets = $ruleCounters.PendingPackets
                    $droppedFlows = $ruleCounters.DroppedFlows

                    if (($droppedPackets -gt 0) -or ($pendingPackets -gt 0) -or ($droppedFlows -gt 0)) { 
                        $vfpPacketDropFound = $true
                        LogVfpCounter "  Dropped Rule : " -error $true
                        LogVfpCounter "  ================ " -error $true
                        NewLine 1
                        LogVfpCounter "  Layer : $layerName , Group : $groupName , Id : $ruleId " -error $true
                        NewLine 1
                        LogVfpCounter "  $ruleJson " -error $true                                    
                        if ($null -ne $oldRule) {

                            $oldDroppedPackets = $oldRule.RuleCounters.DroppedPackets
                            $oldPendingPackets = $oldRule.RuleCounters.PendingPackets
                            $oldDroppedFlows = $oldRule.RuleCounters.DroppedFlows

                            $diffDroppedPackets = $droppedPackets - $oldDroppedPackets
                            $diffPendingPackets = $pendingPackets - $oldPendingPackets
                            $diffDroppedFlows = $droppedFlows - $oldDroppedFlows

                            if (($diffDroppedPackets -gt 0) -or ($diffPendingPackets -gt 0) -or ($diffDroppedFlows -gt 0)) {
                                LogVfpCounter "  Rule key : $ruleKey " -error $true
                                LogVfpCounter "  Change in Dropped Packets : $diffDroppedPackets [$oldDroppedPackets - $droppedPackets] " -error $true
                                LogVfpCounter "  Change in Pending Packets : $diffPendingPackets [$oldPendingPackets - $pendingPackets] " -error $true
                                LogVfpCounter "  Change in Dropped Flows : $diffDroppedFlows [$oldDroppedFlows - $droppedFlows] " -error $true
                            }

                        }

                        NewLine 2

                    }
                    elseif (($PrintMatchedRules -eq $true) -and ($matchedPackets -gt 0)) {   
                        LogVfpCounter "  Matched Rule : "
                        LogVfpCounter "  ================ "
                        NewLine 1
                        LogVfpCounter "  Layer : $layerName , Group : $groupName , Id : $ruleId "
                        NewLine 1
                        LogVfpCounter "  $ruleJson "

                        if ($null -ne $oldRule) {

                            $oldMatchedPackets = $oldRule.RuleCounters.MatchedPackets
                            $diffMatchedPackets = $matchedPackets - $oldMatchedPackets

                            if ($diffMatchedPackets -gt 0) {
                                LogVfpCounter "  Rule key : $ruleKey "
                                LogVfpCounter "  Change in Matched Packets : $diffMatchedPackets [$oldMatchedPackets - $matchedPackets] "
                            }

                        }

                        NewLine 2
                    }

                    $ruleCounterMap[$ruleKey] = $rule
                }
            }
        }
    }

    return $vfpPacketDropFound
}

function GetPodName {
    param (
        [Parameter(Mandatory = $True)][string[]] $containerIdentifiers,
        [Object[]] $PodsInfo
    )

    $items = (($PodsInfo | ConvertFrom-Json).items)
    foreach ($podID in $containerIdentifiers) {
        foreach ($item in $items) {
            if ($item.id -Eq $podID) {
                return $item.metadata.name
            }
        }
    }

    return "unknown"
}

function isPodNamePresent {
    param (
        [Parameter(Mandatory = $True)][string] $podName
    )

    foreach ($podPrefix in $PodNamePrefixes) {
        if ($podName.StartsWith($podPrefix, 'CurrentCultureIgnoreCase')) {
            return $True
        }
        if($podPrefix -eq "*") {
            return $True
        }
    }

    return $false
}

function GetPods {
    [Pod[]]$PodList = @()
    $hnsEndpoints = Get-HnsEndpoint
    $podsInfo = crictl pods -o json
    foreach ($endpoint in $hnsEndpoints) {
        $isremoteEndpoint = ($endpoint.IsRemoteEndpoint -eq $true)
        if ($isremoteEndpoint -ne $true) {
            $endpointPortResource = $endpoint.Resources.Allocators | Where-Object Tag -eq "Endpoint Port"
            $currPortId = $endpointPortResource.EndpointPortGuid
            $podName = GetPodName -containerIdentifiers $endpoint.SharedContainers -PodsInfo $podsInfo
            if ($podName -eq "unknown") {
                continue
            }
            if ($PodNamePrefixes.Length -ne 0 -and !(isPodNamePresent -podName $podName)) {
                continue
            }
            $pod = [Pod]::new()
            $pod.Name = $podName
            $pod.VfpPortGuid = $currPortId
            $pod.EndpointId = $endpoint.ID
            $pod.IPAddress = $endpoint.IPAddress
            $PodList += $pod
        }
    }
    return $PodList
}

function VfpNetworkMetrics {
    param (
        [Parameter(Mandatory = $True)][int] $iteration
    )

    $vfpPacketDropFound = $false

    $timeNowInUtc = Get-Date -Format u
    NewLine 2
    LogVfpCounter "#============ Iteration : $iteration , UTC Time : $timeNowInUtc ============#"

    $vmSwitch = vfpctrl.exe /list-vmswitch-port /format 1 | ConvertFrom-Json
    $ports = $vmSwitch.Ports
    $pods = GetPods

    foreach ($port in $ports) {

        $portName = $port.Id
        $portId = $port.Name
        $portNo = $port.VmsPortId

        $isHostPort = (($portName.Length -gt 14) -and ($portName.Substring(0, 13) -Eq "Container NIC"))

        if (($portName -eq "ExternalPort") -or ($isHostPort -eq $true)) {
            $friendlyPortName = $port.Id
            $mac = $port.MacAddress
            $mac = $mac -replace '..(?!$)', '$0-'
            NewLine 2
            LogVfpCounter "#==== Port : $portName , Mac : $mac , VFP Port ID : $portId , Port No : $portNo , Port Name = $friendlyPortName ,  ====#"
            NewLine 1
            GetPortCounter -portId $portId
            $isDropped = GetRuleCounter -portId $portId
            if($isDropped -eq $true) {
                $vfpPacketDropFound = $true
            }
            NewLine 2
            continue
        }

        foreach ($pod in $pods) {
            if ($pod.VfpPortGuid -eq $portId) {
                $ip = $pod.IPAddress
                $podName = $pod.Name
                $epId = $pod.EndpointId
                $friendlyPortName = $port.Id
                $mac = $port.MacAddress
                $mac = $mac -replace '..(?!$)', '$0-'
                # $ip = (Get-HnsEndpoint | Where-Object MacAddress -EQ $mac).IPAddress
                NewLine 2
                LogVfpCounter "#==== Pod Name : $podName , IP : $ip , Mac : $mac , Endpoint ID : $epId , VFP Port ID : $portId , Port No : $portNo , Port Name = $friendlyPortName ,  ====#"
                NewLine 1
                GetPortCounter -portId $portId
                $isDropped = GetRuleCounter -portId $portId
                if($isDropped -eq $true) {
                    $vfpPacketDropFound = $true
                }
                NewLine 2
            }
        }
    }
    return $vfpPacketDropFound
}

function CheckVfpPacketDrops {
    Write-Host "Checking VFP Packet Drops"
    $vfpPacketDropFound = VfpNetworkMetrics -iteration 1
    LogVfpCounter "#=========== Waiting $trafficTimeInS seconds for vfp counters to change."
    if($EnableVfpOutput -eq $false) {
        Write-Host "#=========== Waiting $trafficTimeInS seconds for vfp counters to change."
    }
    Start-Sleep -Seconds $trafficTimeInS
    $vfpPacketDropFound = VfpNetworkMetrics -iteration 2
    if($vfpPacketDropFound -eq $true) {
        LogError "VFP Packet Drop identified. Please check $VfpRuleFile for detailed information."
        return $true
    }
    LogSuccess "There is no VFP Packet Drop identified."
    return $false
}

#=========================== VFP Rule Counter Functions ================#

function readVfpPortIdList() {
    $vfpPortIds = ((vfpctrl /list-vmswitch-port /format 1 | ConvertFrom-Json).Ports).Name
    return $vfpPortIds
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

function CheckNetworkingServices {
    Write-Host "Checking Status of HNS and Kubeproxy"

    $statusMessage = ""
    $hnsStatus = (Get-Service hns -ErrorAction SilentlyContinue).Status
    $kubeProxyStatus = (Get-Service kubeproxy -ErrorAction SilentlyContinue).Status
    $kubeletStatus = (Get-Service kubelet -ErrorAction SilentlyContinue).Status
    $vfpStatus = (Get-Service vfpext -ErrorAction SilentlyContinue).Status
    $tcpIpStatus = (Get-Service tcpip -ErrorAction SilentlyContinue).Status

    if($hnsStatus -ne "Running") {
        $statusMessage = "HNS is not running. HNS Status : $hnsStatus . Restart hns : Restart-Service -f hns"
    }

    if($kubeProxyStatus -ne "Running") {
        $statusMessage += "KubeProxy is not running. KubeProxy Status : $kubeProxyStatus . Restart KubeProxy : Restart-Service -f kubeproxy"
    }

    if($kubeletStatus -ne "Running") {
        $statusMessage += "kubelet is not running. kubelet Status : $kubeletStatus . Restart kubelet : Restart-Service -f kubelet"
    }

    if($vfpStatus -ne "Running") {
        $statusMessage += "VFP is not running. VFP Status : $vfpStatus . Restart VFP : Restart-Service -f vfpext"
    }

    if($tcpIpStatus -ne "Running") {
        $statusMessage += "TCPIP is not running. TCPIP Status : $tcpIpStatus . Restart TCPIP : Restart-Service -f tcpip"
    }

    if($statusMessage -eq "") {
        LogSuccess "HNS, Kubelet, VFP, TCPIP and Kubeproxy is running fine"
        return $false
    }

    LogError "$statusMessage"
    
    return $true
}

function CheckHnsDnsRuleMissing {
    $expectedDnsRuleCount = 2
    Write-Host "Checking HNS DNS Rule missing"
    $dnsRuleCount = ((Get-HnsPolicyList).Policies | Where-Object InternalPort -EQ 53 | Where-Object ExternalPort -EQ 53).Count

    if($dnsRuleCount -lt $expectedDnsRuleCount) {
        Start-Sleep -Seconds 10
        $dnsRuleCount = ((Get-HnsPolicyList).Policies | Where-Object InternalPort -EQ 53 | Where-Object ExternalPort -EQ 53).Count
    }

    if($dnsRuleCount -lt $expectedDnsRuleCount) {
        LogError "HNS DNS rule count is $dnsRuleCount. DNS issue for sure."
        LogError "Resolution: Upgrade to 1.24.10+, 1.25.6+, 1.26.1+, 1.27.0+"
        LogError "Mitigation : Restart-Service -f kubeproxy"
        return $true
    }
    LogSuccess "HNS DNS rule count is $dnsRuleCount. No DNS issue due to missing HNS DNS rules."
    return $false
}

function CheckHnsDeadlock {
    Write-Host "Checking HNS Deadlock."
    $hnsThreadThrshold = 100
    $hnsProcessId = Get-WmiObject -Class Win32_Service -Filter "Name LIKE 'Hns'" | Select-Object -ExpandProperty ProcessId
    $hnsThreads = (Get-Process -Id $hnsProcessId).Threads
    $threadCount = $hnsThreads.Count
    if($threadCount -ge $hnsThreadThrshold) {
        LogError "HNS thread count is $threadCount which is greater than expected $hnsThreadThrshold. There are chances of deadlock."
        LogError "Resolution: Upgrade to Windows 2022"
        LogError "Mitigation : Restart-Service -f hns , Start-Sleep -Seconds 10 ; Restart-Service -f KubeProxy "
        return $true
    }
    LogSuccess "HNS thread count is $threadCount . No chances of deadlock."
    return $false
}

function CheckHnsCrash {
    Write-Host "Checking HNS crash"
    $hnsCrashCount = (Get-WinEvent -FilterHashtable @{logname = 'System'; ProviderName = 'Service Control Manager' } | Select-Object -Property TimeCreated, Id, LevelDisplayName, Message | Where-Object Message -like "*The Host Network Service terminated unexpectedly*").Count
    if($hnsCrashCount -gt 0) {
        LogError "HNS crash count is $hnsCrashCount. There are chances of issues."
        LogError "Resolution: Upgrade to 1.24.10+, 1.25.6+, 1.26.1+, 1.27.0+"
        LogError "Mitigation : Restart-Service -f KubeProxy "
        return $true
    }
    LogSuccess "HNS crash count is $hnsCrashCount. No issue reported with HNS crash."
    return $false
}

function CheckPingNodeToInternet {
    Write-Host "Checking ping test from node to internet."
    $isStatusFailed = $false
    
    $result = ping 8.8.8.8 -n 2
    $pingTestSuccess = !(($result | findstr "loss").Contains("100% loss"))
    if($pingTestSuccess) {
        LogSuccess "Ping test from node to 8.8.8.8 passed."        
    } else {
        LogError "Ping test from node to 8.8.8.8 failed."
        $isStatusFailed = $true
    }
    $result = ping bing.com -n 2
    $pingTestSuccess = !(($result | findstr "loss").Contains("100% loss"))
    if($pingTestSuccess) {
        LogSuccess "Ping test from node to bing.com passed."        
    } else {
        LogError "Ping test from node to bing.com failed."
        $isStatusFailed = $true
    }

    if($DualStack) {
        $result = ping 2001:4860:4860::8888 -n 2
        $pingTestSuccess = !(($result | findstr "loss").Contains("100% loss"))
        if($pingTestSuccess) {
            LogSuccess "Ping test from node to 2001:4860:4860::8888 passed."        
        } else {
            LogError "Ping test from node to 2001:4860:4860::8888 failed."
            $isStatusFailed = $true
        }
        $result = ping -6 bing.com -n 2
        if(($null -eq $result) -or ($null -eq ($result | findstr "loss"))) {
            LogError "IPV6 Ping test from node to bing.com failed."
            $isStatusFailed = $true
        } else {
            $pingTestSuccess = !(($result | findstr "loss").Contains("100% loss"))
            if($pingTestSuccess) {
                LogSuccess "IPV6 Ping test from node to bing.com passed."        
            } else {
                LogError "IPV6 Ping test from node to bing.com failed."
                $isStatusFailed = $true
            }
        }
    }

    return $isStatusFailed
}

function CheckNodeToInternetConnectivity {
    Write-Host "Checking Node to Internet Connectivity."
    $status = Invoke-WebRequest bing.com -UseBasicParsing
    if($status.StatusCode -le 499) {
        LogSuccess "No issues with invoke webrequest from node to internet (bing.com)."
        return $false
    }
    LogError "Invoke webrequest from node to internet (bing.com) not working."
    return $true
}

function CheckPortExhaustion {
    Write-Host "Checking Port Exhaustion"
    $avTcpPorts = CountAvailableEphemeralPorts -protocol TCP
    if($avTcpPorts -lt 10) {
        LogError "Available TCP ports are $avTcpPorts. Port exhaustion suspected."
        return $true
    }
    $avUdpPorts = CountAvailableEphemeralPorts -protocol UDP
    if($avTcpPorts -lt 10) {
        LogError "Available UDP ports are $avUdpPorts. Port exhaustion suspected."
        return $true
    }
    LogSuccess "Available TCP Ports :  $avTcpPorts , UDP Ports : $avUdpPorts . No port exhaustion suspected."
    return $false
}

function CheckKubeProxyCrash {
    Write-Host "Checking KubeProxy restart"
    for($i = 1; $i -le 10; $i++) {
        $status = (Get-Service kubeproxy -ErrorAction SilentlyContinue).Status
        if($status -eq "Stopped") {
            LogError "KubeProxy is restarting. There are chances of issues."
            LogError "Resolution: Upgrade to v1.24.12+, v1.25.8, v1.26.3+, v1.27.0+"
            LogError "Mitigation : Restart the node or drain to a new node "
            return $true
        }
        $waitTime = (10 - $i)
        Write-Host "Checking KubeProxy restart. Wait time : $waitTime seconds"
        Start-Sleep -Seconds 2
    }
    LogSuccess "KubeProxy service state is $status . No issues identified with KubeProxy restart."
    return $false
}

function CheckKubeletCrash {
    Write-Host "Checking Kubelet restart"
    for($i = 1; $i -le 10; $i++) {
        $status = (Get-Service kubelet -ErrorAction SilentlyContinue).Status
        if($status -eq "Stopped") {
            LogError "Kubelet is restarting. There are chances of issues."
            LogError "Resolution: Upgrade to v1.24.12+, v1.25.8, v1.26.3+, v1.27.0+"
            LogError "Mitigation : Restart the node or drain to a new node "
            return $true
        }
        $waitTime = (10 - $i)
        Write-Host "Checking kubelet restart. Wait time : $waitTime seconds"
        Start-Sleep -Seconds 2
    }
    LogSuccess "Kubelet service state is $status . No issues identified with Kubelet restart."
    return $false
}

function CheckingInvalidHnsPolicy {
    Write-Host "Checking invalid HNS Policy"
    $invalidPolicies = @{}
    $policyIdAndRefs = Get-HnsPolicyList | Select-Object ID, References
    foreach($idref in $policyIdAndRefs){
	    $ref = $idref.References
	    $epids = ($ref -Split "/endpoints/")[1]
	    $invalidEps = @()
	    foreach($epid in $epids) {
		    if($epid.Length -gt 10) {
			    $ep = Get-HnsEndpoint -Id $epid -ErrorAction SilentlyContinue
			    if($null -Eq $ep) {
				    $invalidEps += $epid
			    }
		    }
	    }
	    if(($invalidEps).Count -gt 0){
		    $polId = $idref.Id
		    $invalidPolicies[$polId] = $invalidEps
	    }
    }
    if(($invalidPolicies).Count -gt 0) {
        $jsonOutput = $invalidPolicies | ConvertTo-Json -Depth 10
	    LogError "Few HNS Policies has invalid endpoints : $jsonOutput"
	    return $true
    }
    LogSuccess "All HNS Policies has valid endpoints."
    return $false
}

function CheckPodIpMissing {
    Write-Host "Checking missing of pod ip"
    $missingPodsIps = @()
    $podIds = crictl ps -q
    foreach($podId in $podIds) {
        $ipValue = crictl exec -it $podId ipconfig /all
        $ipv4Config = ($ipValue | find "IPv4 Address")
        if(($null -ne $ipv4Config) -and (($ipv4Config.Split(":")[1]).Length -lt 10)) {
            $hostConfig = ($ipValue | find "Host Name")
            $missingPodsIps += $hostConfig.Split(":")[1]
        }
    }

    if($missingPodsIps.Length -gt 0) {
        LogError "Pod IP missing in few pods : $missingPodsIps"
        return $true
    }

    LogSuccess "Pod IP is present in all the pods."
    return $false
}

function TriggerCurlRequest {
    Write-Host "Triggering curl request to : $DomainName started"

    $podIds = crictl ps -q
    foreach($podId in $podIds) {
        crictl exec -it $podId curl $DomainName
    }

    Write-Host "Triggering curl request to : $DomainName completed"
}

function CheckHnsNetworksMissing {
    $hnsNetworks = @("ext", "azure")
    $missingNetworks = @()
    Write-Host "Checking HNS networks missing."
    $availableNetworks = (Get-HnsNetwork).Name

    foreach($nw in $hnsNetworks) {
        $nwPresent = $false
        foreach($avNw in $availableNetworks) {
            if($avNw -EQ $nw) {
                $nwPresent = $true
                break
            }
        }
        if($nwPresent -eq $false) {
            $missingNetworks += $nw
        }
    }

    if($missingNetworks.Count -eq 0) {
        LogSuccess "All HNS networks present."
        return $false
    }

    LogError "There are missing HNS networks : $missingNetworks"
    return $true
}

function CheckDefaultRouteMissing {
    Write-Host "Checking missing of default route"
    $isStatusFailed = $false

    if($DualStack) {
        $defaultGwPrefix = "::/0"
        $defaultRouteNextHop = "fe80::1234:5678:9abc"
            
        $ip = (Get-HnsNetwork | Select-Object ManagementIPv6)[0].ManagementIPv6
        $ifIndex = (Get-NetIPAddress -IPAddress $ip | Select-Object InterfaceIndex).InterfaceIndex

        $defaultRouteEntry = (Get-NetRoute -InterfaceIndex $ifIndex -NextHop $defaultRouteNextHop -DestinationPrefix $defaultGwPrefix)
        if(($null -eq $defaultRouteEntry) -or (($defaultRouteEntry).ifIndex -ne $ifIndex)) {
            LogError "IPV6 Default route is missing. There are chances of issues."
            LogError "Mitigation : New-NetRoute -DestinationPrefix $defaultGwPrefix -AddressFamily IPv6 -NextHop $defaultRouteNextHop -InterfaceIndex $ifIndex"
            $isStatusFailed = $true
        } else {
            LogSuccess "IPV6 Default route is looking good."
        }
    }

    return $isStatusFailed
}

function CheckHardwareHealth {
    Write-Host "Checking hardware health"
    $hwHealth = @{}
    $sysInfo = systeminfo
    $osName = $sysInfo | find "OS Name"
    $osVersion = $sysInfo | find "OS Version" | sls -NotMatch "BIOS"
    for($i = 1; $i -le 10; $i++) {
        $sysInfo = systeminfo
        $virtInfo = $sysInfo | find "Virtual Memory: Available"
        $availableVirtMem = [int]($virtInfo.Split(" ")[3])
        if($availableVirtMem -lt 1000) {
            $hwHealth["Available Virtual Memory"] = $availableVirtMem
        }

        $phyInfo = $sysInfo | find "Available Physical Memory"
        $availablePhyMem = [int]($phyInfo.Split(" ")[3])
        if($availablePhyMem -lt 1000) {
            $hwHealth["Available Physical Memory"] = $availablePhyMem
        }
        Start-Sleep -Seconds 2
    }
    if($hwHealth.Count -eq 0) {
        LogSuccess "Harware configuration is looking good. $osName , $osVersion"
        return $false
    }
    LogError "Harware configuration is not healthy. $osName , $osVersion . health : $hwHealth"
    return $true
}

function CheckVfpDnsRuleMissing {
    Write-Host "Checking VFP DNS Rule missing"
    $vfpDnsRuleMissing = $false
    $endpoints = Get-HnsEndpoint
    $oneTimeWait = $true
    foreach($ep in $endpoints) {
        if($ep.IsRemoteEndpoint -eq $true) {
            # Write-Host "REP found : $ep"
            continue
        }
        $epID = $ep.ID
        $epMac = $ep.MacAddress
        $epIpAddress = $ep.IPAddress
        $portID = $ep.Resources.Allocators[0].EndpointPortGuid

        $tcpRule = vfpctrl.exe /port $portID /layer LB_DSR /group LB_DSR_IPv4_OUT /list-rule | Select-String -Pattern "RULE.*53_53_6"
        if(($tcpRule.Count -lt 1) -and ($oneTimeWait -eq $true)) {
            Start-Sleep -Seconds 10
            $tcpRule = vfpctrl.exe /port $portID /layer LB_DSR /group LB_DSR_IPv4_OUT /list-rule | Select-String -Pattern "RULE.*53_53_6"
            $oneTimeWait = $false
        }
        if($tcpRule.Count -lt 1) {
            $vfpDnsRuleMissing = $true
            LogError "VFP DNS TCP Rule missing for VFP Port : $portID . Endpoint ID : $epID , Mac : $epMac , IP Address : $epIpAddress"
        }
        
        $udpRule = vfpctrl.exe /port $portID /layer LB_DSR /group LB_DSR_IPv4_OUT /list-rule | Select-String -Pattern "RULE.*53_53_17"
        if(($udpRule.Count -lt 1) -and ($oneTimeWait -eq $true)) {
            Start-Sleep -Seconds 10
            $udpRule = vfpctrl.exe /port $portID /layer LB_DSR /group LB_DSR_IPv4_OUT /list-rule | Select-String -Pattern "RULE.*53_53_17"
            $oneTimeWait = $false
        }
        if($udpRule.Count -lt 1) {
            $vfpDnsRuleMissing = $true
            LogError "VFP DNS UDP Rule missing for VFP Port : $portID . Endpoint ID : $epID , Mac : $epMac , IP Address : $epIpAddress"
        }
    }

    if($vfpDnsRuleMissing){
        LogError "Mitigation : Restart-Service -f hns "
        return $true
    }

    LogSuccess "No issues identified with VFP DNS Rule Missing for local endpoints."
    return $false
}

function CheckLbDsrRuleMissing {

    Write-Host "Checking LB DSR Rule missing"
    $lbDsrRuleMissing = $false

    $serviceIPList = $ServiceIPS.Split(",")

    $portIdList = readVfpPortIdList

    foreach($portId in $portIdList) {

	    $entries = vfpctrl /port $portId /layer LB_DSR /list-group
	    if($entries.Count -le 8) {
		    continue
	    }
	    foreach($serviceIP in $serviceIPList) {
		    $entries = vfpctrl /port $portId /layer LB_DSR /group LB_DSR_IPv4_OUT /list-rule | sls $serviceIP
		    if($entries.Count -le 1) {
			    LogError "VFP Rule missing for Service IP :  $serviceIP in VFP Port : $portName"
                $lbDsrRuleMissing = $true
		    } else {
			    Write-Host "VFP Rule present for Service IP :  $serviceIP in VFP Port : $portName"
		    }
	    }
    }

    if($lbDsrRuleMissing){
        LogError "Mitigation : Restart-Service -f kubeproxy "
        return $true
    }

    LogSuccess "No issues identified with LB DSR Rule Missing for Service IPS : $ServiceIPS."
    return $false
}

function getDuplicateLbDsrVfpRules() {
    param (
        [parameter(Mandatory=$true)][string] $portId,
        [parameter(Mandatory=$true)][string] $groupId
    )

    $vfpRules = ((vfpctrl /port $portId /layer LB_DSR /group $groupId /get-rule-counter /format 1 | ConvertFrom-Json).Rules) | Select-Object ID, Name, Conditions

    $vfpRuleMap = @{}
    
    foreach($rule in $vfpRules) {
        $conditions = $rule.Conditions
        $protocolList = ""
        $ipList = ""
        $portList = ""
        foreach($condition in $conditions) {
            $type = $condition.ConditionType
            if($type -eq 1) {
                # Protocol List
                $protocols = $condition.ProtocolList
                foreach($protocol in $protocols) {
                    $protocolList += "$protocol" + "-"
                }
            }
            if($type -eq 11) {
                # IPV4 Range List
                $ips = $condition.DestinationIPv4RangeList
                foreach($ip in $ips) {
                    if($null -ne $ip) {
                        if($ip.L -eq $ip.H) {
                            $ipList += $ip.L + "-"
                        } else {
                            $ipList += $ip.L + "-" + $ip.H + "-"
                        }
                    }
                }
            }
            if($type -eq 13) {
                # IPV6 Range List
                $ips = $condition.DestinationIPv6RangeList
                foreach($ip in $ips) {
                    if($null -ne $ip) {
                        if($ip.L -eq $ip.H) {
                            $ipList += $ip.L + "-"
                        } else {
                            $ipList += $ip.L + "-" + $ip.H + "-"
                        }
                    }
                }
            }
            if($type -eq 5) {
                # Port Range List
                $ports = $condition.DestinationPortList
                foreach($port in $ports) {
                    $portList += "$port" + "-"
                }
            }
        }

        $key = $ipList + $portList + $protocolList
        if($key.Length -gt 5) {
            $key = $key.Substring(0, $key.Length-1)
        }

        $ruleId = $rule.ID
        if(($null -eq $ruleId) -OR ("" -EQ $ruleId) -or ($ruleId.Length -lt 5)) {
            $ruleId = $rule.Name
        }

        $existingList = $vfpRuleMap[$key]
        if($null -eq $existingList) {
            $existingList = @($ruleId)
        } else {
            $existingList += $ruleId
        }
        
        $vfpRuleMap[$key] = $existingList
    }

    $refinedDuplicateIds = @{}

    foreach($e in $vfpRuleMap.GetEnumerator()) {
        if(($e.Value).Count -gt 1) {
            $refinedDuplicateIds["Condition-" + $e.Key] = $e.Value
        }
    }

    return $refinedDuplicateIds
}

function CheckDuplicate_LB_DSR_VfpRules {

    Write-Host "Checking Duplicate LB DSR VFP Rules"

    $vfpPortIds = readVfpPortIdList
    $duplicateIdAndPorts = @{}

    foreach($portId in $vfpPortIds) {

        $v4DuplicateIds = getDuplicateLbDsrVfpRules -portId $portId -groupId "LB_DSR_IPv4_OUT"
        $v6DuplicateIds = getDuplicateLbDsrVfpRules -portId $portId -groupId "LB_DSR_IPv6_OUT"

        $duplicateIds = $v4DuplicateIds + $v6DuplicateIds

        if($duplicateIds.Count -gt 0) {
            $duplicateIdAndPorts["Port-"+$portId] = $duplicateIds
        }

    }

    if($duplicateIdAndPorts.Count -gt 0){
        LogError "Duplicate LB DSR VFP Rules Present. "
        $jsonOutput = $duplicateIdAndPorts | ConvertTo-Json -Depth 10
        LogError "Info: $jsonOutput "
        LogError "Mitigation : Restart-Service -f hns ; Restart-Service -f kubeproxy "
        return $true
    }

    LogSuccess "No issues identified with Duplicate LB DSR VFP Rules."
    return $false
}

function getDuplicateL2RewriteVfpRules() {
    param (
        [parameter(Mandatory=$true)][string] $portId,
        [parameter(Mandatory=$true)][string] $groupId,
        [parameter(Mandatory=$true)][bool] $isOutbound
    )

    $vfpRules = (vfpctrl /port $portId /layer EXTERNAL_L2_REWRITE_LAYER /group $groupId /get-rule-counter /format 1 | ConvertFrom-Json).Rules

    $duplicateIds = @{}
    $refinedDuplicateIds = @{}

    foreach($vfpRule in $vfpRules) {

        $ruleId = $vfpRule.Id

        if($null -eq $ruleId) {
            # $ruleId = "N/A"
            continue
        }

        $key = ""
        if($true -eq $isOutbound) {
            $conditions = $vfpRule.Conditions
            foreach($condition in $conditions) {

                switch ($condition.ConditionType) {
                    11 {
                        # 11 is the condition type for DestinationIPv4RangeList
                        $dstIpv4RangeList = $condition.DestinationIPv4RangeList
                        foreach($dstIpv4Range in $dstIpv4RangeList) {
                            $key += ("-" + $dstIpv4Range.L + "-" + $dstIpv4Range.H)
                        }
                    }
                    13 {
                        # 13 is the condition type for DestinationIPv6RangeList
                        $dstIpv6RangeList = $condition.DestinationIPv6RangeList
                        foreach($dstIpv6Range in $dstIpv6RangeList) {
                            $key += ("-" + $dstIpv6Range.L + "-" + $dstIpv6Range.H)
                        }
                    }
                    17 {
                        # 17 is the condition type for DestinationMacAddressList
                        $dstMacAddrList = $condition.DestinationMacAddressList
                        foreach($dstMacAddr in $dstMacAddrList) {
                            $key += ("-" + $dstMacAddr)
                        }
                    }
                    21 {
                        # 21 is the condition type for VlanIdRangeList
                        $vlanIdRangeList = $condition.VlanIdRangeList
                        foreach($vlanIdRange in $vlanIdRangeList) {
                            $key += ("-" + $vlanIdRange.L + "-" + $vlanIdRange.H)
                        }
                    }
                }
            }

            if($key.Length -gt 0) {
                $key = $key.Substring(1)
            }

        } else {
            $key = ($vfpRule.Conditions).SourceMacAddressList
        }

        if($key.Length -eq 0) {
            continue
        }

        $existingList = $duplicateIds[$key]
        if($null -eq $existingList) {
            $existingList = @($ruleId)
        } else {
            $existingList += $ruleId
        }
        $duplicateIds[$key] = $existingList
    }

    foreach($e in $duplicateIds.GetEnumerator()) {
        if(($e.Value).Count -gt 1) {
            $refinedDuplicateIds[$e.Key] = $e.Value
        }
    }

    return $refinedDuplicateIds
}

function CheckDuplicate_L2_ReWrite_VfpRules {

    Write-Host "Checking Duplicate L2 ReWrite VFP Rules.."

    $vfpPortIds = readVfpPortIdList
    $duplicateIdAndPorts = @{}

    foreach($portId in $vfpPortIds) {

        $v4OutboundDuplicateIds = getDuplicateL2RewriteVfpRules -portId $portId -groupId "EXTERNAL_L2_REWRITE_GROUP_IPV4_OUT" -isOutbound $true
        $v4InboundDuplicateIds = getDuplicateL2RewriteVfpRules -portId $portId -groupId "EXTERNAL_L2_REWRITE_GROUP_IPV4_IN" -isOutbound $false
        $v6OutboundDuplicateIds = getDuplicateL2RewriteVfpRules -portId $portId -groupId "EXTERNAL_L2_REWRITE_GROUP_IPV6_OUT" -isOutbound $true
        $v6InboundDuplicateIds = getDuplicateL2RewriteVfpRules -portId $portId -groupId "EXTERNAL_L2_REWRITE_GROUP_IPV6_IN" -isOutbound $false

        $duplicateIds = $v4OutboundDuplicateIds + $v4InboundDuplicateIds + $v6OutboundDuplicateIds + $v6InboundDuplicateIds

        if($duplicateIds.Count -gt 0) {
            $duplicateIdAndPorts["PORT_ID_" + $portId] = $duplicateIds
        }

    }

    if($duplicateIdAndPorts.Count -gt 0){
        LogError "Duplicate L2 ReWrite VFP Rules Present. "
        $jsonOutput = $duplicateIdAndPorts | ConvertTo-Json -Depth 10
        LogError "Info: $jsonOutput "
        LogError "Mitigation : Restart-Service -f hns ; Restart-Service -f kubeproxy "
        return $true
    }

    LogSuccess "No issues identified with Duplicate L2 ReWrite VFP Rules."
    return $false
}

function DnsPktCapture {
    $pktmonLogs = "$LogsDir\pktmon"
    $captureTime = 15
    pktmon stop
    Write-Host "Starting DNS Packet Capture"
    Write-Host "Removing all pktmon filters if anything existing..."
    pktmon filter remove
    Write-Host "Create DNS Port filter..."
    pktmon filter add DNSFilter -p 53
    Write-Host "Create a directory for pktmon logs..."
    remove-item -Recurse -Force $pktmonLogs -ErrorAction Ignore
    mkdir $pktmonLogs
    Set-Location $pktmonLogs
    Write-Host "Start pktmon. Command : [pktmon start -c --comp all --pkt-size 0 -m multi-file] ..."
    pktmon start -c --comp all --pkt-size 0 -m multi-file
    Write-Host "Waiting for $captureTime seconds."
    TriggerCurlRequest
    # Start-Sleep -Seconds $captureTime
    pktmon stop
    Write-Host "Logs will be available in $pktmonLogs"
    Write-Host "DNS Packet Capture Completed"
}

function ValidateNetworkIssues {
    $networkIssueFound = $false
    Write-Host "Checking Network Issue."
    if(CheckNetworkingServices) {
        $networkIssueFound = $true
    }
    if(CheckHnsDnsRuleMissing) {
        $networkIssueFound = $true
    }
    if(CheckHnsDeadlock) {
        $networkIssueFound = $true
    }
    if(CheckHnsCrash) {
        $networkIssueFound = $true
    }
    if(CheckPortExhaustion) {
        $networkIssueFound = $true
    }
    if(CheckKubeProxyCrash) {
        $networkIssueFound = $true
    }
    if(CheckKubeletCrash) {
        $networkIssueFound = $true
    }
    if(CheckHnsNetworksMissing) {
        $networkIssueFound = $true
    }
    if(CheckingInvalidHnsPolicy) {
        $networkIssueFound = $true
    }
    if(CheckDuplicate_L2_ReWrite_VfpRules) {
        $networkIssueFound = $true
    }
    if(CheckDuplicate_LB_DSR_VfpRules) {
        $networkIssueFound = $true
    }
    if(CheckVfpDnsRuleMissing) {
        $networkIssueFound = $true
    }
    if(($ServiceIPS -ne "") -and (CheckLbDsrRuleMissing)) {
        $networkIssueFound = $true
    }
    if(CheckDefaultRouteMissing) {
        $networkIssueFound = $true
    }
    if(CheckHardwareHealth) {
        $networkIssueFound = $true
    }
    if(CheckPingNodeToInternet) {
        $networkIssueFound = $true
    }
    if(CheckNodeToInternetConnectivity) {
        $networkIssueFound = $true
    }
    if(CheckPodIpMissing) {
        $networkIssueFound = $true
    }
    if(CheckVfpPacketDrops) {
        $networkIssueFound = $true
    }
    return $networkIssueFound
}

Remove-Item -Force $Logfile -ErrorAction Ignore
Remove-Item -Recurse -Force $LogsZip -ErrorAction Ignore
mkdir $LogsDir -ErrorAction Ignore

$networkIssueFound = ValidateNetworkIssues
if($networkIssueFound) {
    LogError "Network Issue Found."
} else {
    LogSuccess "No Network Issues identified as per current test."
}

if($DnsPktCap) {
    DnsPktCapture
}

Set-Location $cwd
Compress-Archive $LogsDir $LogsZip

Write-Host "Logs available in $LogsZip"
