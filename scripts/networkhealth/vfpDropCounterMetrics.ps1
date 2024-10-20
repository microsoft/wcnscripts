param(
    [string[]] $PodNamePrefixes = @("tcp-client", "tcp-server"),
    [int] $TimeIntervalInSeconds = 300,
    [bool] $PrintMatchedRules = $false
)
   
# Dropped and Pending Rules/Flows will be dumped by default
$logDir = "C:\k\debug\VfpDropRules"
mkdir $logDir -ErrorAction Ignore
$timeNowInUtc = Get-Date -Format u
$fileName = $timeNowInUtc.Replace(" ", "-").Replace(":", "-")
$filePath = "$logDir\rules-$fileName.log"

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

function Log {
    param (
        [parameter(Mandatory=$false)][string] $value = "",
        [parameter(Mandatory=$false)][bool] $error = $false
    )
    Add-Content -Path $filePath -Value $value
    if ($error -eq $true) {
        Write-Host $value -ForegroundColor Red
    }
    else {
        Write-Host $value
    }
}

function NewLine {
    param (
        [parameter(Mandatory=$false)][int] $NoOfLines = 1
    )
    for ($i = 1; $i -le $NoOfLines; $i++) {
        Log -value ""
    }
}

function GetPortCounter {
    param (
        [parameter(Mandatory=$true)][string] $portId
    )
    Log -value "  #== Port Counters ==#"
    NewLine 1
    $portCounterObj = vfpctrl.exe /port $portId /get-port-counter /format 1 | ConvertFrom-Json
    $portCounters = $portCounterObj.InformationArray.PortCounters
    foreach ($portCounter in $portCounters) {
        foreach ($metric in $InterestedPortMetrics) {
            $value = $portCounter.$metric
            $direction = $DIRECTIONS[$portCounter.Direction]
            $metric = ($metric).ToUpper().Replace(" ", "-")
            if (($metric -contains "DROPPED") -and ($value -gt 0)) {
                Log -value "  $direction-$metric : $value" -error $true
            }
            else {
                Log -value "  $direction-$metric : $value"
            }
        }
    }
}

function GetRuleCounter {
    param (
        [parameter(Mandatory=$true)][string] $portId
    )
    NewLine 1
    Log -value "  #== Rule Counters ==#"
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
                        Log -value "  Dropped Rule : " -error $true
                        Log -value "  ================ " -error $true
                        NewLine 1
                        Log -value "  Layer : $layerName , Group : $groupName , Id : $ruleId " -error $true
                        NewLine 1
                        Log -value "  $ruleJson " -error $true
                                    
                        if ($null -ne $oldRule) {

                            $oldDroppedPackets = $oldRule.RuleCounters.DroppedPackets
                            $oldPendingPackets = $oldRule.RuleCounters.PendingPackets
                            $oldDroppedFlows = $oldRule.RuleCounters.DroppedFlows

                            $diffDroppedPackets = $droppedPackets - $oldDroppedPackets
                            $diffPendingPackets = $pendingPackets - $oldPendingPackets
                            $diffDroppedFlows = $droppedFlows - $oldDroppedFlows

                            if (($diffDroppedPackets -gt 0) -or ($diffPendingPackets -gt 0) -or ($diffDroppedFlows -gt 0)) {
                                Log -value "  Rule key : $ruleKey " -error $true
                                Log -value "  Change in Dropped Packets : $diffDroppedPackets [$oldDroppedPackets - $droppedPackets] " -error $true
                                Log -value "  Change in Pending Packets : $diffPendingPackets [$oldPendingPackets - $pendingPackets] " -error $true
                                Log -value "  Change in Dropped Flows : $diffDroppedFlows [$oldDroppedFlows - $droppedFlows] " -error $true
                            }

                        }

                        NewLine 2

                    }
                    elseif (($PrintMatchedRules -eq $true) -and ($matchedPackets -gt 0)) {
                                    
                        Log -value "  Matched Rule : "
                        Log -value "  ================ "
                        NewLine 1
                        Log -value "  Layer : $layerName , Group : $groupName , Id : $ruleId "
                        NewLine 1
                        Log -value "  $ruleJson "

                        if ($null -ne $oldRule) {

                            $oldMatchedPackets = $oldRule.RuleCounters.MatchedPackets
                            $diffMatchedPackets = $matchedPackets - $oldMatchedPackets

                            if ($diffMatchedPackets -gt 0) {
                                Log -value "  Rule key : $ruleKey "
                                Log -value "  Change in Matched Packets : $diffMatchedPackets [$oldMatchedPackets - $matchedPackets] "
                            }

                        }

                        NewLine 2
                    }

                    $ruleCounterMap[$ruleKey] = $rule
                }
            }
        }
    }
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

    $timeNowInUtc = Get-Date -Format u
    NewLine 2
    Log -value "#============ Iteration : $iteration , UTC Time : $timeNowInUtc ============#"

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
            Log -value "#==== Port : $portName , Mac : $mac , VFP Port ID : $portId , Port No : $portNo , Port Name = $friendlyPortName ,  ====#"
            NewLine 1
            GetPortCounter -portId $portId
            GetRuleCounter -portId $portId
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
                Log -value "#==== Pod Name : $podName , IP : $ip , Mac : $mac , Endpoint ID : $epId , VFP Port ID : $portId , Port No : $portNo , Port Name = $friendlyPortName ,  ====#"
                NewLine 1
                GetPortCounter -portId $portId
                GetRuleCounter -portId $portId
                NewLine 2
            }
        }
    }
}

$counter = 1
Log -value "#=========  VFP Network Metrics Started  =========#"

while ($true) {
    if (($counter % 30) -Eq 0) {
        # Resetting the map after every 30 iterations
        $ruleCounterMap = @{}
    }
    VfpNetworkMetrics -iteration $counter
    $counter++
    Start-Sleep $TimeIntervalInSeconds
}