
param (
    [Parameter(Mandatory=$false, HelpMessage="Rule for Pod")][string]$podIp = "10.224.0.53",
    [Parameter(Mandatory=$false, HelpMessage="Rule for Pod")][string]$ipFamily = "IPV4",
    [Parameter(Mandatory=$false, HelpMessage="Rule for Pod")][string]$protoFamily = "TCP",
    [Parameter(Mandatory=$false, HelpMessage="Rule for Pod")][bool]$PrintMatchedRules = $true
)


$podMac = (Get-HnsEndpoint | Where-Object IPAddress -Eq $podIp).MacAddress
$podMacShortened = $podMac.Replace("-", "")
$PodPortId = ((vfpctrl /list-vmswitch-port /format 1 | ConvertFrom-Json).Ports | Where-Object MacAddress -EQ $podMacShortened).Name
$ExtPortId = ((vfpctrl /list-vmswitch-port /format 1 | ConvertFrom-Json).Ports | Where-Object Id -EQ "ExternalPort").Name
$HostPortId = ((vfpctrl /list-vmswitch-port /format 1 | ConvertFrom-Json).Ports | Where-Object Id -Like "Container NIC*").Name

$podLayers = ((vfpctrl /port $PodPortId /list-layer /format 1 | ConvertFrom-Json).Layers | Sort-Object -Property Priority).Name
$extPortLayers = ((vfpctrl /port $ExtPortId /list-layer /format 1 | ConvertFrom-Json).Layers | Sort-Object -Property Priority).Name
$hostPortLayers = ((vfpctrl /port $HostPortId /list-layer /format 1 | ConvertFrom-Json).Layers | Sort-Object -Property Priority).Name

function RemoveNoise() {
    param (
        [Parameter(Mandatory=$true)][System.Object]$Rule
    )
    $Rule.PSObject.Properties.Remove('$type')
    $Rule.PSObject.Properties.Remove('Type')
    $Rule.PSObject.Properties.Remove('SubType')
    $Rule.PSObject.Properties.Remove('MssDelta')
    $Rule.PSObject.Properties.Remove('ReverseMssDelta')
    $Rule.PSObject.Properties.Remove('RuleFlags')
    $Rule.PSObject.Properties.Remove('PaRouteRuleFlags')
    $Rule.PSObject.Properties.Remove('CachePruningThreshold')
    $Rule.PSObject.Properties.Remove('InformationArray')
    $Rule.PSObject.Properties.Remove('NumHeaders')
    $Rule.PSObject.Properties.Remove('PartialRewriteTypes')
    return $Rule
}

function LogVfpCounter {
    param (
        [parameter(Mandatory=$false)][string] $value = "",
        [parameter(Mandatory=$false)][bool] $error = $false
    )
    # Add-Content -Path $VfpRuleFile -Value $value
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
        LogVfpCounter ""
    }
}

function PrintRules {
    param (
        [Parameter(Mandatory=$true)][string[]]$Layers,
        [Parameter(Mandatory=$true)][string]$PortId,
        [Parameter(Mandatory=$false)][string]$Dir="OUT"
    )

    $ruleCounterMap = @{}

    foreach($layer in $Layers) {
        $groups = ((vfpctrl /port $PortId /layer $layer /list-group /format 1 | ConvertFrom-Json).Groups | Sort-Object -Property Priority).Name
        foreach($group in $groups) {
            if($group.Contains("_$DIR") -ne $true) {
                continue
            }
            if(($group.Contains("IPV4") -eq $true) -or ($group.Contains("IPV6") -eq $true)) {
                if($group.Contains($ipFamily) -ne $true) {
                    continue
                }
            }
            if(($group.Contains("TCP") -eq $true) -or ($group.Contains("UDP") -eq $true) -or ($group.Contains("ICMP") -eq $true)) {
                if($group.Contains($protoFamily) -ne $true) {
                    continue
                }
            }
            $rules = (vfpctrl /port $PortId /layer $layer /group $group /get-rule-counter /format 1 | ConvertFrom-Json | Sort-Object -Property Priority).Rules
            foreach ($rule in $rules) {

                $ruleId = $rule.Name
                if (($rule.Id).Length -gt 0) {
                    $ruleId = $rule.Id
                }

                $ruleKey = "$portId-$layer-$group-$ruleId"

                $informationArray = $rule.InformationArray

                $rule = RemoveNoise -Rule $rule

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
                        LogVfpCounter "  Dropped Rule : " -error $true
                        LogVfpCounter "  ================ " -error $true
                        NewLine 1
                        LogVfpCounter "  Layer : $layer , Group : $group , Id : $ruleId " -error $true
                        NewLine 1
                        LogVfpCounter "  $ruleJson " -error $true                                    
                        NewLine 2
                    }
                    elseif (($PrintMatchedRules -eq $true) -and ($matchedPackets -gt 0)) {   
                        LogVfpCounter "  Matched Rule : "
                        LogVfpCounter "  ================ "
                        NewLine 1
                        LogVfpCounter "  Layer : $layer , Group : $group , Id : $ruleId "
                        NewLine 1
                        LogVfpCounter "  $ruleJson "

                        NewLine 2
                    }

                    $ruleCounterMap[$ruleKey] = $rule
                }
            }
        }
    }

    return $ruleCounterMap
}

Write-Host "#===================== Pod VFP Port Rules in Outbound Direction ================#"
NewLine 2
$podPortRulesOutbound = PrintRules -Layers $podLayers -portId $PodPortId -Dir "OUT"
NewLine 2
Write-Host "#===================== External VFP Port Rules in Outbound Direction ================#"
NewLine 2
$extPortRulesOutbound = PrintRules -Layers $extPortLayers -portId $ExtPortId -Dir "OUT"
NewLine 2
Write-Host "#===================== External VFP Port Rules in Inbound Direction ================#"
NewLine 2
$extPortRulesIntbound = PrintRules -Layers $extPortLayers -portId $ExtPortId -Dir "IN"
NewLine 2
Write-Host "#===================== Pod VFP Port Rules in Inbound Direction ================#"
NewLine 2
$podPortRulesIutbound = PrintRules -Layers $podLayers -portId $PodPortId -Dir "IN"
