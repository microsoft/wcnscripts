$LogDirPrefix = "C:\k\debug\NetworkHealth\Log-"
$timeNowInUtc = Get-Date -Format u
$LogDirSuffix = $timeNowInUtc.Replace(" ", "-").Replace(":", "-")
$LogsDir = $LogDirPrefix + $LogDirSuffix
$Logfile = "$LogsDir\health.log"

mkdir $LogsDir -ErrorAction Ignore

function LogError {
    param (
        [parameter(Mandatory=$true)][string] $message
    )
    Write-Host $message -ForegroundColor Red
    Add-content $Logfile -value "[FAILED] $message"
}

function LogSuccess {
    param (
        [parameter(Mandatory=$true)][string] $message
    )
    Write-Host $message -ForegroundColor Green
    Add-content $Logfile -value "[SUCCESS] $message"
}

function readVfpPortIdList() {
    $vfpPortIds = ((vfpctrl /list-vmswitch-port /format 1 | ConvertFrom-Json).Ports).Name
    return $vfpPortIds
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
            $duplicateIdAndPorts["Port-" + $portId] = $duplicateIds
        }

    }

    if($duplicateIdAndPorts.Count -gt 0){
        LogError "Duplicate LB DSR VFP Rules Present. "
        $jsonOutput = $duplicateIdAndPorts | ConvertTo-Json -Depth 10
        LogError "Info: $jsonOutput "
        LogError "Mitigation : Restart-Service -f hns ; Restart-Service -f kubeproxy "
        return $true
    }

    LogSuccess "There is no Duplicate LB DSR VFP Rules."
    return $false
}

CheckDuplicate_LB_DSR_VfpRules