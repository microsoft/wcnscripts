param (
    [Parameter(Mandatory=$true)]
    [array] $PodPortRulesToCheck,
    # array of @{ruleRegex = ""; layerName = ""; groupName = ""}

    [Parameter(Mandatory=$false)]
    [int] $SleepIntervalMins = 5,
    # time to sleep before checking whether HNS restart is required.

    [Parameter(Mandatory=$false)]
    [int] $MinSleepIntervalMins = 1,
    # time to sleep before checking whether HNS restart is required.

    [Parameter(Mandatory=$false)]
    [int] $RuleCheckIntervalMins = 3,
    # if a rule is missing on an endpoint for more than RuleCheckIntervalMins minutes, we restart HNS

    [Parameter(Mandatory=$false)]
    [int] $MaxMitigationCount = 50,

    [Parameter(Mandatory=$false)]
    [int] $MinMitigationIntervalMins = 5,

    [Parameter(Mandatory=$false)]
    [int] $MitigationActionVal = 0,
    # An enum indicating what mitigation action to take. Example, 0 indicates "restart HNS".

    [Parameter(Mandatory=$false)]
    [bool] $CollectWindowsLogs = $true,

    [Parameter(Mandatory=$false)]
    [string] $WindowsLogsPath = "C:\k\debug\ConditionalHnsRestart_data\"
)

class RuleCheckInfo {
    [string]$ruleRegex
    [string]$layerName
    [string]$groupName
    RuleCheckInfo([string] $in_ruleRegex, [string] $in_layerName, [string] $in_groupName)
    {
        $this.ruleRegex = $in_ruleRegex
        $this.layerName = $in_layerName
        $this.groupName = $in_groupName
    }
}

class EndpointInfo {
    [string]$id
    [System.DateTime]$notedTime
    [int] $ruleCheckCount
    [System.DateTime]$lastRuleCheckTime

    EndpointInfo([string] $inId, [System.DateTime] $inTime)
    {
        $this.id = $inId
        $this.notedTime = $inTime
        $this.ruleCheckCount = 0
    }
}

enum MitigationActionEnum {
    E_RestartHns = 0
    E_RestartKubeProxy
}

$g_scriptStartTime = get-date
$g_endpointInfoMap = @{} # key = id, value = EndpointInfo
$g_podRuleCheckList = [System.Collections.Generic.List[RuleCheckInfo]]::new() # array of RuleCheckInfo objects
$g_mitigationActionCount = 0
$g_lastMitigationTime = $g_scriptStartTime
$g_nonPodPortRegex = "Container NIC|Host Vnic|ExternalPort"
$RuleCheckIntervalSecs = $RuleCheckIntervalMins * 60
$SleepIntervalSecs = $SleepIntervalMins * 60
$MinMitigationIntervalSecs = $MinMitigationIntervalMins * 60

function RulePresentInVfpPortGroup(
    [PSCustomObject] $portGroup,
    [RuleCheckInfo] $ruleToCheck
)
{
    # find rule
    $ruleFound = $false
    $ruleIndex = -1
    foreach ($rule in $portGroup.rules) {
        $ruleIndex += 1
        if ($rule.Id -match $ruleToCheck.ruleRegex) {
            $ruleFound = $true
            #$msg = "rule {0} matches regex {1}." -f $rule.Id, $ruleToCheck.ruleRegex
            #write-host $msg
            break
        }
    }

    if ($ruleFound -eq $false) {
        $msg = "rule with regex {0} not found on group {1}" -f $ruleToCheck.ruleRegex, $portGroup.name
        write-host $msg        
    }
    return $ruleFound
}


function RulePresentInVfpPortLayer(
    [PSCustomObject] $layer,
    [RuleCheckInfo] $ruleToCheck
)
{
    # first find layer
    $groupFound = $false
    $groupIndex = -1
    foreach ($portGroup in $layer.groups) {
        $groupIndex += 1
        if ($portGroup.name -eq $ruleToCheck.groupName) {
            $groupFound = $true
            break
        }
    }
    if ($groupFound -eq $false) {
        $msg = "No group on layer {0} matches name {1}" -f ('"' + $ruleToCheck.layerName + '"'),$ruleToCheck.groupName
        write-host $msg
        return $false
    }

    #$msg = "group {0} found in layer {1}." -f $ruleToCheck.groupName, $ruleToCheck.layerName
    #write-host $msg

    return RulePresentInVfpPortGroup -portGroup $layer.groups[$groupIndex] -ruleToCheck $ruleToCheck
}

function RulesPresentOnVfpPort(
    [string] $portId,
    [System.Collections.Generic.List[RuleCheckInfo]] $rulesToCheck
)
{
    #write-host "RulesPresentOnVfpPort called"
    $layers = (vfpctrl /list-rule /port $portId /format 1 | convertfrom-json).Layers

    foreach ($ruleToCheck in $rulesToCheck) {
        # first find layer
        $layerFound = $false
        $layerIndex = -1

        foreach ($layer in $layers) {
            $layerIndex += 1
            if ($layer.name -eq $ruleToCheck.layerName) {
                $layerFound = $true
                break
            }
        }
        if ($layerFound -eq $false) {
            $msg = "No layer on port {0} matches name {1}" -f $portId, ('"' + $ruleToCheck.layerName + '"')
            write-host $msg
            return $false
        }

        #$msg = "Layer {0} found on port {1}: {2}." -f $ruleToCheck.layerName, $portId, $layers[$layerIndex]
        #write-host $msg

        $rulePresentInLayer = RulePresentInVfpPortLayer -layer $layers[$layerIndex] -ruleToCheck $ruleToCheck
        if ($rulePresentInLayer -eq $false) {
            $msg = "No rule on port {0} matches regex {1}." -f $portId, $ruleToCheck.ruleRegex
            write-host $msg
            return $false
        }
    }

    return $true
}

function PortIsPodPort(
    [PSCustomObject] $vfpPortInfo
)
{
    if ($vfpPortInfo.id -match $g_nonPodPortRegex) {
        return $false
    }

    return $true
}

function RulesAreMissing() {
    $vfpPortList = ((vfpctrl /list-vmswitch-port /format 1 | convertfrom-json).Ports)
    $vfpPortMap = @{}

    #$msg = "There are {0} ports in VFP." -f $vfpPortList.count
    #write-host $msg

    ## Note new endpoint IDs.
    $priorSize = $g_endpointInfoMap.count
    foreach ($vfpPort in $vfpPortList)
    {
        $vfpPortMap.Add($vfpPort.Id, $vfpPort)

        if ($g_endpointInfoMap.ContainsKey($vfpPort.Id) -eq $false)
        {
            $notedTime = get-date
            $endpointInfo = [EndpointInfo]::New($vfpPort.Id, $notedTime)
            $g_endpointInfoMap.Add($vfpPort.Id, $endpointInfo)
        }
    }
    $endpointsAdded = $g_endpointInfoMap.count - $priorSize
    $msg = "new endpoints added to g_endpointInfoMap: {0}" -f $endpointsAdded
    write-host $msg
    ##


    ## Delete stale endpoint IDs, so that g_endpointInfoMap's size does not keep increasing forever.
    $stalePortIdList = @()
    foreach ($portId in $g_endpointInfoMap.Keys) {
        $portIdPresent = $false
        foreach ($vfpPort in $vfpPortList) {
            if ($vfpPort.Id -eq $portId) {
                $portIdPresent = $true
                break
            }
        }

        if ($portIdPresent -eq $false) {
            $stalePortIdList += @($portId)
        }
    }
    $priorSize = $g_endpointInfoMap.count
    foreach ($portId in $stalePortIdList) {
        $msg = "deleting stale endpoint ID {0}" -f $portId
        write-host $msg
        $g_endpointInfoMap.Remove($portId)
    }
    
    $endpointsDeleted = $g_endpointInfoMap.count - $priorSize
    $msg = "old endpoints deleted from g_endpointInfoMap: {0}" -f $endpointsDeleted
    write-host $msg
    ##


    ## Check pod port rules.
    foreach ($portId in $g_endpointInfoMap.Keys)
    {
        $isPodPort = PortIsPodPort -vfpPortInfo $vfpPortMap[$portId]
        if ($isPodPort -eq $false) {
            # this could be external port or host vNIC. Ignore.
            continue
        }

        $current_time = get-date
        $timeSinceLastCheck = $current_time - $g_endpointInfoMap[$portId].lastRuleCheckTime
        if ($g_endpointInfoMap.ruleCheckCount -gt 0) {
            if ($timeSinceLastCheck.TotalSeconds -lt $RuleCheckIntervalSecs) {
                # check again later
                continue
            }
        }

        #$msg = "Checking for rules on port name:{0} id:{1}" -f $vfpPortMap[$portId].name,$vfpPortMap[$portId].id
        #write-host $msg

        $rulesPresent = RulesPresentOnVfpPort -portId $portId -rulesToCheck $g_podRuleCheckList
        if ($rulesPresent -eq $true) {
            # This port has the necessary rules.
            $g_endpointInfoMap[$portId].ruleCheckCount += 1
            $g_endpointInfoMap[$portId].lastRuleCheckTime = $current_time
            continue
        }

        # We reach here when a port does not have the necessary rules for more than RuleCheckIntervalMins.
        # Mitigation action must be taken.
        $msg = "Rules missing on VFP port with ID {0} since last {1} minutes" -f $portId,$timeSinceLastCheck.TotalMinutes
        write-host $msg
        return $true
    }
    ## Pod port rule check done.

    return $false
}

function ScriptSetup()
{
    foreach ($rule in $PodPortRulesToCheck) {
        $ruleCheckInfo = [RuleCheckInfo]::New($rule.ruleRegex, $rule.layerName, $rule.groupName)
        $g_podRuleCheckList.Add($ruleCheckInfo)
    }
    $msg = "Number of pod port rules to check: {0}" -f $g_podRuleCheckList.count
    write-host $msg
}

function CheckIfMitigationRequired()
{
    $rulesMissing = RulesAreMissing
    return $rulesMissing
}

function collectLogsBeforeMitigation(
    [string]$LogsPath
)
{
    # create log path if not yet created.
    mkdir -Force $LogsPath

    if ($CollectWindowsLogs -eq $true) {
        write-host "collecting windows logs"
        $originalPath = pwd
        Set-Location $LogsPath
        C:\k\debug\collect-windows-logs.ps1
        Set-Location $originalPath
    }
}

function ExecuteMitigationAction()
{
    if ($MitigationActionEnum -eq [MitigationActionEnum]::E_RestartHns) {
        write-host "restarting HNS"
        restart-service -f hns
    }
}


function myMain()
{
    ScriptSetup
    while ($true)
    {
        write-host ""
        $mitigationRequired = CheckIfMitigationRequired

        if ($mitigationRequired -eq $false) {
            sleep ($SleepIntervalSecs)
            continue
        }

        $current_time = get-date
        $timeSinceLastMitigation = $current_time - $g_lastMitigationTime
        $scriptAge = $current_time - $g_scriptStartTime

        ####
        # Conditions for not mitigating.
        if ($scriptAge.TotalMinutes -lt $SleepIntervalMins)
        {
            # current_time could be just after a reboot, or just after a HNS/kube-proxy restart.
            # We don't hurry yet. We check again after $SleepIntervalSecs.
            $msg = "Not taking mitigation-action since current time could be just after reboot/HNS/kube-proxy restart."
            write-host $msg
            sleep ($SleepIntervalSecs)
            continue
        }
        elseif ($g_mitigationActionCount -ge $MaxMitigationCount)
        {
            $msg = "Not taking mitigation-action since MaxMitigationCount has been crossed. Shouldn't take action anymore."
            write-host $msg
            sleep ($SleepIntervalSecs)
            continue
        }
        elseif ($timeSinceLastMitigation.TotalSeconds -lt $MinMitigationIntervalSecs)
        {
            $timeToSleepSecs = $MinMitigationIntervalSecs - $timeSinceLastMitigation.TotalSeconds
            $timeToSleepMins = $timeToSleepSecs / 60
            $msg = "Not taking mitigation-action since it was taken just {0} minutes ago. Checking again after {1} minutes" -f $timeSinceLastMitigation.TotalMinutes, $timeToSleepMins
            write-host $msg
            sleep ($timeToSleepSecs)
            continue
        }
        # All negative cases (i.e., conditions to not mitigate end here.)
        ####

        $msg = "Collecting logs before mitigation"
        write-host $msg
        collectLogsBeforeMitigation -LogsPath $WindowsLogsPath        

        $msg = "Taking mitigation action..."
        write-host $msg
        ExecuteMitigationAction

        $g_lastMitigationTime = get-date
        $g_mitigationActionCount += 1
    }
}

myMain
