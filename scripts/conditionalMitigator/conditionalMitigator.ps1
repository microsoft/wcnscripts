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
    [int] $RuleCheckIntervalMins = 15,
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
        $this.lastRuleCheckTime = get-date  # Initializing with current time because otherwise it would have a garbage value.
    }
}

enum MitigationActionEnum {
    E_RestartHns = 0
    E_RestartKubeProxy
}

$g_scriptStartTime = get-date
$g_endpointInfoMap = @{} # key = id, value = EndpointInfo
$g_currentVfpPortMap = @{}
$g_podRuleCheckList = [System.Collections.Generic.List[RuleCheckInfo]]::new() # array of RuleCheckInfo objects
$g_mitigationActionCount = 0
$g_lastMitigationTime = $g_scriptStartTime
$g_nonPodPortRegex = "Container NIC|Host Vnic|ExternalPort"
$RuleCheckIntervalSecs = $RuleCheckIntervalMins * 60
$SleepIntervalSecs = $SleepIntervalMins * 60
$MinMitigationIntervalSecs = $MinMitigationIntervalMins * 60

function LogWithTimeStamp(
    [string] $msgStr
)
{
    $currentTime = (get-date).ToUniversalTime()
    $timestamp = $currentTime.ToShortDateString() + " " + $currentTime.ToLongTimeString()
    $msg = $timestamp + " | " + $msgStr
    write-host $msg
}


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
            break
        }
    }

    if ($ruleFound -eq $false) {
        $msg = "rule with regex {0} not found on group {1}" -f $ruleToCheck.ruleRegex, $portGroup.name
        LogWithTimeStamp -msgStr $msg        
    }
    return $ruleFound
}


function IsRulePresentInVfpPortLayer(
    [PSCustomObject] $layer,
    [RuleCheckInfo] $ruleToCheck
)
{
    # find group
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
        LogWithTimeStamp -msgStr $msg
        return $false
    }

    return RulePresentInVfpPortGroup -portGroup $layer.groups[$groupIndex] -ruleToCheck $ruleToCheck
}


function CheckForRulesOnVfpPort(
    [string] $portId,
    [System.Collections.Generic.List[RuleCheckInfo]] $rulesToCheck
)
{
    #write-host "CheckForRulesOnVfpPort called"
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
            LogWithTimeStamp -msgStr $msg
            return $false
        }

        $rulePresentInLayer = IsRulePresentInVfpPortLayer -layer $layers[$layerIndex] -ruleToCheck $ruleToCheck
        if ($rulePresentInLayer -eq $false) {
            $msg = "No rule on port {0} matches regex {1}." -f $portId, $ruleToCheck.ruleRegex
            LogWithTimeStamp -msgStr $msg
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


function NoteCurrentVfpPorts()
{
    $vfpPortList = ((vfpctrl /list-vmswitch-port /format 1 | convertfrom-json).Ports)
    # reset g_currentVfpPortMap to empty map
    $g_currentVfpPortMap.Clear()

    LogWithTimeStamp -msgStr "Adding new endpoints to g_endpointInfoMap"
    $priorSize = $g_endpointInfoMap.count
    foreach ($vfpPort in $vfpPortList)
    {
        $g_currentVfpPortMap.Add($vfpPort.Id, $vfpPort)

        if ($g_endpointInfoMap.ContainsKey($vfpPort.Id) -eq $false)
        {
            $notedTime = get-date
            $endpointInfo = [EndpointInfo]::New($vfpPort.Id, $notedTime)
            $g_endpointInfoMap.Add($vfpPort.Id, $endpointInfo)
        }
    }

    $endpointsAdded = $g_endpointInfoMap.count - $priorSize
    LogWithTimeStamp -msgStr ("new endpoints added to g_endpointInfoMap: {0}" -f $endpointsAdded)

    LogWithTimeStamp -msgStr ("size of g_currentVfpPortMap: {0}" -f $g_currentVfpPortMap.count)

    ## Delete stale endpoint IDs, so that g_endpointInfoMap's size does not keep increasing forever.
    LogWithTimeStamp -msgStr "Removing deleted endpoints from $g_endpointInfoMap"
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
        LogWithTimeStamp -msgStr $msg
        $g_endpointInfoMap.Remove($portId)
    }

    $endpointsDeleted = $g_endpointInfoMap.count - $priorSize
    $msg = "old endpoints deleted from g_endpointInfoMap: {0}" -f $endpointsDeleted
    LogWithTimeStamp -msgStr $msg
    ##
}

function RulesAreMissing() {
    ## Check pod port rules.
    foreach ($portId in $g_endpointInfoMap.Keys)
    {
        $isPodPort = PortIsPodPort -vfpPortInfo $g_currentVfpPortMap[$portId]
        if ($isPodPort -eq $false) {
            # this could be external port or host vNIC. Ignore.
            continue
        }

        $current_time = get-date
        if ($g_endpointInfoMap.ruleCheckCount -gt 0) {
            $timeSinceLastCheck = $current_time - $g_endpointInfoMap[$portId].lastRuleCheckTime
            if ($timeSinceLastCheck.TotalSeconds -lt $RuleCheckIntervalSecs) {
                # check again later
                continue
            }
        } else {
            $timeSinceLastCheck = $current_time - $g_scriptStartTime
        }

        $rulesPresent = CheckForRulesOnVfpPort -portId $portId -rulesToCheck $g_podRuleCheckList
        $g_endpointInfoMap[$portId].ruleCheckCount += 1

        if ($rulesPresent -eq $false) {
            # We reach here when a port does not have the necessary rules for more than RuleCheckIntervalMins.
            # Mitigation action must be taken.
            $msg = "Rules missing on VFP port with ID {0} since atleast last {1} minutes" -f $portId,$timeSinceLastCheck.TotalMinutes
            LogWithTimeStamp -msgStr $msg
            return $true
        }

        $g_endpointInfoMap[$portId].lastRuleCheckTime = $current_time
        # This port has the necessary rules.
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
    LogWithTimeStamp -msgStr $msg
}


function CheckIfMitigationRequired()
{
    NoteCurrentVfpPorts

    $rulesMissing = RulesAreMissing
    return $rulesMissing
}


function collectLogsBeforeMitigation(
    [string]$LogsPath
)
{
    if ($CollectWindowsLogs -eq $true) {
        # create log path if not yet created.
        mkdir -Force $LogsPath

        LogWithTimeStamp -msgStr "collecting windows logs"
        $originalPath = pwd
        Set-Location $LogsPath
        C:\k\debug\collect-windows-logs.ps1
        Set-Location $originalPath

        $currentPath = (pwd).Path
        LogWithTimeStamp -msgStr ("current location: {0}" -f $currentPath)
    }
}


function ExecuteMitigationAction()
{
    LogWithTimeStamp -msgStr ("MitigationActionVal is {0}" -f $MitigationActionVal)

    if ($MitigationActionVal -eq [MitigationActionEnum]::E_RestartHns) {
        LogWithTimeStamp -msgStr "restarting HNS"
        restart-service -f hns
    } elseif ($MitigationActionVal -eq [MitigationActionEnum]::E_RestartKubeProxy) {
        LogWithTimeStamp -msgStr "restarting kubeproxy"
        restart-service -f kubeproxy
    }
}

function SleepInfinitely() {
    while(1) {
        sleep($SleepIntervalSecs)
    }
}

function myMain()
{
    ScriptSetup

    if ($PauseAtBeginning -eq $true) {
        $msg = "Script started. Current time could be just after reboot/HNS/kube-proxy restart. Sleeping for few mins before starting mitigation-checks."
        LogWithTimeStamp -msgStr $msg
        sleep ($SleepIntervalSecs)
    }

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
        if ($g_mitigationActionCount -ge $MaxMitigationCount)
        {
            $msg = "Not taking mitigation-action since MaxMitigationCount has been crossed. Going to infinite sleep."
            LogWithTimeStamp -msgStr $msg
            SleepInfinitely
        }
        elseif ($timeSinceLastMitigation.TotalSeconds -lt $MinMitigationIntervalSecs)
        {
            $timeToSleepSecs = $MinMitigationIntervalSecs - $timeSinceLastMitigation.TotalSeconds
            $timeToSleepMins = $timeToSleepSecs / 60
            if ($MinSleepIntervalMins > $timeToSleepMins) {
                $timeToSleepSecs = $MinSleepIntervalMins * 60
                $timeToSleepMins = $timeToSleepSecs / 60
            }
            $msg = "Not taking mitigation-action since it was taken just {0} minutes ago. Checking again after {1} minutes" -f $timeSinceLastMitigation.TotalMinutes, $timeToSleepMins
            LogWithTimeStamp -msgStr $msg
            sleep ($timeToSleepSecs)
            continue
        }
        # All negative cases (i.e., conditions to not mitigate end here.)
        ####

        $msg = "Collecting logs before mitigation"
        LogWithTimeStamp -msgStr $msg
        collectLogsBeforeMitigation -LogsPath $WindowsLogsPath        

        $msg = "Taking mitigation action..."
        LogWithTimeStamp -msgStr $msg
        ExecuteMitigationAction

        $g_lastMitigationTime = get-date
        $g_mitigationActionCount += 1
    }
}

myMain
