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
    [bool] $PauseAtBeginning = $true,

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

    EndpointInfo([string] $inId)
    {
        $this.id = $inId
        $this.notedTime = get-date
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
    $msg = (hostname) + " " + $timestamp + " | " + $msgStr
    write-host $msg
}


function IsRulePresentInVfpPortGroup(
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
        LogWithTimeStamp -msgStr ("rule with regex {0} not found on group {1}" -f $ruleToCheck.ruleRegex, $portGroup.name)        
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
        LogWithTimeStamp -msgStr ("No group on layer {0} matches name {1}" -f ('"' + $ruleToCheck.layerName + '"'),$ruleToCheck.groupName)
        return $false
    }

    return IsRulePresentInVfpPortGroup -portGroup $layer.groups[$groupIndex] -ruleToCheck $ruleToCheck
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
            LogWithTimeStamp -msgStr ("No layer on port {0} matches name {1}" -f $portId, ('"' + $ruleToCheck.layerName + '"'))
            return $false
        }

        $rulePresentInLayer = IsRulePresentInVfpPortLayer -layer $layers[$layerIndex] -ruleToCheck $ruleToCheck
        if ($rulePresentInLayer -eq $false) {
            LogWithTimeStamp -msgStr ("No rule on port {0} matches regex {1}." -f $portId, $ruleToCheck.ruleRegex)
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

    LogWithTimeStamp -msgStr "Checking if new endpoints have been added"
    $priorSize = $g_endpointInfoMap.count
    foreach ($vfpPort in $vfpPortList)
    {
        $g_currentVfpPortMap.Add($vfpPort.Id, $vfpPort)

        if ($g_endpointInfoMap.ContainsKey($vfpPort.Id) -eq $false)
        {
            $endpointInfo = [EndpointInfo]::New($vfpPort.Id)
            $g_endpointInfoMap.Add($vfpPort.Id, $endpointInfo)
        }
    }

    $endpointsAdded = $g_endpointInfoMap.count - $priorSize
    LogWithTimeStamp -msgStr ("new endpoints added to g_endpointInfoMap: {0}" -f $endpointsAdded)

    LogWithTimeStamp -msgStr ("size of g_currentVfpPortMap: {0}" -f $g_currentVfpPortMap.count)

    ## Delete stale endpoint IDs, so that g_endpointInfoMap's size does not keep increasing forever.
    LogWithTimeStamp -msgStr "Checking if any endpoints have been deleted"
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
        $g_endpointInfoMap.Remove($portId)
    }

    $endpointsDeleted = $priorSize - $g_endpointInfoMap.count
    LogWithTimeStamp -msgStr ("old endpoints deleted from g_endpointInfoMap: {0}" -f $endpointsDeleted)
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
        $timeSinceLastCheck = $current_time - $g_endpointInfoMap[$portId].lastRuleCheckTime

        if ($g_endpointInfoMap.ruleCheckCount -gt 0) {
            if ($timeSinceLastCheck.TotalSeconds -lt $RuleCheckIntervalSecs) {
                # check again later
                continue
            }
        }

        $rulesPresent = CheckForRulesOnVfpPort -portId $portId -rulesToCheck $g_podRuleCheckList
        $g_endpointInfoMap[$portId].ruleCheckCount += 1

        if ($rulesPresent -eq $false) {
            # We reach here when a port does not have the necessary rules for more than RuleCheckIntervalMins.
            # Mitigation action must be taken.
            LogWithTimeStamp -msgStr ("Rules missing on VFP port with ID {0} since atleast last {1:N2} minutes" -f $portId,$timeSinceLastCheck.TotalMinutes)
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
    LogWithTimeStamp -msgStr ("Number of pod port rules to check: {0}" -f $g_podRuleCheckList.count)
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


function RestartWinService(
    [string]$serviceName
) {
    $oldPid = (Get-WmiObject -Class Win32_Service -Filter "Name LIKE '$serviceName'" | Select-Object -ExpandProperty ProcessId).ToString()
    LogWithTimeStamp -msgStr ("Current {0} pid: {1}. Restarting {0}" -f $serviceName,$oldPid)

    restart-service -f $serviceName

    $newPid = (Get-WmiObject -Class Win32_Service -Filter "Name LIKE '$serviceName'" | Select-Object -ExpandProperty ProcessId).ToString()
    LogWithTimeStamp -msgStr ("{0} pid after restart: {1}" -f $serviceName,$newPid)
}


function ExecuteMitigationAction()
{
    if ($MitigationActionVal -eq [MitigationActionEnum]::E_RestartHns) {
        RestartWinService -serviceName "Hns"
    } elseif ($MitigationActionVal -eq [MitigationActionEnum]::E_RestartKubeProxy) {
        RestartWinService -serviceName "kubeproxy"
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
        LogWithTimeStamp -msgStr ("Script started. Current time could be just after reboot/HNS/kube-proxy restart. Sleeping for few mins before starting mitigation-checks.")
        sleep($SleepIntervalSecs)
    }

    while ($true)
    {
        write-host ""
        $mitigationRequired = CheckIfMitigationRequired

        if ($mitigationRequired -eq $false) {
            sleep($SleepIntervalSecs)
            continue
        }

        $current_time = get-date
        $timeSinceLastMitigation = $current_time - $g_lastMitigationTime
        $scriptAge = $current_time - $g_scriptStartTime

        ####
        # Conditions for not mitigating.
        if ($g_mitigationActionCount -ge $MaxMitigationCount)
        {
            LogWithTimeStamp -msgStr ("Not taking mitigation-action since MaxMitigationCount has been crossed. Going to infinite sleep.")
            SleepInfinitely
        }
        elseif (($g_mitigationActionCount -gt 0) -And ($timeSinceLastMitigation.TotalSeconds -lt $MinMitigationIntervalSecs))
        {
            $timeToSleepSecs = $MinMitigationIntervalSecs - $timeSinceLastMitigation.TotalSeconds
            $timeToSleepMins = $timeToSleepSecs / 60
            if ($MinSleepIntervalMins > $timeToSleepMins) {
                $timeToSleepSecs = $MinSleepIntervalMins * 60
                $timeToSleepMins = $timeToSleepSecs / 60
            }
            LogWithTimeStamp -msgStr ("Not taking mitigation-action since it was taken just {0:N2} minutes ago. Checking again after {1:N2} minutes" -f $timeSinceLastMitigation.TotalMinutes, $timeToSleepMins)
            sleep($timeToSleepSecs)
            continue
        }
        # All negative cases (i.e., conditions to not mitigate end here.)
        ####

        collectLogsBeforeMitigation -LogsPath $WindowsLogsPath        

        LogWithTimeStamp -msgStr ("Taking mitigation action...")
        ExecuteMitigationAction

        $g_lastMitigationTime = get-date
        $g_mitigationActionCount += 1
        LogWithTimeStamp -msgStr ("Mitigation done {0} times." -f $g_mitigationActionCount)
        sleep($MinMitigationIntervalSecs)
    }
}

myMain
