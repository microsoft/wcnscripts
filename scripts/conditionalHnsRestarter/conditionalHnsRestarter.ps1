param (
    [Parameter(Mandatory=$true)]
    [array] $PodPortRulesToCheck,
    # array of @{ruleRegex = ""; layerName = ""; groupName = ""}

    [Parameter(Mandatory=$false)]
    [int] $SleepIntervalMins = 5,
    # time to sleep before checking whether HNS restart is required.

    [Parameter(Mandatory=$false)]
    [int] $RuleCheckIntervalMins = 3,
    # if a rule is missing on an endpoint for more than RuleCheckIntervalMins minutes, we restart HNS

    [Parameter(Mandatory=$false)]
    [int] $MaxHnsRestarts = 50,

    [Parameter(Mandatory=$false)]
    [int] $MinRestartInterval = 5,

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
    [bool] $rulesVerified

    EndpointInfo([string] $inId, [System.DateTime] $inTime)
    {
        $this.id = $inId
        $this.notedTime = $inTime
        $this.rulesVerified = $false
    }
}

$g_scriptStartTime = get-date
$g_endpointInfoMap = @{} # key = id, value = EndpointInfo
$g_podRuleCheckList = [System.Collections.Generic.List[RuleCheckInfo]]::new() # array of RuleCheckInfo objects
$g_hnsRestartCount = 0
$g_lastHnsRestartTime = $g_scriptStartTime
$g_nonPodPortRegex = "Container NIC|Host Vnic|ExternalPort"


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

    $msg = "rule {0} matches regex {1}." -f $rule.Id, $ruleToCheck.ruleRegex
    write-host $msg

            break
        }
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
        return $false
    }

    $msg = "group {0} found in layer {1}." -f $ruleToCheck.groupName, $ruleToCheck.layerName
    write-host $msg

    return RulePresentInVfpPortGroup -portGroup $layer.groups[$groupIndex] -ruleToCheck $ruleToCheck
}

function RulesPresentOnVfpPort(
    [string] $portId,
    [System.Collections.Generic.List[RuleCheckInfo]] $rulesToCheck
)
{
    $layers = (vfpctrl /list-rule /port $portId /format 1 | convertfrom-json).Layers

    foreach ($ruleToCheck in $rulesToCheck) {
        write-host ""

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
            return $false
        }

        $msg = "Layer {0} found on port {1}: {2}." -f $ruleToCheck.layerName, $portId, $layers[$layerIndex]
        write-host $msg

        $rulePresentInLayer = RulePresentInVfpPortLayer -layer $layers[$layerIndex] -ruleToCheck $ruleToCheck
        if ($rulePresentInLayer -eq $false) {
            return $false
        }
    }

    return $true
}

function PortIsPodPort(
    [PSCustomObject] $vfpPortInfo
)
{
    if ($vfpPortInfo.id -match $g_nonPodPortRegex)
    {
        return $false
    }

    return $true
}

function RulesAreMissing() {
    $vfpPortList = ((vfpctrl /list-vmswitch-port /format 1 | convertfrom-json).Ports)
    $current_time = get-date
    $vfpPortMap = @{}

    $msg = "There are {0} ports in VFP." -f $vfpPortList.count
    write-host $msg

    ## Note new endpoint IDs.
    $msg = "$g_endpointInfoMap size before adding new ports {0}" -f $g_endpointInfoMap.count
    write-host $msg
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
    $msg = "$g_endpointInfoMap size after adding new ports {0}" -f $g_endpointInfoMap.count
    write-host $msg
    ##

    ## Delete stale endpoint IDs, so that g_endpointInfoMap's size does not keep increasing forever.
    $stalePortIdList = @()
    $msg = "$g_endpointInfoMap size before deleting stale ports {0}" -f $g_endpointInfoMap.count
    write-host $msg
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
    foreach ($portId in $stalePortIdList) {
        # TODO: log this
        $g_endpointInfoMap.Remove($portId)
    }
    $msg = "$g_endpointInfoMap size after deleting stale ports {0}" -f $g_endpointInfoMap.count
    write-host $msg
    ##


    foreach ($portId in $g_endpointInfoMap.Keys)
    {
        if ($g_endpointInfoMap[$portId].rulesVerified -eq $true)
        {
            continue
        }

        $isPodPort = PortIsPodPort -vfpPortInfo $vfpPortMap[$portId]
        if ($isPodPort -eq $false) {
            # this could be external port or host vNIC
            continue
        }

        #$msg = "checking for rules on port name:{0} id:{1}" -f $vfpPortMap[$portId].name,$vfpPortMap[$portId].id
        #write-host $msg

        $rulesPresent = RulesPresentOnVfpPort -portId $portId -rulesToCheck $g_podRuleCheckList
        
        #$msg = "rules present: {0}" -f $rulesPresent
        #write-host $msg

        if (($current_time - $g_endpointInfoMap[$portId].notedTime).TotalMinutes -gt $RuleCheckIntervalMins)
        {
            # hns must be restarted
            return $true
        }
    }

    return $false
}

function ScriptSetup()
{
    foreach ($rule in $PodPortRulesToCheck) {
        $ruleCheckInfo = [RuleCheckInfo]::New($rule.ruleRegex, $rule.layerName, $rule.groupName)
        $g_podRuleCheckList.Add($ruleCheckInfo)
    }
    $msg = "Size of g_podRuleCheckList: {0}" -f $g_podRuleCheckList.count
    write-host $msg
$msg = "rulesToCheck[0].layerName: {0}" -f $g_podRuleCheckList[0].layerName
write-host $msg

}

function CheckIfRestartRequired()
{
    $rulesMissing = RulesAreMissing
    return $false
}

function collectLogs(
    [string]$LogsPath
)
{
    # create log path if not yet created.
    mkdir -Force $LogsPath
    $originalPath = pwd
    Set-Location $LogsPath
    C:\k\debug\collect-windows-logs.ps1
    Set-Location $originalPath
}

function restartHnsService()
{
    restart-service -f hns
}

function myMain()
{
    ScriptSetup
    while ($true)
    {
        $restartRequired = CheckIfRestartRequired

        if ($restartRequired -eq $false) {
            sleep ($SleepIntervalMins * 60)
            continue
        }

        $current_time = get-date
        $timeSinceLastRestart = $current_time - $g_lastHnsRestartTime
        $scriptAge = $current_time - $g_scriptStartTime

        ####
        # Check conditions to not restart HNS.
        if ($scriptAge.TotalMinutes -lt $SleepIntervalMins)
        {
            # current_time could be just after a reboot, or just after a HNS/kube-proxy restart.
            # Let's not restart yet.
            sleep ($SleepIntervalMins * 60)
            continue
        }
        elseif ($g_hnsRestartCount -ge $MaxHnsRestarts)
        {
            # TODO: log("max HNS restarts already done. Shouldn't restart anymore.")
            sleep ($SleepIntervalMins * 60)
            continue
        }
        elseif ($timeSinceLastRestart.TotalMinutes -lt $MinRestartInterval)
        {
            # TODO: log("HNS restarted recently. Let's wait more.")
            sleep ($timeSinceLastRestart.TotalSeconds)
            continue
        }
        # All negative cases (i.e., conditions to not restart HNS end here.)
        ####

        # TODO: log("")
        collectLogs -LogsPath $WindowsLogsPath
        
        restartHnsService

        $g_lastHnsRestartTime = get-date
        $g_hnsRestartCount += 1

    }
}

myMain
