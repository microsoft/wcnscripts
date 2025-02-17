param (
    [Parameter(Mandatory=$true)][string]$ServiceIPS = "",
    [Parameter(Mandatory=$false)][string]$RunFromOutside = $false,
    [Parameter(Mandatory=$false)][string]$CopyScriptToNode = $false,
    [Parameter(Mandatory=$false)][string]$HpcPodPrefix = "hpc",
    [Parameter(Mandatory=$false)][string]$HpcNamepsace = "demo",
    [Parameter(Mandatory=$false)][string]$Layer = "LB_DSR",
    [Parameter(Mandatory=$false)][string]$Group = "LB_DSR_IPv4_OUT"
)

# Eg: .\checkLbDsrMissing.ps1 -ServiceIPS "20.51.25.211,10.0.10.189,10.0.92.4"

$Logfile = "health.log"

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

function CheckLbDsrRuleMissing {

    Write-Host "Checking $Layer Rule missing"
    $lbDsrRuleMissing = $false

    $serviceIPList = $ServiceIPS.Split(",")

    $portNameList = vfpctrl /list-vmswitch-port | sls "Port name"

    foreach($portName in $portNameList) {
	    $portId = $portName.ToString().Split(":")[1].Trim()
	    $entries = vfpctrl /port $portId /layer $Layer /list-group
	    if($entries.Count -le 8) {
		    continue
	    }
	    foreach($serviceIP in $serviceIPList) {
		    $entries = vfpctrl /port $portId /layer $Layer /group $Group /list-rule | sls $serviceIP
		    if($entries.Count -le 1) {
			    LogError "VFP $Layer Rule missing for Service IP :  $serviceIP in VFP Port : $portName"
                $lbDsrRuleMissing = $true
		    } else {
			    LogSuccess "VFP $Layer Rule present for Service IP :  $serviceIP in VFP Port : $portName"
		    }
	    }
    }

    if($lbDsrRuleMissing){
        LogError "Mitigation : Restart-Service -f kubeproxy "
        return
    }

    LogSuccess "No issues identified with $Layer Rule Missing for Service IPS : $ServiceIPS."
}

function ExecFromOutside {
    $hpcPods = kubectl get pods -n $HpcNamepsace | sls $HpcPodPrefix
    if($CopyScriptToNode -eq $true) {
        foreach($hpcPod in $hpcPods) {
            $podId = $hpcPod.ToString().Split(" ")[0].Trim()
            Write-Host "Copying script to $podId"
            kubectl cp .\checkLbDsrMissing.ps1 "$podId`:`checkLbDsrMissing.ps1" -n $HpcNamepsace
        }
    }
    foreach($hpcPod in $hpcPods) {
	    $podId = $hpcPod.ToString().Split(" ")[0].Trim()
	    kubectl exec -it $podId -n $HpcNamepsace -- powershell ".\checkLbDsrMissing.ps1 -ServiceIPS '$ServiceIPS' -Layer $Layer -Group $Group"
    }
}

if($RunFromOutside -eq $true) {
    ExecFromOutside
}

CheckLbDsrRuleMissing