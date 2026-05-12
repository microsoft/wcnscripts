function Get-PodIdAndIp {
    $podsJson = crictl pods -o json | ConvertFrom-Json
    $results = foreach ($pod in $podsJson.items) {
        $podId = $pod.id
        $podName = $pod.metadata.name
        $podNamespace = $pod.metadata.namespace

        # Get pod IP from inspectp
        $inspectJson = crictl inspectp -o json $podId | ConvertFrom-Json
        $podIPv4 = $inspectJson.status.network.ip
        if ($podIPv4 -eq $null -or $podIPv4 -eq "") {
            continue
        }
        $podIPv6 = $inspectJson.status.network.additionalIps | Where-Object { $_ -match ':' } | Select-Object -First 1

        [pscustomobject]@{
            "Pod ID"    = $podId
            "Pod Name"  = $podName
            "Namespace" = $podNamespace
            "IPv4"      = $podIPv4
            "IPv6"      = $podIPv6
            "State"     = $pod.state
        }
    }
    return $results
}

function VfpPortToEndpointMapping {
    $ports = (vfpctrl.exe /list-vmswitch-port /format 1 | ConvertFrom-Json).Ports
    $endpoints = Get-HnsEndpoint

    $results = foreach ($port in $ports) {

        $portId   = $port.Id
        if ($portId -eq $null -or $portId -eq "" -or $portId -eq "ExternalPort" -or $portId -like "Container NIC *") {
            continue
        }
        $portName = $port.Name
        $portMac  = $port.MacAddress
        $portNo   = $port.VmsPortId

        # Normalize MAC (00155D5AB0B2 → 00-15-5D-5A-B0-B2)
        $epMac = ($portMac -split '(.{2})' | Where-Object { $_ }) -join '-'

        $ep = $endpoints | Where-Object { $_.MacAddress -eq $epMac } | Select-Object -First 1

        [pscustomobject]@{
            "VFP Port"      = $portId
            "VFP Port Name" = $portName
            "VFP Port No."  = $portNo
            "EP ID"         = $ep.ID
            "IPv4"          = $ep.IPAddress
            "IPv6"          = $ep.IPv6Address
            "MAC"           = $epMac
        }
    }
    return $results
}

function Get-PortsMissingDnsRules {
    $portMapping = VfpPortToEndpointMapping

    $results = foreach ($entry in $portMapping) {
        $portName = $entry."VFP Port Name"
        $hasDnsTcp = $false
        $hasDnsUdp = $false
        $dnsRules = @()

        $rules = (vfpctrl /port $portName /layer LB_DSR /group LB_DSR_IPv4_OUT /list-rule /format 1 | ConvertFrom-Json).Rules
        foreach ($rule in $rules) {
            $ruleId = $rule.Id
            if ($ruleId -match '_53_53_6_') {
                $hasDnsTcp = $true
                $dnsRules += $ruleId
            }
            if ($ruleId -match '_53_53_17_') {
                $hasDnsUdp = $true
                $dnsRules += $ruleId
            }
        }

        if (-not $hasDnsTcp -or -not $hasDnsUdp) {
            [pscustomobject]@{
                "VFP Port"      = $entry."VFP Port"
                "VFP Port Name" = $portName
                "EP ID"         = $entry."EP ID"
                "IPv4"          = $entry."IPv4"
                "IPv6"          = $entry."IPv6"
                "Has DNS TCP"   = $hasDnsTcp
                "Has DNS UDP"   = $hasDnsUdp
                "DNS Rules"     = ($dnsRules -join ", ")
            }
        }
    }
    return $results
}

function Force-DeletePodSandbox {
    param(
        [string]$podId
    )
    $deleted = $false
    while (-not $deleted) {
        Write-Host "Attempting to force delete pod sandbox $podId ..."
        crictl stopp $podId 2>$null
        crictl rmp -f $podId 2>$null
        $check = crictl pods -o json | ConvertFrom-Json
        $still = $check.items | Where-Object { $_.id -eq $podId }
        if ($still -eq $null) {
            Write-Host "Pod sandbox $podId successfully deleted."
            $deleted = $true
        } else {
            Write-Host "Pod sandbox $podId still exists, retrying..."
        }
    }
}

function Test-DnsFromPod {
    param(
        [string]$podId
    )
    # Get the first running container in this pod
    $containers = crictl ps -o json --pod $podId | ConvertFrom-Json
    $containerId = $containers.containers | Where-Object { $_.state -eq "CONTAINER_RUNNING" } | Select-Object -First 1 -ExpandProperty id
    if ($containerId -eq $null -or $containerId -eq "") {
        Write-Host "No running container found in pod $podId, DNS check skipped."
        return $false
    }

    try {
        $output = (crictl exec $containerId nslookup kubernetes.default.svc.cluster.local 2>&1) -join "`n"
        if ($output -match "timed out" -or $output -match "timeout was" -or $output -match "can't resolve" -or $output -match "SERVFAIL" -or $output -match "connection timed out") {
            Write-Host "DNS check FAILED for pod $podId : $output"
            return $false
        }
        if ($output -match "Address" -and $output -match "Name:") {
            Write-Host "DNS check PASSED for pod $podId"
            return $true
        }
        Write-Host "DNS check FAILED for pod $podId : $output"
        return $false
    } catch {
        Write-Host "DNS check ERROR for pod $podId : $($_.Exception.Message)"
        return $false
    }
}

$sleepInSeconds = 300 # 5 minutes

While($true) {
    Write-Host "Checking for ports with missing DNS rules..."
    $portsWithMissingDnsRules = Get-PortsMissingDnsRules
    $podDetails = Get-PodIdAndIp
    foreach ($port in $portsWithMissingDnsRules) {
        $matchedPod = $podDetails | Where-Object { $_.IPv4 -eq $port.IPv4 }
        if ($matchedPod) {
            Write-Host "Pod: $($matchedPod.'Pod Name') | Namespace: $($matchedPod.Namespace) | PodIP: $($matchedPod.IPv4) | VFP Port: $($port.'VFP Port Name') | Has DNS TCP: $($port.'Has DNS TCP') | Has DNS UDP: $($port.'Has DNS UDP')"

            $dnsOk = Test-DnsFromPod -podId $matchedPod.'Pod ID'
            if (-not $dnsOk) {
                Write-Host "DNS verification failed, force deleting pod sandbox..."
                Force-DeletePodSandbox -podId $matchedPod.'Pod ID'
            } else {
                Write-Host "DNS works despite missing VFP rule, skipping deletion."
            }
        } else {
            Write-Host "No pod found for VFP Port: $($port.'VFP Port Name') | EP IPv4: $($port.IPv4) | Has DNS TCP: $($port.'Has DNS TCP') | Has DNS UDP: $($port.'Has DNS UDP')"
        }
    }
    Write-Host "Check complete. Sleeping for $sleepInSeconds seconds before next check..."
    Start-Sleep -Seconds $sleepInSeconds
}