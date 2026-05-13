$groups = @("LB_DSR_IPv4_OUT", "LB_DSR_IPv6_OUT")
$refreshIntervalSeconds = 10

function Get-EndpointIpDictionary {
    $dict = @{}

    $policies = Get-HnsPolicyList

    $endpointIds = $policies.References |
        Where-Object { $_ -like "/endpoints/*" } |
        ForEach-Object { ($_ -split "/")[-1] } |
        Sort-Object -Unique

    $endpointIds | ForEach-Object {
        try {
            $endpoint = Get-HnsEndpoint -Id $_
        } catch {
            Write-Host "Failed to get HNS endpoint $_`: $($_.Exception.Message)" -ForegroundColor Yellow
            continue
        }

        if ($null -eq $endpoint) {
            Write-Host "HNS endpoint $_ not found, skipping." -ForegroundColor Yellow
            continue
        }

        if ($null -ne $endpoint.IPAddress) {
          $dict[$endpoint.IPAddress] = $true
        }
        if ($null -ne $endpoint.IPv6Address) {
          $dict[$endpoint.IPv6Address] = $true
        }
    }

    return $dict
}

function Get-StaleRuleCommands {
    param(
        [string[]]$Groups
    )

    $dictDstIPs = Get-EndpointIpDictionary
    $staleRuleCommands = [System.Collections.Generic.List[string]]::new()

    $ports = (vfpctrl.exe /list-vmswitch-port /format 1 | ConvertFrom-Json).Ports.Name
    foreach ($port in $ports) {
        foreach ($group in $Groups) {
            $rules = (vfpctrl /port $port /layer LB_DSR /group $group /list-rule /format 1 | ConvertFrom-Json).Rules
            foreach ($rule in $rules) {
                $ruleId = $rule.Id
                $ruleText = vfpctrl /get-rule-info /port $port /layer LB_DSR /group $group /rule $ruleId 2>&1
                if (-not $ruleText) {
                    Write-Host "No output from vfpctrl"
                    continue
                }

                $dips = Get-DipRangesFromRuleText -RuleText $ruleText
                # Check which DIPs are missing in the dictionary
                $missingDIPs = $dips | Where-Object { -not $dictDstIPs.ContainsKey($_) }

                if ($missingDIPs.Count -eq 0) {
                    # Write-Host "All DIP ranges are present in the dictionary." -ForegroundColor Green
                } else {
                    # Write-Host "Missing DIP ranges:" -ForegroundColor Red
                    # $missingDIPs | ForEach-Object { Write-Host " - $_" }
                    $staleRuleCommands.Add("vfpctrl /remove-rule /port $port /layer LB_DSR /group $group /rule $ruleId")
                }
            }
        }
    }

    return $staleRuleCommands
}

function Get-DipRangesFromRuleText {
    param([string[]]$RuleText)

    $collect = $false
    $dips = @()

    foreach ($line in $RuleText) {

        # Detect beginning of DIP Range block
        if ($line -match "DIP Range") {
            $collect = $true
            continue
        }

        # Stop when FlagsEx or another header appears
        if ($collect -and $line -match "FlagsEx") {
            break
        }

        # Process lines like:
        # { 10.244.0.25 : 53 }
        # { fdf5:5d67:b9ce:b28f::13f : 4445 }
        if ($collect -and $line.Trim().StartsWith("{")) {

            # Remove surrounding { } then trim
            $clean = $line.Trim().Trim('{','}').Trim()
            # Use regex to extract IP before last " : "
            if ($clean -match '(.+)\s*:\s*\d+$') {
                $ip = $matches[1].Trim()
                $dips += $ip
            }
        }
    }

    return $dips
}

While($true) {
    Write-Host "##========== Waiting for $refreshIntervalSeconds seconds for the next iteration..." -ForegroundColor Cyan
    Start-Sleep -Seconds $refreshIntervalSeconds
    Write-Host "##========== Starting new iteration to check for stale LB DSR rules..." -ForegroundColor Cyan
    $staleRuleCommands_1 = Get-StaleRuleCommands -Groups $groups
    Start-Sleep -Seconds 60 # Short pause before executing commands
    $staleRuleCommands_2 = Get-StaleRuleCommands -Groups $groups

    # Rules present in both passes (consistently stale)
    $inBothPasses = $staleRuleCommands_1 | Where-Object { $staleRuleCommands_2 -contains $_ }

    if ($inBothPasses.Count -gt 0) {
        Write-Host "##========== Found $($inBothPasses.Count) stale rule(s) to remove." -ForegroundColor Yellow
    } else {
        Write-Host "##========== No stale rules found." -ForegroundColor Green
    }

    # Execute only rules that appeared in both passes (consistently stale)
    foreach ($cmd in $inBothPasses) {
        Write-Host "##========== Executing Delete Command: $cmd" -ForegroundColor Yellow
        Invoke-Expression $cmd
    }
}