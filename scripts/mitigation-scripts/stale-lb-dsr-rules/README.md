# Stale LB DSR Rules Cleanup

## Overview

This mitigation script automatically detects and removes stale Load Balancer Direct Server Return (LB DSR) rules from VFP (Virtual Filtering Platform) that reference non-existent backend endpoints. It runs continuously to maintain network health by cleaning up orphaned rules that can cause connectivity issues.

## Problem Statement

When backend endpoints are removed or become unavailable, the corresponding LB DSR rules in VFP may not be cleaned up properly. These stale rules can:
- Cause packet routing failures
- Lead to connection timeouts
- Create unnecessary overhead in the networking stack
- Result in traffic being sent to non-existent endpoints

## Solution

The `cleanup-stale-lb-rules.ps1` script:
1. Checks and sets the required registry configuration for LB DSR feature management
2. Continuously monitors VFP LB DSR rules (both IPv4 and IPv6)
3. Compares rule destination IPs (DIPs) against active HNS endpoints
4. Automatically removes rules that reference non-existent endpoints

## Prerequisites

- Windows Server with HNS (Host Network Service) enabled
- VFP control utilities (`vfpctrl.exe`) available
- PowerShell with administrator privileges
- HNS PowerShell module

## Usage

### Running the Script on a Single Node

```powershell
.\cleanup-stale-lb-rules.ps1
```

The script will:
1. Check registry key `HKLM:\SYSTEM\CurrentControlSet\Policies\Microsoft\FeatureManagement\Overrides\140377743`
2. If the key value is 1, set it to 0 and restart the node (this disables PR 13179278 which is causing delete LB RPC calls from KubeProxy to fail with Invalid IP Error - ICM: 719903780)
3. Start a continuous monitoring loop with 10-second intervals
4. Clean up any stale LB DSR rules found

**Note:** This approach fixes issues on a single node. If the issue is widespread across the cluster, deploy the solution using a DaemonSet:

```powershell
kubectl create -f cleanup-stale-lb-rules.yaml
```

This will run the mitigation script as HPC pods on all affected nodes.

### Configuration

You can modify these parameters at the top of the script:

- **`$groups`**: VFP groups to monitor (default: `LB_DSR_IPv4_OUT`, `LB_DSR_IPv6_OUT`)
- **`$refreshIntervalSeconds`**: Time between cleanup iterations (default: 10 seconds)

## How It Works

### 1. Registry Check
The script first ensures the feature flag registry key (140377743) is set to 0. If not, it sets the value and restarts the node.

### 2. Endpoint Collection
- Retrieves all HNS policies
- Extracts endpoint references
- Builds a dictionary of valid endpoint IP addresses

### 3. Rule Validation
For each VFP port and LB DSR group:
- Lists all rules in the `LB_DSR` layer
- Extracts DIP (Destination IP) ranges from each rule
- Compares DIPs against the valid endpoint dictionary

### 4. Cleanup
- Rules with DIPs not found in active endpoints are flagged as stale
- Stale rules are automatically deleted using `vfpctrl /remove-rule`

## Output Examples

### Healthy State
```
All DIP ranges are present in the dictionary.
```

### Stale Rules Detected
```
Missing DIP ranges:
 - 10.244.0.25
 - fdf5:5d67:b9ce:b28f::13f
Deleting rule : ruleId: ABC123, port: Port1, group: LB_DSR_IPv4_OUT
```

## Monitoring

The script provides color-coded output:
- **Green**: Healthy state, all rules valid
- **Yellow**: Configuration changes or rule deletion in progress
- **Red**: Stale rules detected
- **Cyan**: Status updates and iteration markers

## Important Notes

- The script runs indefinitely until manually stopped (Ctrl+C)
- Node restart may occur on first run if registry configuration is incorrect
- Ensure no legitimate endpoint updates are in progress during cleanup to avoid false positives
- The script requires elevated privileges to modify VFP rules and registry settings

## Troubleshooting

### Script doesn't detect stale rules
- Verify VFP and HNS are functioning correctly
- Check that `vfpctrl.exe` is accessible in the system PATH
- Ensure HNS endpoints are properly registered

### Node restarts unexpectedly
- This is expected behavior if the registry key is not set to 0
- After restart, the script will continue normal operation

### Permission errors
- Run PowerShell as Administrator
- Verify account has rights to modify VFP rules and registry

## Related Documentation

- [VFP Documentation](../../helper/VFP.psm1)
- [HNS Module](../HNS/)
- [Network Health Monitoring](../../networkhealth/)

## Support

For issues or questions, please refer to the main repository documentation or open an issue.
