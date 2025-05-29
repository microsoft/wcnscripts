This script checks whether any load balancer policies are in a degraded state. When a policy is degraded (indicated by a state value of 4), kube-proxy may be unable to delete it, potentially leading to an infinite loop. Before confirming a policy as degraded, the script also verifies that its referenced endpoints are valid.

To run the script, open a PowerShell window and run the following command: 
 PS> .\findDegradedPolicy.ps1

 Or, we can run the scripts under hostprocess daemonset containers using findDegradedPolicy.yaml