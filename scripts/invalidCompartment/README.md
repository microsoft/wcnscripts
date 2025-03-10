The script extracts the namespaceId and compartmentId from the endpoint information. It then validates the compartmentId against the namespace details. If any anomalies are detected, HNS and TCP/IP traces are captured, along with Windows log collection.

To run the script, open a PowerShell window and run the following command: 
 PS> .\invalidCompartment.ps1

 Or, we can run the scripts under hostprocess daemonset containers using invalidCompartment.yaml