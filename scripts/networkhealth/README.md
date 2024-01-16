# Networkhealth.ps1

This will analyze VFP and HNS container networking health.
The following output modes are supported through the `-OutputMode` parameter:

| OutputMode | Tests Pass                                                                          | Tests Fail                                                                                 |
|------------|-------------------------------------------------------------------------------------|--------------------------------------------------------------------------------------------|
| Event      | Log a concise informational event in Event logs describing container network health | 1. Log a warning event with verbose logs <br/>  2. Dump HNS data to JSON <br/> 3. Collect Windows Logs |
| Html       | 1. Create a HTML report of validated network tests <br/> 2. Dump HNS data to JSON         | 1. Create a HTML report of validated network tests and failures <br/> 2. Dump HNS data to JSON   |
| All        | All the above                                                                       | All the above                                                                              |

## Assumptions
For collecting logs during failure or using the `-CollectLogs` parameter, The script assumes you have the following script in `C:\k\debug` (the default path on AKS-Windows): [aka.ms/collect-windows-logs](http://aka.ms/collect-windows-logs)

## Running locally
You can replay the script locally by using the generated JSON files and using the `-Replay` parameter.

## Event Logs
If the `-OutputMode` is set to `Event` or `All`, the script will register a new event source provider `NetworkHealth` in the `Application` event logs, where new events will be written. Informational events will use event ID 0, whereas warnings will use event ID 1.

## Instructions for AKS cluster

1. Apply the yaml **networkhealth.yaml** on an AKS cluster using this command
```
    Cleanup the previous instance of the daemon set and re-apply.

    kubectl delete -f networkhealth.yaml
    kubectl apply -f networkhealth.yaml
```

2. Wait for 5 minutes and redirect the output of the following command to a text file and provide it to the support engineer.
```
    kubectl logs -l name=networkhealth --all-containers=true

    Example:
    kubectl logs -l name=networkhealth --all-containers=true >> networkhealth.txt
    Provide the generated networkhealth.txt
```
## Command to run startNetworkDiagnostics
```
Normal Execution: .\startNetworkDiagnostics.ps1 -TimeIntervalInSeconds 30 -PrintMatchedRules $true -PodNamePrefixes tcp-server,tcp-client

Execution with DNS Packet Capture: .\startNetworkDiagnostics.ps1 -DnsPktCap $true

Execution with DualStack Test: .\startNetworkDiagnostics.ps1 -DualStack $true

Execution with Vfp Rule Counter Dump for Pods : .\startNetworkDiagnostics.ps1 -PodNamePrefixes tcp-client,tcp-server

Execution with printing matched rule counter : .\startNetworkDiagnostics.ps1 -PodNamePrefixes tcp-client,tcp-server -PrintMatchedRules $true

Execution with validate loadbalancer rules for Service IPS : .\startNetworkDiagnostics.ps1 -ServiceIPS "10.0.0.1,10.0.0.2"

```

## Command to run vfpDropCounterMetrics
```
.\vfpDropCounterMetrics.ps1 -TimeIntervalInSeconds 30 -PrintMatchedRules $true -PodNamePrefixes tcp-server,tcp-client
```

## DNS Health Check
```
Invoke-WebRequest https://raw.githubusercontent.com/microsoft/wcnscripts/2ea829ebaaf523cf58ef8e64120e54849eb4bd51/scripts/networkhealth/startNetworkDiagnostics.ps1 -OutFile startNetworkDiagnostics.ps1
.\startNetworkDiagnostics.ps1
```