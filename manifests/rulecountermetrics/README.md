# rulecountermetrics
A manifest to capture VFP counters on periodic basis.


## Usage
```
kubectl apply -f rulecountermetrics2022.yaml
```
Will query VFP port and rule counters of all pods with prefix "win-webserver" every 15 minutes and print these to `C:\k\debug\hnslogs\rulecounters.txt` file.

If you have containerD v1.6.18 or higher, you can also apply `packetcapture.yaml` on either Windows Server 2022 or Windows Server 2019.

## Parameters
```
  [string] $NetworkName = "azure",  # L2bridge Network name (default "azure" in AKS) 
  [string[]] $PodNamePrefixes = @("win-webserver"), # Prefix of pod names to monitor
  [int] $TimeIntervalInSeconds = 900,  # Interval to sleep between querying the VFP counters
  [bool] $ExternalToService = $true, # Enable host port to service VFP counters 
  [parameter(Mandatory = $false)] [string] $FileName = "rulecounters.txt", # Output file name
  [parameter(Mandatory = $false)] [string] $LogDirectory = "c:\k\debug\hnslogs\" # Output directory
``` 