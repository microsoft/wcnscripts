# monitorDNS
A script to monitor DNS load balancing policies, associated VFP rules and rule counters.

## Usage
```
.\monitorDNS.ps1
```
Will query DNS rules every 3 seconds for any changes for 20 minutes and print any changes to dnsinfo.txt file. 

## Parameters
```
    [parameter(Mandatory = $false)] [string] $FileName = "dnsinfo.txt", # Output file name
    [parameter(Mandatory = $false)] [int] $WaitTime = 1200, # In seconds
    [parameter(Mandatory = $false)] [int] $Interval = 3, # Interval (in seconds) to sleep between querying DNS rules
    [parameter(Mandatory = $false)] [bool] $VerifyVfpRules = $true # Flag to skip (noisy) monitoring of VFP rules  
``` 