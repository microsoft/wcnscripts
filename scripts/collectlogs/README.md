# collectlogs
A script to take a snapshot of HNS and general container networking state.

## Usage
```
.\collectlogs.ps1
```
Will take a snapshot of container networking state for l2bridge networking mode in current HNS schema version.

## Parameters
```
    [parameter(Mandatory = $false)] [string] $Network = "L2Bridge", # network mode (L2bridge or Overlay)
    [parameter(Mandatory = $false)] [ValidateSet(1,2)] [int] $HnsSchemaVersion = 2 # HNS schema version
```