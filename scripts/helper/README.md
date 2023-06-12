# helper
This directory contains a collection of helper scripts/Powershell functions for network inspection.

## Usage

```
ipmo .\helper.v2.psm1
```
Will import the helper functions.

# dumpVfpPolicies.ps1
Can be used to output the VFP rules on the system.

## Usage

```
.\dumpVfpPolicies.ps1
```
Will dump the VFP rules, mappings, and NAT ranges into `vfprules.txt`.