# packetcapture
A manifest to capture packets and HNS traces.

By default, it will rotate the traces so that 40 newest trace files are preserved (filesize ~500 MB). When you stop the trace, there should be at most 41 log files.

NOTE: This will capture a lot of data, and consume significant disk space. Adjust the `$MaxLogFileCount` as needed.

## Usage
```
kubectl apply -f packetcapture2022.yaml
```
Will schedule packetcapture DaemonSet pods onto every Windows node into namespace `wcn-debug`. This will use level 4 by default and write `packetcapture.etl` files into directory `C:\k\debug\hnslogs`.

If you have containerD v1.6.18 or higher, you can also apply `packetcapture.yaml` on either Windows Server 2022 or Windows Server 2019.

## Parameters
`pktmon start --trace -p Microsoft-Windows-Host-Network-Service -p 2F07E2EE-15DB-40F1-90EF-9D7BA282188A -p 9F2660EA-CFE7-428F-9850-AECA612619B0 -p 1F387CBC-6818-4530-9DB6-5F1058CD7E86 -p 67DC0D66-3695-47c0-9642-33F76F7BD7AD -l 6 -m multi-file -f packetcapture.etl -s 256;`

This runs Pktmon trace at full verbosity for the following providers:
  * Microsoft-Windows-Host-Network-Service
  * Microsoft-Windows-TCPIP
  * Microsoft-Windows-Hyper-V-VfpExt
  * vmswitch
  * Microsoft-Windows-Hyper-V-VmSwitch

See aka.ms/pktmon for further pktmon documentation.