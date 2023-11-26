# capturepacketdrops
A manifest to capture dropped packet traces in VFP.

By default, it will rotate the traces so that 40 newest trace files are preserved (filesize ~500 MB). When you stop the trace, there should be at most 41 log files.

NOTE: This will capture a lot of data, and consume significant disk space. Adjust the `$MaxLogFileCount` as needed.

## Usage
```
kubectl apply -f capturepacketdrops2022.yaml
```
Will schedule packetcapture DaemonSet pods onto every Windows node into namespace `wcn-debug`. This will use level 4 by default and write `packetcapture.etl` files into directory `C:\k\debug\wcnlogs`.

If you have containerD v1.6.18 or higher, you can also apply `capturepacketdrops.yaml` on either Windows Server 2022 or Windows Server 2019.

## Parameters
`pktmon start -t -p Microsoft-Windows-Hyper-V-VfpExt -k 0x0000000000000002 -m multi-file -f packetcapture.etl -s 256;`

This runs Pktmon trace filtering with keyword 'Guard' (used for filtering dropped packets) for Microsoft-Windows-Hyper-V-VfpExt provider.

See aka.ms/pktmon for further pktmon documentation.