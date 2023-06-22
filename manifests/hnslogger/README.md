# hnslogger
A manifest to monitor basic HNS activity at levels:
  * 2 - errors only
  * 4 - (info) errors + HNS RPC calls
  * 6 - all activity (*VERY* noisy)

By default, it will rotate the traces so that only the 4 newest trace files are preserved (filesize ~500 MB). When you stop the trace, there should be at most 5 log files.

NOTE: Currently, the hnslogger only contains activity for HNS at medium verbosity. Depending on the nature of the issue, it may be required to expand the list of components to monitor and/or verbosity to further diagnose the issue.

## Usage
```
kubectl apply -f hnsloggger2022.yaml
```
Will schedule hnslogger DaemonSet pods onto every Windows node into namespace `wcn-debug`. This will use level 4 by default and write `hnslogs.etl` files into directory `C:\k\debug\hnslogs`.

If you have containerD v1.6.18 or higher, you can also apply `hnslogger.yaml` on either Windows Server 2022 or Windows Server 2019.

## Parameters
`pktmon start --trace -p Microsoft-Windows-Host-Network-Service -l 4 -m multi-file -f hnslogs.etl -s 256;`
For example, to change from level 4 to level 2, you can change `-l 4` to `-l 2`.
See aka.ms/pktmon for further pktmon documentation.