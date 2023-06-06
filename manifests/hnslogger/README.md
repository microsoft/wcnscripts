# hnslogger
A manifest to monitor basic HNS activity at levels:
  * 2 - errors only
  * 4 - (info) errors + HNS RPC calls
  * 6 - all activity (*VERY* noisy)

By default, it will rotate the traces so that only the 5 newest trace files are preserved (filesize ~256 MB).

## Usage
```
kubectl apply -f hnsloggger.yaml
```
Will schedule hnslogger DaemonSet pods onto every Windows node. This will use level 4 by default and write `hnslogs.etl` files into directory `C:\k\hnslogs`.

## Parameters
`pktmon start --trace -p Microsoft-Windows-Host-Network-Service -l 4 -m multi-file -f hnslogs.etl -s 256;`
For example, to change from level 4 to level 2, you can change `-l 4` to `-l 2`.
See aka.ms/pktmon for further pktmon documentation.