# Capture DNS Packets

> This yaml spawns hostprocess daemonset containers in every node once created. The script inside the container will start pktmon capture for DNS packets originating from every pod with prefix mentioned in powershell variable $podPrefix [Eg: "tcp-server"]

## Start DNS Packet Capture

Update the $podPrefix in DnsPktCapture2019.yaml/DnsPktCapture2022.yaml with right values.
```
Line: 28   $podPrefix = "DnsPinger"
```
Start pktmon by creating daemon set: DnsPktCapture2019.yaml.
```
kubectl create -f .\DnsPktCapture2019.yaml
```
Keep the containers running less than 5 hours.

## Stop DNS Packet Capture

Once the issue is reproduced or pktmon running time exceeds 5 hours, stop pktmon by deleting daemon set: DnsPktCapture2019.yaml and wait for 5 minutes.
```
kubectl delete -f .\DnsPktCapture2019.yaml
```
Packet capture will be generated in “C:\pktmonLogs” directory of each node after 5 minutes. Copy the capture logs out of the node.
