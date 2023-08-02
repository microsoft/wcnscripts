# Capture TCP and Pktmon Packets

> This yaml spawns hostprocess daemonset containers in every node once created. The script inside the container will start pktmon capture and TCPIP traces and keep monitoring 

## Start pktmon capture and TCPIP traces

Start traces by creating daemon set: StartTcpAndPktCapture2022.yaml
```
kubectl create -f .\StartTcpAndPktCapture2022.yaml
```
Keep the containers running less than 5 hours.

## Stop pktmon capture and TCPIP traces

Once routes goes missing or pktmon running time exceeds 5 hours, stop pktmon by deleting daemon set: StartTcpAndPktCapture2022.yaml and wait for 5 minutes.
```
kubectl delete -f .\StartTcpAndPktCapture2022.yaml
```
Packet capture will be generated in “C:\pktmonLogs” directory of each node after 5 minutes. Copy the capture logs out of the node.
