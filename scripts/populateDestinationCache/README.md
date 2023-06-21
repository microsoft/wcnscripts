# Populate destination cache

> This yaml spawns hostprocess daemonset containers in every node once created. The script inside the container will keep populating destination cache for the gateway

## Start script

```
kubectl create -f .\populateDestCache2022.yaml
```