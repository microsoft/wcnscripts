# AKS Periscope

AKS Periscope allows AKS customers to run initial diagnostics, collect and export the logs (such as into an Azure Blob storage account) to help them analyze and identify potential problems or easily share the information to support to help with the troubleshooting process.

In AKS Periscope, [kustomization.yaml](./kustomization.yaml) is used to define the Kubernetes resources that are required for the tool to function properly. This includes defining the deployment, service, and configuration files for AKS Periscope itself, as well as the resources required to monitor and analyze your AKS cluster.

## Instructions

  1. Request blob storage from Microsoft support or create your own blob storage and generate a SAS key
  2. Configure the `kustomization.yaml`. Replace the placeholders `<strgAcctName>`, `<containerName>`, `<runId>`, and `<sasKey>` with the appropriate values.
  3. Apply the yaml in the AKS cluster 
     * `kubectl apply -f kustomization.yaml`

This should collect the required logs to troubleshoot networking issues from all the Windows worker nodes on the AKS cluster and place them in the blob store.