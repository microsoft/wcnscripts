# wcnscripts

> A collection of Windows container networking troubleshooting scripts and manifests, primarily targeting networking issues in the Azure Kubernetes Service.

## Scripts directory
[scripts](./scripts) contains network troubleshooting PowerShell scripts.

## Manifests directory
[manifests](./manifests) contains manifests (.yaml) to help monitor/remedy K8s Windows networking issues. 


## Examples

### Kube-proxy / CNI issues:
To investigate kube-proxy or CNI issues, run the following:
  1. Before the repro: [collect-windows-logs](http://aka.ms/collect-windows-logs)
  2. Start HNS trace: [starthnstrace.ps1](./scripts/starthnstrace/starthnstrace.ps1)
  3. Reproduce the issue
  4. Stop the HNS trace: press 'q' in shell from step #2
  5. After the repro: [collect-windows-logs](http://aka.ms/collect-windows-logs)


### Data path issues:
To investigate data path issues such as intermittent packet loss:
  1. Before the repro: [collect-windows-logs](http://aka.ms/collect-windows-logs)
  2. Start packet trace: [startpacketcapture.ps1](./scripts/startpacketcapture/startpacketcapture.ps1)
  3. Reproduce the issue
  4. Stop the packet capture trace: press 'q' in shell from step #2
  5. After the repro: [collect-windows-logs](http://aka.ms/collect-windows-logs)


### Control-plane issues:
To investigate control-plane issues, run the following:
  1. Before the repro: [collect-windows-logs](http://aka.ms/collect-windows-logs)
  2. Start HNS trace: [starthnstrace.ps1](./scripts/starthnstrace/starthnstrace.ps1)
  3. Reproduce the issue
  4. Stop the HNS trace: press 'q' in shell from step #2
  5. After the repro: [collect-windows-logs](http://aka.ms/collect-windows-logs)


### DNS issues:
To investigate DNS issues:
  1. Before the repro: [collect-windows-logs](http://aka.ms/collect-windows-logs)
  2. Start monitoring DNS rules/policies/counters: [monitorDNS](./scripts/monitorDNS/monitorDNS.ps1)
  3. Start packet trace: [startpacketcapture.ps1](./scripts/startpacketcapture/startpacketcapture.ps1)
  4. Reproduce the issue
  5. Stop the packet capture trace: press 'q' in shell from step #3
  6. Stop the DNS monitoring from step #2 (press Ctrl+C) 
  7. After the repro: [collect-windows-logs](http://aka.ms/collect-windows-logs)


### Contributing

This project welcomes contributions and suggestions.  Most contributions require you to agree to a
Contributor License Agreement (CLA) declaring that you have the right to, and actually do, grant us
the rights to use your contribution. For details, visit https://cla.opensource.microsoft.com.

When you submit a pull request, a CLA bot will automatically determine whether you need to provide
a CLA and decorate the PR appropriately (e.g., status check, comment). Simply follow the instructions
provided by the bot. You will only need to do this once across all repos using our CLA.

This project has adopted the [Microsoft Open Source Code of Conduct](https://opensource.microsoft.com/codeofconduct/).
For more information see the [Code of Conduct FAQ](https://opensource.microsoft.com/codeofconduct/faq/) or
contact [opencode@microsoft.com](mailto:opencode@microsoft.com) with any additional questions or comments.

### Trademarks

This project may contain trademarks or logos for projects, products, or services. Authorized use of Microsoft 
trademarks or logos is subject to and must follow 
[Microsoft's Trademark & Brand Guidelines](https://www.microsoft.com/en-us/legal/intellectualproperty/trademarks/usage/general).
Use of Microsoft trademarks or logos in modified versions of this project must not cause confusion or imply Microsoft sponsorship.
Any use of third-party trademarks or logos are subject to those third-party's policies.
