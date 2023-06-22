# Collect-windows-logs

This will run the [collect-windows-logs](http://aka.ms/collect-windows-logs) script from a DaemonSet and store the generated .zip archive into directory `c:\k\debug\hnslogs\`. 
The [collect-windows-logs](http://aka.ms/collect-windows-logs) script is present by default in AKS Windows nodes under path `C:\k\debug\collect-windows-logs.ps1`.

# Instructions
  1. Replace `<repro_hostname>` in the [collect-windows-logs-2022.yaml](./collect-windows-logs-2022.yaml) file
  2. Apply the manifest to collect logs:
      * kubectl apply -f collect-windows-logs-2022.yaml

Wait for the script to complete (2-10 min) (keyword "DONE" in stdout logs), note down the generated .zip archive, then use your preferred method (e.g. `kubectl cp`) to copy the .zip archive to your destination.