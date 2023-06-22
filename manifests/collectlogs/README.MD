# collectlogs

This will run the [collectlogs](http://aka.ms/collectlogs) script from a DaemonSet and store the generated .zip archive into directory `c:\k\debug\hnslogs\`. 
The [collectlogs](http://aka.ms/collectlogs) script is present by default in AKS Windows nodes under path `C:\k\debug\collectlogs.ps1`.

# Instructions
  1. Replace `<repro_hostname>` in the [collectlogs2022.yaml](./collectlogs2022.yaml) file
  2. Apply the manifest to collect logs:
      * kubectl apply -f collectlogs2022.yaml

Wait for the script to complete (2-10 min) (keyword "DONE" in stdout logs), note down the generated .zip archive, then use your preferred method (e.g. `kubectl cp`) to copy the .zip archive to your destination.