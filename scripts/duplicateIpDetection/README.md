The script uses the  Get-HnsEndpoint  cmdlet to retrieve all IP addresses associated with the endpoints on the host. It then groups the IP addresses by value and filters the groups to include only those with more than one IP address.

 To run the script, open a PowerShell window and run the following command: 
 PS> .\DetectDuplicateIpAddrs.ps1
 
Once a duplicate IP address is detected, it breaks out of the while loop and then collects Windows logs on the node. 
 