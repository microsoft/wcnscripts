# portCountAvailable.ps1
A script to monitor availability of ephemeral (aka dynamic) ports on the Node. HNS consumes dynamic ports for NAT purposes (64 per pod), in addition to active connections established from the hosted pods. 

## Usage
```
.\portCountAvailable.ps1
```
Will create file `portrangeinfo.txt` and print the number of available ports every 10s for a total wait time of 1 hour.