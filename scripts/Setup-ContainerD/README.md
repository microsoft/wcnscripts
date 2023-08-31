## How To Setup ContainerD Locally

### VHD Image to be used
```
Use: \\winbuilds\release\rs_onecore_liof1
Eg: \\winbuilds\release\rs_onecore_liof1\25272.1004.221221-1100\amd64fre\vhd\vhd_server_serverdatacentercore_en-us\25272.1004.amd64fre.rs_onecore_liof1.221221-1100_server_serverdatacentercore_en-us.vhd
```

#### Copy this directory to C:\ in new VM

#### Open "\\winbuilds\release\rs_onecore_liof1" using "Windows + r" to make the directory accessible by the script

### Install Docker
```
.\Install-Docker.ps1.ps1 -Stable -HyperV
```
This will involve restart of VM. Login to VM again

### Install ContainerD
```
.\Install-ContainerD.ps1
```

### Import Modules
```
cd C:\Setup-ContainerD\hns
Import-Module -Force .\HnsContainerdApis.psm1
```
The above step will be executed as part of installation script.

### Create DualStack Network
```
CreateDualStackNetwork
```

### Create DualStack Service
```
CreateDualStackService -svcName server-svc -ipStartIndex 10 -podCount 2
```
Default values for -vip = 14.0.0.14 , -vip6 = 14::14 

### Create Client Pod
```
CreatePod -podName client
```

### Find the pod id of server pods
```
crictl ps | sls "server-svc"

```

### Find the ip address of one of the server pod using pod id
```
crictl exec -it <Server Pod ID> ipconfig

```

### Find the pod id of client pod
```
crictl ps | sls "client"

```

### Establish TCP Connection from Client Pod to Server Pod using Server Pod IP
```
crictl exec -it <Client Pod ID> client.exe -i <Server Pod IP> -p 4444 -c 1 -r 2 -d 10

```

### Establish TCP Connection from Client Pod to Server Pods using Server Service IP
```
crictl exec -it <Client Pod ID> client.exe -i 14.0.0.14 -p 4444 -c 1 -r 2 -d 10
crictl exec -it <Client Pod ID> client.exe -i 14::14 -p 4444 -c 1 -r 2 -d 10

```

### Enable ARP/NDP entries in every pod
```
$ifIndex = (Get-NetAdapter).ifIndex
Get-NetNeighbor // To find the MacAddress
New-NetNeighbor -IPAddress 10.0.0.1 -LinkLayerAddress <Mac Address> -InterfaceIndex $ifIndex -ErrorAction Ignore
New-NetNeighbor -IPAddress 10::1 -LinkLayerAddress <Mac Address> -InterfaceIndex $ifIndex -ErrorAction Ignore
```