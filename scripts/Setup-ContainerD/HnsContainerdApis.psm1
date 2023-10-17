$Global:hnsVersion=2
Import-Module -Force .\newsdnhelper.psm1

$l2bridgeNetworkName = "test-prim-l2bridge-ipv6"
$k8sL2bridgeNetworkName = "l2bridgenetwork"
$useRoute = $true

$IPV4AddressPrefix = "10.0.0."
$IPV6AddressPrefix = "10::"
$dummyMac = "00-15-5D-C5-9C-63"

$ContainerDInstallDirectory = "C:\Program Files\containerd"
$CniConfDirectory = "C:\Program Files\containerd\cni\conf"
$imageName = "docker.io/princepereira/tcp-client-server:WS2022CONTAINERD"

function CreateSingleStackNetwork() {
	Remove-Item -Force -Recurse $PodJsonPath -ErrorAction Ignore
	mkdir $PodJsonPath
	DisableAddressRandomization
	Write-Host "Create single stack network called ..." -ForegroundColor Green
	Write-Host "Create primary l2bridge network called ..." -ForegroundColor Green
	CreatePrimaryL2BridgeNetwork -networkName $l2bridgeNetworkName
	Write-Host "Create primary l2bridge network completed ..." -ForegroundColor Green
	Write-Host "Create primary k8s l2bridge network called ..." -ForegroundColor Green
	CreateKubernetesL2BridgeNetwork -networkName $k8sL2bridgeNetworkName -IsContainerD $True
	Write-Host "Create primary k8s l2bridge network completed ..." -ForegroundColor Green
	Restart-Service containerd
	Start-Sleep 2
	Write-Host "Create single stack network completed ..." -ForegroundColor Green
}

function CreateDualStackNetwork() {
	Write-Host "Create dual stack network called ..." -ForegroundColor Green
	Write-Host "Create primary l2bridge network called ..." -ForegroundColor Green
	Remove-Item -Force -Recurse $PodJsonPath -ErrorAction Ignore
	mkdir $PodJsonPath
	DisableAddressRandomization
	CreatePrimaryL2BridgeNetwork -networkName $l2bridgeNetworkName -IsDualStack
	Write-Host "Create primary l2bridge network completed ..." -ForegroundColor Green
	Write-Host "Create primary k8s l2bridge network called ..." -ForegroundColor Green
	CreateKubernetesL2BridgeNetwork -networkName $k8sL2bridgeNetworkName -IsDualStack -IsContainerD $True
	Write-Host "Create primary k8s l2bridge network completed ..." -ForegroundColor Green
	Restart-Service containerd
	Start-Sleep 2
	Write-Host "Create dual stack network completed ..." -ForegroundColor Green
}

function CreatePod() {
	param(
        [parameter(Mandatory=$true)][string] $podName,
		[parameter(Mandatory=$false)][string] $ipv4Address = "",
		[parameter(Mandatory=$false)][string] $ipv6Address = ""
    )
	
	Write-Host "Create pod : $podName called ..." -ForegroundColor Green
	$cdCommandOutputs1 = @{}
	$cdCommandOutputs1["containerName"] = $podName
	$endpoint = CreateContainerDContainerWithPolicy -containerName $podName `
                                -installDirectory $ContainerDInstallDirectory `
                                -cniConfigDirectory $CniConfDirectory `
                                -networkType "L2Bridge" `
                                -enableOutboundNat `
                                -gateway $Global:TestL2BridgeGateway  `
                                -useRoute:$useRoute `
                                -createForElb `
                                -useExternalVip `
                                -crossHost `
                                -image $imageName `
                                -outputs $cdCommandOutputs1 `
                                -Verbose
	Write-Host "Create pod : $podName completed ... End Point : $endpoint ..." -ForegroundColor Green
	return $endpoint
}

function CreateSingleStackService() {
	param(
		[parameter(Mandatory=$true)][string] $svcName,
		[parameter(Mandatory=$false)][string] $createLB="True",
		[parameter(Mandatory=$false)][string] $enableDSR="True",
		[parameter(Mandatory=$false)][string] $vip = $Global:ServiceVip,
		[parameter(Mandatory=$false)][int] $intPort = 4444,
		[parameter(Mandatory=$false)][int] $extPort = 4444,
		[parameter(Mandatory=$true)][int] $ipStartIndex,
        [parameter(Mandatory=$false)][int] $podCount=1,
		[parameter(Mandatory=$false)][string] $gatewayV4,
		[parameter(Mandatory=$false, HelpMessage="Eg: 10.0.0.1,10.0.0.2")][string[]] $endpointList
    )
	
	$endpoints = @()
	$networkId = ((Get-HnsNetwork | Where-Object Name -EQ $k8sL2bridgeNetworkName).ID)
	
	foreach($ep in $endpointList) {
		$epName = "EP-"+$ep.Replace(".","-")
		$ipv4EP = $ep
		Write-Host "Create Endpoint : $epName called..." 
		New-HnsEndpoint -NetworkId $networkId -Name $epName -IPAddress $ipv4EP -PrefixLength 24 -GatewayAddress $gatewayV4 -MacAddress $dummyMac -RemoteEndpoint -EnableOutboundNat
		Start-Sleep 3
		$endpoint = (Get-HnsEndpoint | Where-Object Name -EQ $epName).ID
		$endpoints = $endpoints + $endpoint
		Write-Host "Create Endpoint : $epName completed... New Endpoint : $endpoint, Endpoints : $endpoints" 
	}
	
	Write-Host "Create singlestack service called ..." -ForegroundColor Green
	for($i = 1; $i -le $podCount; $i++) {
		$podName = $svcName + "-pod-" + $i
		$ipOctect = $ipStartIndex + $i - 1
		$ipv4Address = $IPV4AddressPrefix + $ipOctect
		Write-Host "Executing command : CreatePod -podName $podName -ipv4Address $ipv4Address ..." -ForegroundColor Green
		$endpoint = (CreatePod -podName $podName -ipv4Address $ipv4Address)
		$endpoints += $endpoint
		Start-Sleep 3
	}
	
	if($createLB -EQ "False") {
		Write-Host "createLB is False, so no loadbalancer will be created ..." -ForegroundColor Green
		return
	}
	
	Write-Host "Create IPV4 loadbalancer called ..."
	if($enableDSR -EQ "False") {
		Write-Host "Executing command :  CreateLoadBalancer -Endpoints $endpoints -InternalPort $intPort -ExternalPort $extPort -Vip $vip -Verbose ..." -ForegroundColor Green
		CreateLoadBalancer -Endpoints $endpoints -InternalPort $intPort -ExternalPort $extPort -Vip $vip -Verbose
	} else {
		Write-Host "Executing command :  CreateLoadBalancer -Endpoints $endpoints -InternalPort $intPort -ExternalPort $extPort -Vip $vip -DSR -Verbose ..." -ForegroundColor Green
		CreateLoadBalancer -Endpoints $endpoints -InternalPort $intPort -ExternalPort $extPort -Vip $vip -DSR -Verbose
	}
	Write-Host "Create IPV4 loadbalancer completed ... Endpoints : $endpoints ..." -ForegroundColor Green
	Start-Sleep 3
	Write-Host "Create singlestack service completed ..." -ForegroundColor Green
}

function CreateDualStackService() {
	param(
		[parameter(Mandatory=$true)][string] $svcName,
		[parameter(Mandatory=$false)][string] $createLB="True",
		[parameter(Mandatory=$false)][string] $enableDSR="True",
		[parameter(Mandatory=$false)][string] $vip = $Global:ServiceVip,
		[parameter(Mandatory=$false)][string] $vip6 = $Global:ServiceVipV6,
		[parameter(Mandatory=$false)][int] $intPort = 4444,
		[parameter(Mandatory=$false)][int] $extPort = 4444,
		[parameter(Mandatory=$true)][int] $ipStartIndex,
        [parameter(Mandatory=$false)][int] $podCount=1,
		[parameter(Mandatory=$false)][string] $gatewayV4,
		[parameter(Mandatory=$false)][string] $gatewayV6,
		[parameter(Mandatory=$false, HelpMessage="Eg: 10.0.0.1-14::1,10.0.0.2-14::2")][string[]] $endpointList
    )
	
	$endpoints = @()
	$networkId = ((Get-HnsNetwork | Where-Object Name -EQ $k8sL2bridgeNetworkName).ID)
	
	foreach($ep in $endpointList) {
		$epArray = ($ep).Split("-")
		$epName = "EP-"+$epArray[0].Replace(".","-")
		$ipv4EP = $epArray[0]
		$ipv6EP = $epArray[1]
		Write-Host "Create Endpoint : $epName called..." 
		New-HnsEndpoint -NetworkId $networkId -Name $epName -IPAddress $ipv4EP -PrefixLength 24 -IPv6Address $ipv6EP -IPv6PrefixLength 64 -GatewayAddress $gatewayV4 -GatewayAddressV6 $gatewayV6 -MacAddress $dummyMac -RemoteEndpoint -EnableOutboundNat
		Start-Sleep 3
		$endpoint = (Get-HnsEndpoint | Where-Object Name -EQ $epName).ID
		$endpoints = $endpoints + $endpoint
		Write-Host "Create Endpoint : $epName completed... New Endpoint : $endpoint, Endpoints : $endpoints" 
	}
	
	Write-Host "Create dualstack service called ..." -ForegroundColor Green
	for($i = 1; $i -le $podCount; $i++) {
		$podName = $svcName + "-pod-" + $i
		$ipOctect = $ipStartIndex + $i - 1
		$ipv4Address = $IPV4AddressPrefix + $ipOctect
		$ipv6Address = $IPV6AddressPrefix + $ipOctect
		Write-Host "Executing command : CreatePod -podName $podName -ipv4Address $ipv4Address ipv6Address $ipv6Address ..." -ForegroundColor Green
		$endpoint = (CreatePod -podName $podName -ipv4Address $ipv4Address -ipv6Address $ipv6Address)
		$endpoints += $endpoint
		Start-Sleep 3
	}
	
	if($createLB -EQ "False") {
		Write-Host "createLB is False, so no loadbalancer will be created ..." -ForegroundColor Green
		return
	}
	
	Write-Host "Create IPV4 loadbalancer called ..."
	if($enableDSR -EQ "False") {
		Write-Host "Executing command :  CreateLoadBalancer -Endpoints $endpoints -InternalPort $intPort -ExternalPort $extPort -Vip $vip -Verbose ..." -ForegroundColor Green
		CreateLoadBalancer -Endpoints $endpoints -InternalPort $intPort -ExternalPort $extPort -Vip $vip -Verbose
	} else {
		Write-Host "Executing command :  CreateLoadBalancer -Endpoints $endpoints -InternalPort $intPort -ExternalPort $extPort -Vip $vip -DSR -Verbose ..." -ForegroundColor Green
		CreateLoadBalancer -Endpoints $endpoints -InternalPort $intPort -ExternalPort $extPort -Vip $vip -DSR -Verbose
	}
	Write-Host "Create IPV4 loadbalancer completed ... Endpoints : $endpoints ..." -ForegroundColor Green
	Start-Sleep 3
	Write-Host "Create IPV6 loadbalancer called ..." -ForegroundColor Green
	if($enableDSR -EQ "False") {
		Write-Host "Executing command :  CreateLoadBalancer -Endpoints $endpoints -InternalPort $intPort -ExternalPort $extPort -Vip $vip6 -IPv6 -Verbose ..." -ForegroundColor Green
		CreateLoadBalancer -Endpoints $endpoints -InternalPort $intPort -ExternalPort $extPort -Vip $vip6 -IPv6 -Verbose
	} else {
		Write-Host "Executing command :  CreateLoadBalancer -Endpoints $endpoints -InternalPort $intPort -ExternalPort $extPort -Vip $vip6 -DSR -IPv6 -Verbose ..." -ForegroundColor Green
		CreateLoadBalancer -Endpoints $endpoints -InternalPort $intPort -ExternalPort $extPort -Vip $vip6 -DSR -IPv6 -Verbose
	}
	
	Write-Host "Create IPV6 loadbalancer completed ... Endpoints : $endpoints ..." -ForegroundColor Green
	Write-Host "Create dualstack service completed ..." -ForegroundColor Green
}

function CleanupContainersAndEndPoints() {
	Write-Host "Cleanup containers called ..." -ForegroundColor Green
	CleanupContainers -ErrorAction Ignore
	Start-Sleep 2
	Write-Host "Cleanup containers completed ..." -ForegroundColor Green
	Write-Host "Cleanup endpoints called ..." -ForegroundColor Green
	Get-HnsEndpoint | Remove-HnsEndpoint -ErrorAction Ignore
	Start-Sleep 3
	Write-Host "Cleanup endpoints completed ..." -ForegroundColor Green
	Write-Host "Cleanup policies called ..." -ForegroundColor Green
	Get-HnsPolicyList | Remove-HnsPolicyList -ErrorAction Ignore
	Start-Sleep 2
	Write-Host "Cleanup policies completed ..." -ForegroundColor Green
}

function CleanupAll() {
	Write-Host "Cleanup all called ..." -ForegroundColor Green
	crictl rmp -af
	CleanupContainersAndEndPoints
	Write-Host "Cleanup all completed ..." -ForegroundColor Green
	Write-Host "Cleanup HnsNetworks called ..." -ForegroundColor Green
	Get-HnsNetwork | Remove-HnsNetwork -ErrorAction Ignore
	Write-Host "Cleanup HnsNetworks completed ..." -ForegroundColor Green
}