$ScriptPath = Split-Path $MyInvocation.MyCommand.Path

Import-Module $ScriptPath\HNS.Common.Pester.psm1 -Force -Verbose:$false -DisableNameChecking

$Global:UsePreExistingNetwork = $false
$Global:L2BridgeNetworkName = "l2bridgenetwork"
$Global:DummyTestSubnet = "9.0.0.0/24"
$Global:DummyTestGateway = "9.0.0.1"
$Global:TestSubnet = "10.0.0.0/24"
$Global:TestGateway = "10.0.0.1"
$Global:TestL2BridgeGateway = "10.0.0.2"
$Global:TestIPAddress = "10.0.0.10"
$Global:TestPrefixLength = 24
$Global:ServiceVip = "14.0.0.14"
$Global:ServiceVipSubnet = "14.0.0.0/8";
$Global:TestMacAddress = "12-34-56-78-9a-bc"
$Global:DockerSwarmDefaultAddressPool = "20.20.0.0/16"
$Global:PodJsonPath = "C:\Jsons"

#
# For ARP IPv6 Load test
# Set DummyTestSubnetV6 to fd00::00/120 and DummyTestGatewayV6 to fd00::01
# Assign ip address fd00::1 to the external NIC on this machine and fd00::2 (or something in the fd00::00/120 range) to the 2nd/remote machine
# Use the command "CreatePrimaryL2BridgeNetwork -IsDualStack" to create L2bridge that spans IPv4 and IPv6 networks
#
$Global:DummyTestSubnetV6 = "90::00/64"
$Global:DummyTestGatewayV6 = "90::01"
$Global:TestSubnetV6 = "10::00/64"
$Global:TestGatewayV6 = "10::01"
$Global:TestL2BridgeGatewayV6 = "10::02"
$Global:TestIPAddressV6 = "10::10"
$Global:TestPrefixLengthV6 = 64
$Global:ServiceVipV6 = "14::14"
$Global:ServiceVipSubnetV6 = "14::00/64";

[runspacefactory]::CreateRunspacePool()
$SessionState = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault()
$RunspacePool = [runspacefactory]::CreateRunspacePool(
    1, #Min Runspaces
    25 #Max Runspaces
)
$RunspacePool.Open()

<#
     Helper functions
#>

function WaitForManagementIp()
{
    param(
        [string] $network = "l2bridgenetwork"
    )

    Write-WTTLogMessage "Waiting for ManagementIP on [$network] "


    for ($i=0;$i -lt 360;$i++)
    {
        $hnsnetwork = Get-HnsNetwork -Verbose | Where-Object Name -EQ $network
        if (($null -ne $hnsnetwork) -and
            $hnsnetwork.ManagementIp -and
            (Get-NetIPAddress $hnsnetwork.ManagementIP -ErrorAction SilentlyContinue)
            )
        {
            return $hnsnetwork.ManagementIp
        }
        Start-Sleep -Milliseconds 1000
    }

    throw "Host is not connected to internet"

}

function CreatePrimaryL2BridgeNetwork()
{
    param(
        [string] $networkName = "primaryl2bridgenetwork",
        [parameter(Mandatory = $false)] [switch] $IsDualStack
    )

    $ip = WaitForHostConnectivity
    $hostinterface =  $ip.InterfaceAlias

    $AddressPrefixes = @($Global:DummyTestSubnet)
    $Gateways = @($Global:DummyTestGateway)

    $IPv6 = $IsDualStack.IsPresent
    if($IPv6)
    {
        $AddressPrefixes += $Global:DummyTestSubnetV6
        $Gateways += $Global:DummyTestGatewayV6
    }

    $network = New-HnsNetwork -Type L2Bridge -Name $networkName -AddressPrefix $AddressPrefixes -Gateway $Gateways -AdapterName $hostinterface -Verbose
    WaitForHostConnectivity -interfaceAlias "vEthernet ($hostinterface)"

    Write-WTTLogMessage "$networkName [$network] network created with subnet $Global:TestSubnet."
}

function CreateL2BridgeNetwork()
{
    param(
        [string] $networkName = "l2bridgenetwork",
        [string] $networkAdapterName,
        [string] $HostName = $null,
        [array] $Subnet,
        [array] $Gateway,
        [int] $Vlan = $Global:Vlan,
        [parameter(Mandatory = $false)] [switch] $IsDualStack,
        [parameter(Mandatory = $false)] [bool] $IsContainerD = $false
    )

    $IPv6 = $IsDualStack.IsPresent

    if (!$networkAdapterName)
    {
        $ip = WaitForHostConnectivity
        $networkAdapterName =  $ip.InterfaceAlias

        if ($networkAdapterName.StartsWith("vEthernet"))
        {
            $networkAdapterName = $null
        }
    }

    if($Subnet -eq $null)
    {
        $Subnet = @($Global:TestSubnet)

        if($IPv6)
        {
            $Subnet += $Global:TestSubnetV6
        }
    }

    if($Gateway -eq $null)
    {
        $Gateway = @($Global:TestGateway)

        if($IPv6)
        {
            $Gateway += $Global:TestGatewayV6
        }
    }

    if ($HostName)
    {
        Invoke-Command -ComputerName $hostName `
            -ScriptBlock {
                param(
                    [string] $networkName = "l2bridgenetwork",
                    [string] $networkAdapterName,
                    [string] $HostName,
                    [string] $Subnet,
                    [string] $Gateway,
                    [int] $Vlan
                )
                Import-Module c:\tools\SDNHelper.psm1 -DisableNameChecking
                CreateL2BridgeNetwork -networkName $networkName -networkAdapterName $networkAdapterName -Subnet $Subnet -Gateway $Gateway -Vlan $Vlan
                #New-HnsNetwork -Type L2Bridge -Name $networkName -AddressPrefix $Subnet -Gateway $Gateway -SubnetPolicies $subnetPolicies -Verbose
                #Restart-Service docker
            } -ArgumentList $networkName, $networkAdapterName, $null, $Subnet, $Gateway, $Vlan

    }
    else
    {
        $subnetPolicies = $null

        New-HnsNetwork -Type L2Bridge -Name $networkName -AddressPrefix $Subnet -Gateway $Gateway -Vlan $Vlan -AdapterName $networkAdapterName -Verbose
        # Restart docker to pick up the network
        if ($IsContainerD -eq $false)
        {
            Restart-Service docker
        }
    }
}

function CreateKubernetesL2BridgeNetwork()
{
    param(
        [string] $networkName = "l2bridgenetwork",
        [string] $HostName = $null,
        [array] $Subnet = $null,
        [array] $Gateway = $null,
        [string] $PodGateway = $Global:TestL2BridgeGateway,
        [string] $PodGatewayV6 = $null,
        [int] $Vlan = $Global:Vlan,
        [parameter(Mandatory = $false)] [switch] $IsDualStack,
        [parameter(Mandatory = $false)] [bool] $IsContainerD
    )

    $IPv6 = $IsDualStack.IsPresent

    $ip = WaitForHostConnectivity
    $hostinterface =  $ip.InterfaceAlias

    if($Subnet -eq $null)
    {
        $Subnet = @($Global:TestSubnet)

        if($IPv6)
        {
            $Subnet += $Global:TestSubnetV6
        }
    }

    if($Gateway -eq $null)
    {
        $Gateway = @($Global:TestGateway)

        if($IPv6)
        {
            $Gateway += $Global:TestGatewayV6
        }
    }

    if([string]::IsNullOrEmpty($PodGatewayV6) -and $IPv6)
    {
        $PodGatewayV6 = $Global:TestL2BridgeGatewayV6
    }


    $subnetV4 = $null
    $subnetV6 = $null
    foreach($s in $subnet)
    {
        if($s.Contains(":"))
        {
            $subnetV6 = $s
        }
        else
        {
            $subnetV4 = $s
        }

        if($null -ne $subnetV4 -and $null -ne $subnetV6)
        {
            break
        }
    }


    $hnsnetwork = CreateL2BridgeNetwork -networkName $networkName -Vlan $Vlan -HostName $HostName -Subnet $Subnet -Gateway $Gateway -IsContainerD $IsContainerD

    CreateL2BridgeGatewayNic -networkId $hnsnetwork.Id -podEndpointGW $PodGateway -podEndpointGWV6 $PodGatewayV6

    AddRoutePodGwRoute -netInterface $hostinterface -destinationPrefix $subnetV4 -nextHop "0.0.0.0" -metric 270
    AddRoutePodGwRoute -netInterface $hostinterface -destinationPrefix $subnetV4 -nextHop $PodGateway -metric 300


    if($IPv6)
    {
        AddRoutePodGwRoute -netInterface $hostinterface -destinationPrefix $subnetV6 -nextHop "::" -metric 270
        AddRoutePodGwRoute -netInterface $hostinterface -destinationPrefix $subnetV6 -nextHop $PodGatewayV6 -metric 300
    }

    Write-WTTLogMessage ($hnsnetwork | ConvertTo-Json -Depth 10)

    return $hnsnetwork
}

function AddRoutePodGwRoute()
{
     param(
        [string] $netInterface,
        [string] $destinationPrefix,
        [string] $nextHop,
        [string] $metric
     )

    $route = Get-NetRoute -InterfaceAlias $netInterface -DestinationPrefix $destinationPrefix -NextHop $nextHop -ErrorAction SilentlyContinue
    if (!$route)
    {
        $out = New-NetRoute -InterfaceAlias $netInterface -DestinationPrefix $destinationPrefix -NextHop $nextHop -RouteMetric $metric
    }
}
function CreateL2BridgeGatewayNic()
{
    param(
        [string] $endpointName = "l2bridgenetworkgw",
        [Guid] $networkId,
        [string] $podEndpointGW,
        [string] $podEndpointGWV6
    )

    if([string]::IsNullOrEmpty($podEndpointGWV6))
    {
        $hnsEndpoint = New-HnsEndpoint  `
            -NetworkId $networkId `
            -Name $endpointName  `
            -IPAddress $podEndpointGW `
            -GatewayAddress "0.0.0.0" -Verbose
    }
    else
    {
        $hnsEndpoint = New-HnsEndpoint  `
            -NetworkId $networkId `
            -Name $endpointName  `
            -IPAddress $podEndpointGW `
            -GatewayAddress "0.0.0.0" `
            -IPv6Address $podEndpointGWV6 `
            -GatewayAddressV6 "::" -Verbose
    }

    Attach-HnsHostEndpoint -EndpointID $hnsEndpoint.Id -CompartmentID 1 -Verbose
    $vnicName = "vEthernet ($endpointName)"
    # enable Forwarding to true
    netsh int ipv4 set int "$vnicName" for=en

    if($podEndpointGWV6 -ne $null)
    {
        netsh int ipv6 set int "$vnicName" for=en
    }
}

function AttachL2BridgeEndpoint(
        [string] $containerName = $null,
        [string] $networkName = "l2bridgenetwork",
        [string] $endpointName = "testendpoint",
        [string] $IPAddress = $Global:TestIPAddress,
        [string] $IPAddressV6 = $Global:TestIPAddressV6,
        [switch] $enableOutboundNat,
        [HashTable][parameter(Mandatory=$false)] $InboundNatPolicy, #  @ {"InternalPort" = "80"; "ExternalPort" = "8080"}
        [HashTable][parameter(Mandatory=$false)] $PAPolicy, #  @ {"PA" = "1.2.3.4"; }
        [switch] $IsDualStack
)
{
    $network = GetL2BridgeNetwork $networkName
    $managementIP = $network.ManagementIP
    # Create Endpoint

    if(-not $IsDualStack.IsPresent)
    {
        $endpoint = New-HNSEndpoint -NetworkId $network.ID `
                        -Name $endpointName `
                        -IPAddress $IPAddress `
                        -EnableOutboundNat:$enableOutboundNat.IsPresent `
                        -DNSServerList (Get-HostDnsServers -IPAddress $managementIP) `
                        -InboundNatPolicy $InboundNatPolicy `
                        -PAPolicy $PAPolicy `
                        -Verbose
    }
    else
    {
        $endpoint = New-HNSEndpoint -NetworkId $network.ID `
                -Name $endpointName `
                -IPAddress $IPAddress `
                -IPv6Address $IPAddressV6 `
                -EnableOutboundNat:$enableOutboundNat.IsPresent `
                -DNSServerList (Get-HostDnsServers -IPAddress $managementIP) `
                -InboundNatPolicy $InboundNatPolicy `
                -InboundNatPolicyV6 $InboundNatPolicy `
                -PAPolicy $PAPolicy `
                -Verbose
    }

    if (-not $endpoint)
    {
        throw "Endpoint creation failed!!!"
    }

    Write-WTTLogMessage ($endpoint | ConvertTo-Json -Depth 10)

    if ($containerName)
    {
        $out = HotAdd-NetworkEndpoint-HCSContainer -Id $(GetContainerId $containerName) -EndpointId $endpoint.ID -Verbose
    }
    return $($endpoint.ID)
}

function GetL2BridgeNetwork (
    [string] $networkName = "l2bridgenetwork"
)
{
    $network = Get-HnsNetwork | Where-Object Name -eq $networkName

    if (!$network) {
        throw "unable to find network with $networkName"
    }

    return $network
}

function ConvertTo-DecimalIP
{
  param(
    [Parameter(Mandatory = $true, Position = 0)]
    [Net.IPAddress] $IPAddress
  )

  $i = 3; $DecimalIP = 0;
  $IPAddress.GetAddressBytes() | ForEach-Object {
    $DecimalIP += $_ * [Math]::Pow(256, $i); $i--
  }
  return [UInt32]$DecimalIP
}

function ConvertTo-DottedDecimalIP
{
  param(
    [Parameter(Mandatory = $true, Position = 0)]
    [Uint32] $IPAddress
  )
    $DottedIP = $(for ($i = 3; $i -gt -1; $i--)
    {
      $Remainder = $IPAddress % [Math]::Pow(256, $i)
      ($IPAddress - $Remainder) / [Math]::Pow(256, $i)
      $IPAddress = $Remainder
    })
    return [String]::Join(".", $DottedIP)
}

function ConvertTo-MaskLength
{
  param(
    [Parameter(Mandatory = $True, Position = 0)]
    [Net.IPAddress] $SubnetMask
  )

    $Bits = "$($SubnetMask.GetAddressBytes() | ForEach-Object {
      [Convert]::ToString($_, 2)
    } )" -replace "[\s0]"

    return $Bits.Length
}

function ConvertTo-DottedDecimalIP
{
  param(
    [Parameter(Mandatory = $true, Position = 0)]
    [Uint32] $IPAddress
  )
    $DottedIP = $(for ($i = 3; $i -gt -1; $i--)
    {
      $Remainder = $IPAddress % [Math]::Pow(256, $i)
      ($IPAddress - $Remainder) / [Math]::Pow(256, $i)
      $IPAddress = $Remainder
    })
    return [String]::Join(".", $DottedIP)
}

function ConvertTo-MaskLength
{
  param(
    [Parameter(Mandatory = $True, Position = 0)]
    [Net.IPAddress] $SubnetMask
  )

    $Bits = "$($SubnetMask.GetAddressBytes() | ForEach-Object {
      [Convert]::ToString($_, 2)
    } )" -replace "[\s0]"

    return $Bits.Length
}

function Get-MgmtSubnet(
    [string] $networkName = "l2bridgenetwork"
)
{
    $network = GetL2BridgeNetwork $networkName

    $ip = (Get-NetIPAddress -IpAddress $network.ManagementIP -AddressFamily IPv4)
    $addr = $ip.IPAddress
    $guid = (Get-NetAdapter | Where-Object InterfaceIndex -eq $($ip.InterfaceIndex)).InterfaceGuid
    $regPath = 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\' + $guid
    $regContent = $regContent =(Get-Item -Path $regPath)
    $subnetProperty = $regContent.GetValueNames() -like "*subnetMask"
    $mask = $regContent.GetValue($subnetProperty)
    $mgmtSubnet = (ConvertTo-DecimalIP $addr) -band (ConvertTo-DecimalIP $mask)
    $mgmtSubnet = ConvertTo-DottedDecimalIP $mgmtSubnet
    return "$mgmtSubnet/$(ConvertTo-MaskLength $mask)"
}

function Get-MgmtSubnetV6(
    [string] $networkName = "l2bridgenetwork"
)
{
    $network = GetL2BridgeNetwork $networkName
    $ipaddress = $network.ManagementIPv6

    $ip =  [System.Net.IPAddress]::Parse($ipaddress)
    $bytes = $ip.GetAddressBytes()

    $prefix = "{0:X2}" -f $bytes[0]
    1..7 | ForEach-Object {
        if($_ %2 -eq 0)
        {
            $prefix += ":"
        }
        $prefix += "{0:X2}" -f $bytes[$_]
    }

    $prefix += "::/64"
    return $prefix
}

function AttachKubernetesL2BridgeEndpoint (
    [string] $containerName,
    [string] $networkName = "l2bridgenetwork",
    [parameter(Mandatory=$false)][string] $ipAddress = $Global:TestIPAddress,
    [parameter(Mandatory = $false)] [uint16] $PrefixLength = $Global:TestPrefixLength,
    [parameter(Mandatory=$false)][string] $gateway = $Global:TestL2BridgeGateway,
    [parameter(Mandatory=$false)][string] $ipV6Address = $Global:TestIPAddressV6,
    [parameter(Mandatory = $false)] [uint16] $PrefixLengthV6 = $Global:TestPrefixLengthV6,
    [parameter(Mandatory=$false)][string] $gatewayV6 = $Global:TestL2BridgeGatewayV6,
    [parameter(Mandatory=$false)][switch] $enableOutboundNat,
    [switch] $createForElb,
    [switch] $useRoute,
    [switch] $useExternalVip,
    [switch] $crossHost,
    [HashTable][parameter(Mandatory=$false)] $InboundNatPolicy, #  @ {"InternalPort" = "80"; "ExternalPort" = "8080"}
    [HashTable][parameter(Mandatory=$false)] $PAPolicy, #  @ {"PA" = "1.2.3.4"; }
    [parameter(Mandatory = $false)] [switch] $IsDualStack
)
{
    $network = GetL2BridgeNetwork $networkName

    $routePrefixes = @();
    $natexceptions = $null;
    $managementIP = $network.ManagementIp

    $IPv6 = $IsDualStack.IsPresent

    if($IPv6)
    {
        $managementIPv6 = $network.ManagementIpv6
    }

    if($useExternalVip.IsPresent)
    {
        $routePrefixes += $Global:ServiceVipSubnet
        $natexceptions = @($Global:ServiceVipSubnet)

        if($IPv6)
        {
            $routePrefixes += $Global:ServiceVipSubnetV6
            $natexceptions += $Global:ServiceVipSubnetV6
        }
    }

    if ($createForElb.IsPresent){
        $routePrefixes += @("$managementIP/32")

        if($IPv6)
        {
            $routePrefixes += @("$managementIPv6/128")
        }
    }

    if (!$useRoute.IsPresent)
    {
        $routePrefixes = $null;
    }

    if ($crossHost.IsPresent)
    {
        $natexceptions += Get-MgmtSubnet $networkName
        if($IPv6)
        {
            $natexceptions += Get-MgmtSubnetV6 $networkName
        }
    }

    if(-not $IPv6)
    {
        $ipV6Address = $null
        $gatewayV6 = $null
        $PrefixLengthV6 = 0

    }

    # Create Endpoint
    $endpoint = New-HNSEndpoint -NetworkId $network.ID `
                    -IPAddress $ipAddress `
                    -PrefixLength $PrefixLength  `
                    -IPV6Address $ipV6Address `
                    -IPv6PrefixLength $PrefixLengthV6  `
                    -EnableOutboundNat:$enableOutboundNat `
                    -RemoteEndpoint:$remoteEndpoint `
                    -GatewayAddress $gateway `
                    -GatewayAddressV6 $gatewayV6 `
                    -OutboundNatExceptions  $natexceptions `
                    -RoutePrefixes $routePrefixes `
                    -DNSServerList (Get-HostDnsServers -IPAddress $managementIP) `
                    -InboundNatPolicy $InboundNatPolicy `
                    -PAPolicy $PAPolicy `
                    -Verbose
    if (-not $endpoint)
    {
        throw "Endpoint creation failed!!!"
    }

    Write-WTTLogMessage ($endpoint | ConvertTo-Json -Depth 10)

    if (!$containerName)
    {
        throw "ContainerName is empty!!!"
    }
    $out = HotAdd-NetworkEndpoint-HCSContainer -Id $(GetContainerId $containerName) -EndpointId $endpoint.ID -Verbose
    return ($endpoint.ID)
}

function CreateRemoteEndpoint(
    [string] $networkName = "l2bridgenetwork",
    [string] $IPAddress = $Global:TestIPAddress,
    [string] $remoteEndpointMacAddress = $Global:TestMacAddress,
    [string] $IPV6Address = $Global:TestIPAddressV6,
    [switch] $IsDualStack
)
{
    $network = GetL2BridgeNetwork $networkName

    # Create Endpoint
    $endpoint = New-HNSEndpoint -NetworkId $network.ID `
                    -IPAddress $IPAddress `
                    -RemoteEndpoint `
                    -MacAddress $remoteEndpointMacAddress `
                    -Verbose
    if (-not $endpoint)
    {
        throw "Remote Endpoint creation failed!!!"
    }
    return $endpoint
}

function RemovePrimaryL2BridgeNetwork()
{
    param(
        [string] $networkName = "primaryl2bridgenetwork"
    )

    Execute-ContainerCommand -command "network rm $networkName" -ignoreExceptionMessage "No such network"
    Write-WTTLogMessage "$networkName network removed."
}

function RemoveL2BridgeNetwork()
{
    param(
        [string] $HostName = $null,
        [string] $networkName = "l2bridgenetwork",
        [parameter(Mandatory = $false)] [bool] $IsContainerD
    )

    if ($HostName)
    {
        Invoke-Command -ComputerName $HostName `
            -ScriptBlock {
                param(
                    [string] $networkName = "l2bridgenetwork"
                )
                Import-Module c:\tools\SDNHelper.psm1 -DisableNameChecking
                RemoveL2BridgeNetwork -networkName $networkName
            } -ArgumentList $networkName
    }
    else
    {
        try {
            GetL2BridgeNetwork -networkName $networkName | Remove-HnsNetwork
        } catch {
            Write-Output "Ignoring exception"
        }

        if ($IsContainerD -eq $false)
        {
            Restart-Service docker
        }
        Write-WTTLogMessage "$networkName network removed."
    }
}

function CreateContainerWithoutNetwork()
{
    param(
        [string] $containerName,
        [ValidateSet('process', 'hyperv')]
        [parameter(Mandatory = $false)]
        [string] $isolation = 'process'
    )

    CreateContainerWithNetwork -containerName $containerName -networkName "none" -isolation $isolation
}

function CreateL2BridgeContainer()
{
    param(
        [string] $containerName,
        [ValidateSet('process', 'hyperv')]
        [parameter(Mandatory = $false)]
        [string] $isolation = 'process',
        [string] $networkName = "l2bridgenetwork",
        [parameter(Mandatory=$false)][string] $ipAddress = $Global:TestIPAddress,
        [parameter(Mandatory = $false)] [uint16] $PrefixLength = $Global:TestPrefixLength,
        [parameter(Mandatory=$false)][string] $gateway = $Global:TestL2BridgeGateway,
        [parameter(Mandatory=$false)][string] $ipV6Address = $Global:TestIPAddressV6,
        [parameter(Mandatory = $false)] [uint16] $PrefixLengthV6 = $Global:TestPrefixLengthV6,
        [parameter(Mandatory=$false)][string] $gatewayV6 = $Global:TestL2BridgeGatewayV6,
        [parameter(Mandatory=$false)][switch] $enableOutboundNat,
        [switch] $createForElb,
        [switch] $useRoute,
        [switch] $crossHost,
        [switch] $useExternalVip,
        [HashTable][parameter(Mandatory=$false)] $InboundNatPolicy, #  @ {"InternalPort" = "80"; "ExternalPort" = "8080"}
        [HashTable][parameter(Mandatory=$false)] $PAPolicy, #  @ {"PA" = "1.2.3.4"; },
        [parameter(Mandatory = $false)] [switch] $IsDualStack
    )

    $dockerId = CreateContainerWithoutNetwork -containerName $containerName  -isolation $isolation
    return AttachKubernetesL2BridgeEndpoint -networkName $networkName `
                                            -ipAddress $ipAddress  `
                                            -prefixLength $PrefixLength  `
                                            -gateway $gateway  `
                                            -ipV6Address $ipV6Address  `
                                            -prefixLengthV6 $PrefixLengthV6  `
                                            -gatewayV6 $gatewayV6  `
                                            -containerName $containerName `
                                            -enableOutboundNat:$enableOutboundNat `
                                            -createForElb:$createForElb `
                                            -useExternalVip:$useExternalVip `
                                            -useRoute:$useRoute `
                                            -crossHost:$crossHost `
                                            -InboundNatPolicy $InboundNatPolicy `
                                            -PAPolicy $PAPolicy `
                                            -IsDualStack:$IsDualStack.IsPresent `
                                            -Verbose
}

function CreateContainerDPodConfig(
    [string] $podName,
    [string] $installDirectory
)
{
    return (Get-Content -Path ".\pod.template.json" -Raw).
                Replace('{{SANDBOX_NAME}}', $podName)
}

function CreateContainerDContainerConfig(
    [string] $containerName,
    [string] $image,
    [string] $installDirectory
)
{
    return (Get-Content -Path ".\wcow-container.template.json" -Raw).
                Replace('{{CONTAINER_NAME}}', $containerName).
                Replace('{{IMAGE}}', $image)
}

function CreateContainerDEndpointNetworkPolicies(
    [string] $networkName = "l2bridgenetwork",
    [parameter(Mandatory=$false)][string] $gateway = $Global:TestL2BridgeGateway,
    [parameter(Mandatory=$false)][switch] $enableOutboundNat,
    [switch] $createForElb,
    [switch] $useRoute,
    [switch] $crossHost,
    [switch] $useExternalVip,
    [HashTable][parameter(Mandatory=$false)] $inboundNatPolicy, #  @ {"InternalPort" = "80"; "ExternalPort" = "8080"}
    [HashTable][parameter(Mandatory=$false)] $paPolicy #  @ {"PA" = "1.2.3.4"; }
)
{
    $policies = @();
    $routePrefixes = @();
    $natexceptions = $null;
    $managementIP = $network.ManagementIp

    if($useExternalVip.IsPresent)
    {
        $routePrefixes += $Global:ServiceVipSubnet
        $natexceptions = @($Global:ServiceVipSubnet)
    }

    if ($crossHost.IsPresent)
    {
        $natexceptions += Get-MgmtSubnet $networkName
    }

    if ($createForElb.IsPresent)
    {
        $routePrefixes += @("$managementIP/32")
    }

    if (!$useRoute.IsPresent)
    {
        $routePrefixes = $null;
    }

    if ($enableOutboundNat.IsPresent)
    {
        $Settings = @{}
        if ($natexceptions)
        {
            $ExceptionList = $null
            foreach ($exp in $natexceptions)
            {
                if(-not $exp.Contains(":"))
                {
                    if($null -eq $ExceptionList)
                    {
                        $ExceptionList = @()
                    }

                    $ExceptionList += $exp
                }
            }
            $Settings += @{Exceptions = $ExceptionList}
        }

        $policies += @{
            Type = "OutBoundNAT";
            Settings = $Settings;
        };
    }

    if ($routePrefixes)
    {
        foreach ($routeprefix in $routePrefixes)
        {
            $rPolicy = @{
                DestinationPrefix = $routeprefix;
                NeedEncap = $true;
            }

            $policies += @{
                Type = "SDNRoute";
                Settings = $rPolicy;
            };
        }
    }

    if ($inboundNatPolicy)
    {
        $natFlags = 0;
        if ($inboundNatPolicy["LocalRoutedVip"])
        {
            $natFlags = $natFlags -bor [NatFlags]::LocalRoutedVip
        }

        $policies += @{
            Type = "PortMapping";
            Settings = @{
                InternalPort = $inboundNatPolicy["InternalPort"];
                ExternalPort = $inboundNatPolicy["ExternalPort"];
                Flags = $natFlags;
            };
        }
    }

    if ($paPolicy)
    {
        $policies += @{
            Type = "ProviderAddress";
            Settings = @{
                ProviderAddress = $paPolicy["PA"];
            }
        }
    }

    # $policyJson = convertto-json $policies -Depth 10

    # return $policyJson
    return $policies
}

function ContainerDContainerInitializeCNIConfig(
    [string] $networkName,
    [string] $networkType,
    [string] $cniConfigDirectory
)
{
    $network = GetL2BridgeNetwork $networkName
    $managementIP = $network.ManagementIP

    $cdc = (Get-Content -Path ".\sdnbridgecni.template.conf" -Raw).
                Replace('{{NAME}}', $networkName).
                Replace('{{TYPE}}', $networkType)

    $dnsServers = Get-HostDnsServers -IPAddress $managementIP
    $cdc = $cdc.Replace('{{DNSSERVER}}', $dnsServers)
            
    $cdc = $cdc.Replace('{{GATEWAY}}', $Global:TestL2BridgeGateway)

    $cniFileName = ($cniConfigDirectory + "\" + $networkName + "_cni.conf")

    if (Test-Path -Path "$cniFileName")
    {
        Remove-Item -Force -Path "$cniFileName"
    }

    $cdc | Out-File -FilePath $cniFileName -Encoding ascii
}
function CreateContainerDContainerWithPolicy(
    [string] $containerName,
    [string] $installDirectory,
    [string] $cniConfigDirectory,
    [string] $networkName = "l2bridgenetwork",
    [string] $networkType,
    [parameter(Mandatory=$false)][string] $gateway = $Global:TestL2BridgeGateway,
    [parameter(Mandatory=$false)][switch] $enableOutboundNat,
    [switch] $createForElb,
    [switch] $useRoute,
    [switch] $crossHost,
    [switch] $useExternalVip,
    [string] $image,
    [HashTable][parameter(Mandatory=$false)] $InboundNatPolicy, #  @ {"InternalPort" = "80"; "ExternalPort" = "8080"}
    [HashTable][parameter(Mandatory=$false)] $PAPolicy, #  @ {"PA" = "1.2.3.4"; },
    [HashTable][parameter(Mandatory=$false)] $outputs
)
{
    $network = GetL2BridgeNetwork $networkName

    $podName = ($containerName + "_pod")
    $podConfig = CreateContainerDPodConfig -podName $podName -installDirectory $installDirectory
    $containerConfig = CreateContainerDContainerConfig -containerName $containerName `
                                                       -image $image `
                                                       -installDirectory $installDirectory

    # $cdc = ContainerDContainerInitializeCNIConfig -networkName $networkName -networkType $networkType

    $policies = CreateContainerDEndpointNetworkPolicies -networkName $networkName `
                                                        -gateway $gateway `
                                                        -enableOutboundNat:$enableOutboundNat `
                                                        -createForElb:$createForElb `
                                                        -useRoute:$useRoute `
                                                        -crossHost:$crossHost `
                                                        -useExternalVip:$useExternalVip `
                                                        -inboundNatPolicy $InboundNatPolicy `
                                                        -paPolicy $PAPolicy
    
    # $cdc = $cdc.Replace('{{ADDITIONALARGS}}', $policies)

    $managementIP = $network.ManagementIP

    $podFileNameOld = ($installDirectory + "\" + $podName + "_pod.json")
    $podConfig | Out-File -FilePath $podFileNameOld -Encoding ascii

    $outputs["podFile"] = $podFileNameOld
    $outputs["podName"] = $podName

    $containerFileNameOld = ($installDirectory + "\" + $containerName + "_container.json")
    $containerConfig |  Out-File -FilePath $containerFileNameOld -Encoding ascii

    $outputs["containerFile"] = $containerFileNameOld

    # $outputs["cniFile"] = $cniFileName
	Copy-Item -Path "$podFileNameOld" -Destination "$PodJsonPath" -Recurse -Force
	Copy-Item -Path "$containerFileNameOld" -Destination "$PodJsonPath" -Recurse -Force
	
	$podFileName = ($PodJsonPath + "\" + $podName + "_pod.json")
	$containerFileName = ($PodJsonPath + "\" + $containerName + "_container.json")
	
    #.\crictl.exe runp --runtime runhcs-wcow-process pod.json
    $podId = Execute-ContainerDCommand "runp --runtime runhcs-wcow-process $podFileName"

    Write-WTTLogMessage "Pod created, name $podName, config $podFileName, id $podId"

    $outputs["podID"] = $podId
	

    #.\crictl.exe create <POD-ID> .\wcow-container.json .\pod.json 
    $containerId = Execute-ContainerDCommand "create $podId $containerFileName $podFileName"

    Write-WTTLogMessage "Container created, name $containerName, config $containerConfig, id $containerId"

    $outputs["containerID"] = $containerId

    #.\crictl.exe start <CONTAINER-ID> 
    Execute-ContainerDCommand "start $containerId" | Out-Null

    Write-WTTLogMessage "Container $containerId started"

    #CNI appends _<network name> to the Id
    $hnsPodName = ($podId + "_" +$networkName)
    $endpointObj = Get-HnsEndpoint | Where-Object Name -eq $hnsPodName
    $outputs["endpointObj"] = $endpointObj

    $Settings = @{
        Policies = @();
    }
    $Settings.Policies = $policies

    AddEndpointPolicy -EndpointId $endpointObj.ID -Settings $Settings

    return $endpointObj.ID
}

function RemoveL2BridgeContainer()
{
    param(
        [string] $containerName,
        [parameter(Mandatory=$false)][string] $ipAddress = $Global:TestIPAddress
    )
    CleanupContainer -ContainerName $ContainerName
    $ep = Get-HnsEndpoint | Where-Object IpAddress -eq $ipAddress
    if ($ep) { Remove-HnsEndpoint $ep }
}

function CreateL2BridgeSharedContainer()
{
    param(
        [string] $containerName,
        [ValidateSet('process', 'hyperv')]
        [parameter(Mandatory = $false)]
        [string] $isolation = 'process',
        [string] $primaryContainerName,
        [Guid] $EndpointId
    )
    CreateContainerWithNetwork -containerName $containerName -isolation $isolation -networkName "container:$primaryContainerName"
    HotAdd-NetworkEndpoint-HCSContainer -Id $(GetContainerId $containerName) -EndpointId $EndpointId
}

function CreateL2BridgePod()
{
    param(
        [string] $containerName,
        [ValidateSet('process', 'hyperv')]
        [parameter(Mandatory = $false)]
        [string] $isolation = 'process',
        [int] $WorkloadContainerCount,
        [string] $IpAddress,
        [string] $ipV6Address,
        [parameter(Mandatory = $false)]
        [switch] $IsDualStack
    )

    $cmdArgsList = New-Object System.Collections.ArrayList
    $cont1 = "$containerName"
    $endpoint = CreateL2BridgeContainer -containerName $cont1 -isolation $isolation -enableOutboundNat `
        -ipAddress $IpAddress -ipV6Address $ipV6Address -IsDualStack:$IsDualStack.IsPresent

    foreach ($i in 1..$WorkloadContainerCount)
    {
        $cont2 = "$cont1-shared-${i}"
        $cmdArgs = @("CreateL2BridgeSharedContainer", "-containerName", $cont2, "-isolation", $isolation , "-primaryContainerName", $cont1,  "-EndpointId", $endpoint)
        $cmdArgsList.Add($cmdArgs)
    }

    ExecuteParallelCmdsInRunSpace -CmdArgsList $cmdArgsList -workingDir $workingDir
}

function RemoveL2BridgePod()
{
    param(
        [string] $containerName,
        [int] $WorkloadContainerCount,
        [string] $IpAddress
    )

    $cmdArgsList = New-Object System.Collections.ArrayList
    $cont1 = "$containerName"
    $cmdArgsList.Add(@("RemoveL2BridgeContainer", "-containerName", $cont1, "-ipAddress", $IpAddress))
    foreach ($i in 1..$WorkloadContainerCount)
    {
        $cont2 = "$cont1-shared-${i}"
        $cmdArgs = @("CleanupContainer", "-containerName", $cont2)
        $cmdArgsList.Add($cmdArgs)
    }
    ExecuteParallelCmdsInRunSpace -CmdArgsList $cmdArgsList -workingDir $workingDir
}


function CreateL2BridgePods()
{
    param(
        [string] $containerNamePrefix,
        [ValidateSet('process', 'hyperv')]
        [parameter(Mandatory = $false)]
        [string] $isolation = 'process',
        [int] $PodCount,
        [int] $WorkloadCountPerPod,
        [parameter(Mandatory = $false)]
        [switch] $IsDualStack
    )

    $DualStackSwitch = '-IsDualStack:$false'
    if($IsDualStack.IsPresent)
    {
        $enableDualStack = '-IsDualStack:$true'
    }

    $cmdArgsList = New-Object System.Collections.ArrayList
    1..$PodCount | ForEach-Object {
        $cmdArgs = @("CreateL2BridgePod", "-containerName", "${containerNamePrefix}_${_}", "-isolation", $isolation, `
            "-IpAddress", "10.0.0.$(10 + ${_})", "-WorkloadContainerCount", $WorkloadCountPerPod,
            "-IpV6Address", "10::$(10 + ${_})", $enableDualStack);

        $cmdArgsList.Add($cmdArgs)
    }
    ExecuteParallelCmdsInRunSpace -CmdArgsList $cmdArgsList -workingDir $workingDir
}

function RemoveL2BridgePods()
{
    param(
        [string] $containerNamePrefix,
        [int] $PodCount,
        [int] $WorkloadCountPerPod
    )
    $cmdArgsList = New-Object System.Collections.ArrayList
    1..$PodCount | ForEach-Object {
        $cmdArgs = @("RemoveL2BridgePod", "-containerName", "${containerNamePrefix}_${_}", "-IpAddress", "10.0.0.$(10 + ${_})", "-WorkloadContainerCount", $WorkloadCountPerPod);
        $cmdArgsList.Add($cmdArgs)
    }
    ExecuteParallelCmdsInRunSpace -CmdArgsList $cmdArgsList -workingDir $workingDir
}

function JoinSwarm()
{
    param(
        [string] $managerIp = "127.0.0.1"
    )

    WaitForHostConnectivity
    Execute-ContainerCommand -command "swarm init --advertise-addr=$($managerIp) --listen-addr=$($managerIp):2377 --default-addr-pool=$($Global:DockerSwarmDefaultAddressPool)"

    ### Wait for Network creation to complete
    $ingressNetworkName = "ingress" # NOTE: Hardcoded
    $startTime = Get-Date
    $networkcreated = $false
    $WaitTimeInSeconds = 60
    do
    {
        $timeElapsed = $(Get-Date) - $startTime
        Write-Host "Waiting up to $WaitTimeInSeconds seconds for $ingressNetworkName network creation. Elapsed time: $timeElapsed"
        if ($($timeElapsed).TotalSeconds -ge $WaitTimeInSeconds)
        {
            throw "Fail to create the network in $WaitTimeInSeconds seconds"
        }

        Start-Sleep -s 1
        $networkId = (docker network inspect $ingressNetworkName | ConvertFrom-Json).Id
        $networkcreated =  $null -ne (Get-HnsNetwork | Where-Object Name -Match $networkId)
    }
    until ($networkcreated)
    ### Network creation complete
}

function CreateInternalOverlayNetwork()
{
    param(
        [string] $networkName = "test",
        [string] $managerIp = "127.0.0.1"
    )
    $ip = WaitForHostConnectivity
    $hostinterface =  $ip.InterfaceAlias
    $network = Execute-ContainerCommand -command "network create --driver overlay --attachable --internal --subnet $Global:TestSubnet  --gateway $Global:TestGateway $networkName"
    WaitForHostConnectivity -interfaceAlias "$hostinterface"
    Write-WTTLogMessage "$networkName [$network] network created with subnet $Global:TestSubnet."
}

function LeaveSwarm()
{
    Execute-ContainerCommand -command "swarm leave --force"
}
function RemoveInternalOverlayNetwork()
{
    param(
        [string] $networkName = "test"
    )

    Execute-ContainerCommand -command "network rm $networkName" -ignoreFailure
    Write-WTTLogMessage "$networkName network removed."
}
function CreateContainerWithNetwork()
{
    param(
        [string] $containerName,
        [string] $networkName,
        [string] $ip = "",
        [string] $dns = "",
        [string] $containerImageName = "iis",
        [string] $containerCmd = "cmd",
        [ValidateSet('process', 'hyperv')]
        [parameter(Mandatory = $false, Position = 0)]
        [string] $isolation = 'process',
        [string] $volmapping = "c:\tools:c:\tools",
        [string] $MAC = "",
        [string] $hostName = $null
    )

    $command = "create -t --rm --isolation=$isolation --name=$containerName --net=$networkName "

    if(-not [String]::IsNullOrEmpty($ip))
    {
        $command += "--ip $ip "
    }

    if(-not [String]::IsNullOrEmpty($dns))
    {
        $command += "--dns $dns "
    }

    if(-not [String]::IsNullOrEmpty($volmapping))
    {
        $command += "-v $volmapping "
    }

    if(-not [String]::IsNullOrEmpty($MAC))
    {
        $command += "--mac-address $MAC "
    }

    $command += "$containerImageName $containerCmd"

    Execute-ContainerCommand -command $command -hostName $hostName

    Write-WTTLogMessage "$containerName Container created."

    Execute-ContainerCommand -command "start $containerName" -hostName $hostName
    Write-WTTLogMessage "$containerName started."
}

function AddStaticNeighbor()
{
    param(
        [string] $containerId,
        [string] $ip,
        [string] $mac,
        [switch] $addGateway
    )

    $netadapter = GetNetAdapterFromContainer -container $containerId
    $isIpv6 = $ip.Contains(":")

    if($addGateway.IsPresent)
    {
        $destPrefix = "0.0.0.0/0"
        if($isIpv6)
        {
            $destPrefix = "::/0"
        }
        Execute-ContainerCommand -command "exec $containerId powershell New-NetRoute -DestinationPrefix $destPrefix -InterfaceIndex $netadapter -NextHop $ip " -ignoreFailure
    }

    $type = "ipv4"
    if($isIpv6)
    {
        $type = "ipv6"
    }

    Execute-ContainerCommand -command "exec $containerId cmd /c netsh int $type add neighbors $netadapter $ip $mac" -ignoreFailure
}

function AddStaticRoute()
{
    param(
        [string] $containerId,
        [string] $nextHop = "",
        [string] $prefix,
        [string] $interfaceIndex
    )

    $isIpv6 = $prefix.Contains(":")
    if(-not [String]::IsNullOrEmpty($containerId))
    {
        $netadapter = GetNetAdapterFromContainer -container $containerId
        $command = "New-NetRoute -DestinationPrefix $prefix -InterfaceIndex $netadapter"

        if(-not [String]::IsNullOrEmpty($nextHop))
        {
            $command += " -NextHop $nextHop"
        }

        Execute-ContainerCommand -command "exec $containerId powershell $command " -ignoreFailure
    }
    else
    {
        $type = "ipv4"
        if($isIpv6)
        {
            $type = "ipv6"
        }
        # there is some bug new net route is not working
        cmd /c "netsh interface $type add ro $prefix $interfaceIndex $nextHop"
    }
}

function TestExternalConnectivity()
{
    param(
        [string] $containerId,
        [string] $remoteHost = "www.msftconnecttest.com",
        [string] $remoteHostV6 = "ipv6.msftconnecttest.com",
        [string] $remoteHostPath = "/connecttest.txt",
        [string] $port = "80",
        [switch] $DisableTrace,
        [bool] $isIpv6,
        [bool] $isContainerD = $false
    )

    $startTime = Get-Date
    if (!$DisableTrace.IsPresent)
    {
        #DumpVfpPolicies -OutFileName "OutboundTo_${remoteHost}_${port}"
    }

    $destination = $remoteHost

    if($isIpv6)
    {
        $destination = $remoteHostV6
    }

    if ($isContainerD -eq $false)
    {
        $status = Execute-ContainerCommand -command "exec $containerId powershell (curl http://${destination}:${port}${remoteHostPath} -UseBasicParsing -DisableKeepAlive).StatusCode"
    }
    else
    {
        $status = Execute-ContainerDCommand -command "exec $containerId powershell (curl http://${destination}:${port}${remoteHostPath} -UseBasicParsing -DisableKeepAlive).StatusCode"
    }

    if($status -contains "200")
    {
        Write-WTTLogMessage "$remoteHost returned $status."
        $elapsedTime = ($(Get-Date) - $startTime).TotalSeconds
        Write-WTTLogMessage "Elapsed time [$elapsedTime]s "
        return
    }

    throw "TCP connection to $remoteHost failed from $containerId."
}

function TestInboundNat()
{
    param(
        [string] $remoteHost,
        [string] $externalPort,
        [string] $localHostIP,
        [switch] $DisableTrace,
        [parameter(Mandatory = $false)] [string] $username = $null,
        [parameter(Mandatory = $false)] [string] $password = $null
    )
    if (!$DisableTrace.IsPresent)
    {
        #DumpVfpPolicies -OutFileName "InboundFrom_${remoteHost}_to_${localHostIP}_${externalPort}"
    }

    $ip = $localHostIP

    if($localHostIP.Contains(":"))
    {
        $ip = "[$localHostIP]"
    }

    $curlurl = "http://${ip}:$externalPort"
    Write-WTTLogMessage "trying to curl $curlurl from $remoteHost"

    if ($username)
    {
        $pword = ConvertTo-SecureString -String $password -AsPlainText -Force
        $credential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $username, $pword
        $status = Invoke-Command -ComputerName $remoteHost -Credential $credential -ScriptBlock {param($url) Invoke-WebRequest $url -UseBasicParsing} -ArgumentList $curlurl  -Verbose
    }
    else
    {
        $status = Invoke-Command -ComputerName $remoteHost -ScriptBlock {param($url) Invoke-WebRequest $url -UseBasicParsing} -ArgumentList $curlurl  -Verbose
    }

    if($status.StatusCode -eq "200")
    {
        Write-WTTLogMessage "$remoteHost returned $status ."
        return
    }

    throw "TCP connection for $username from $remoteHost to $localHostIP $externalPort failed. $status"
}

function TestServiceVipFromContainer()
{
    param(
        [string] $containerNameOrId,
        [string] $externalPort,
        [string] $serviceVip,
        [switch] $DisableTrace,
        [int] $protocol = 6,
        [string] $dipContainerNameOrId = $null,
        [bool] $isContainerD = $false
    )
    if (!$DisableTrace.IsPresent)
    {
        #DumpVfpPolicies -OutFileName "OutboundTo_${serviceVip}_${externalPort}_from_container"
    }

    if ($protocol -eq 6) {

        $ip = $serviceVip

        if($serviceVip.Contains(":"))
        {
            $ip = "[$serviceVip]"
        }

        $curlurl =  "http://${ip}:$externalPort"

        $cmd =  "(curl $curlurl -UseBasicParsing -DisableKeepAlive).StatusCode"
        $startTime = Get-Date

        if ($IsContainerD -eq $false)
        {
            $status = Execute-ContainerCommand -command "exec $containerNameOrId powershell $cmd"
        }
        else
        {
            $status = Execute-ContainerDCommand -command "exec $containerNameOrId powershell $cmd"
        }

        if($status -contains "200")
        {
            Write-WTTLogMessage "$remoteHost returned $status ."
            $elapsedTime = ($(Get-Date) - $startTime).TotalSeconds
            Write-WTTLogMessage "Total time [$elapsedTime]s "
            return
        }

        throw "TCP connection from container $containerNameOrId to $serviceVip $externalPort failed. $status"
    }
    elseif ($protocol -eq 17)
    {
        #For UDP the helper runs traffic with same 5 tuple always
        RunCtsTrafficTestEx `
                    -sourceContainer $containerNameOrId `
                    -destinationContainer $dipContainerNameOrId `
                    -destinationIp $serviceVip `
                    -protocol "udp" `
                    -destinationPort $externalPort `
                    -sourcePort 45678 `
    }
}

function TestServiceVipFromHost()
{
    param(
        [string] $externalPort,
        [string] $serviceVip,
        [switch] $DisableTrace
    )
    if (!$DisableTrace.IsPresent)
    {
        #DumpVfpPolicies -OutFileName "OutboundTo_${serviceVip}_${externalPort}_from_container"
    }

    $ip = $serviceVip

    if($serviceVip.Contains(":"))
    {
        $ip = "[$serviceVip]"
    }

    $curlurl =  "http://${ip}:$externalPort"
    $startTime = Get-Date

    $status = Invoke-Command -ScriptBlock {param($url) Invoke-WebRequest $url -UseBasicParsing -DisableKeepAlive} -ArgumentList $curlurl  -Verbose

    if($status.StatusCode -eq "200")
    {
        Write-WTTLogMessage "$remoteHost returned $status ."
        return
    }

    if($status -contains "200")
    {
        Write-WTTLogMessage "$remoteHost returned $status ."
        $elapsedTime = ($(Get-Date) - $startTime).TotalSeconds
        Write-WTTLogMessage "Total time [$elapsedTime]s "
        return
    }

    throw "TCP connection from host to $serviceVip $externalPort failed. $status"
}

function RunCtsTrafficDistributionTest
{
    [CmdletBinding()]
    param(
        [parameter(Mandatory=$false)][string] $sourceContainer,
        [parameter(Mandatory=$true)][string] $dip1container,
        [parameter(Mandatory=$true)][string] $dip2container,
        [ValidateSet('tcp', 'udp')]
        [parameter(Mandatory=$true)][string] $protocol = 'tcp',
        [parameter(Mandatory=$false)][string] $sourceIp = '*',
        [parameter(Mandatory=$true)][string] $destinationIp,
        [parameter(Mandatory=$false)][int] $DestinationPort = 4444,
        [parameter(Mandatory=$false)][string] $LoadBalancerDistribution = "None"
    )

    $dip1filename = "dip1connections.txt"
    $dip2filename = "dip2connections.txt"
    $expectedString = ""
    $connectionCount = 4

    if ($protocol -eq "udp")
    {
        $expectedString = "UDP connection succeeded"
        Execute-ContainerCommand -command "exec -d $dip1container $Global:ctsTraffic -listen:* -port:$destinationPort -protocol:udp -BitsPerSecond:320 -FrameRate:1 -BufferDepth:5 -StreamLength:5 -ConnectionFilename:$dip1filename" -Verbose
        Execute-ContainerCommand -command "exec -d $dip2container $Global:ctsTraffic -listen:* -port:$destinationPort -protocol:udp -BitsPerSecond:320 -FrameRate:1 -BufferDepth:5 -StreamLength:5 -ConnectionFilename:$dip2filename" -Verbose
        if ($sourceContainer)
        {
            $x = Execute-ContainerCommand "exec $sourceContainer $Global:ctsTraffic -target:$destinationIp -port:$destinationPort -protocol:udp -BitsPerSecond:320 -FrameRate:1 -BufferDepth:5 -StreamLength:5 -Connections:$connectionCount -iterations:1" -Verbose
        }
        else
        {
            $sourceContainer = "host"
            $x = c:\tools\ctstraffic.exe -target:$destinationIp -port:$destinationPort -protocol:udp -BitsPerSecond:320 -FrameRate:1 -BufferDepth:5 -StreamLength:5 -Connections:$connectionCount -iterations:1
        }
    }
    else
    {
        $expectedString = "TCP connection succeeded"
        Execute-ContainerCommand "exec -d $dip1container $Global:ctsTraffic -listen:* -port:$destinationPort -protocol:tcp  -transfer:1000 -ConnectionFilename:$dip1filename" -Verbose
        Execute-ContainerCommand "exec -d $dip2container $Global:ctsTraffic -listen:* -port:$destinationPort -protocol:tcp  -transfer:1000 -ConnectionFilename:$dip2filename" -Verbose
        if ($sourceContainer)
        {
            $x = Execute-ContainerCommand "exec $sourceContainer $Global:ctsTraffic -target:$destinationIp -port:$destinationPort -protocol:tcp -Bind:$sourceIp -transfer:1000 -iterations:1 -Connections:$connectionCount" -Verbose
        }
        else
        {
            $sourceContainer = "host"
            $x = c:\tools\ctstraffic.exe -target:$destinationIp -port:$destinationPort -protocol:tcp -Bind:$sourceIp -transfer:1000 -iterations:1 -Connections:$connectionCount
        }
    }

    # Copy connection logs from dip containers and kill ctstraffic to avoid interfering with future tests
    mkdir "c:\tmpConnections"

    Execute-ContainerCommand ("cp " + $dip1container + ":c:\" + $dip1filename + " c:\tmpConnections\") -Verbose
    Execute-ContainerCommand ("cp " + $dip2container + ":c:\" + $dip2filename + " c:\tmpConnections\") -Verbose
    Execute-ContainerCommand "exec -d $dip1container taskkill /f /im ctstraffic.exe" -Verbose
    Execute-ContainerCommand "exec -d $dip2container taskkill /f /im ctstraffic.exe" -Verbose

    $dip1connections = (Get-Content c:\tmpConnections\$dip1filename | Select-String -Pattern $expectedString).Length
    $dip2connections = (Get-Content c:\tmpConnections\$dip2filename | Select-String -Pattern $expectedString).Length

    Write-Verbose -Verbose "$dip1connections successful connections on $dip1container and $dip2connections successful connections on $dip2container"

    # Validate that all connections were successful and that the connections were
    #     a) handled by one dip container in the case of 2 or 3 tuple
    #     -OR-
    #     b) divided amongst the dip containers in the case of 5 tuple
    if (($dip1connections + $dip2connections) -lt $connectionCount)
    {
        throw "$sourceContainer initiated $connectionCount connections to $serviceVip $externalPort and not all succeeded."
    }
    else
    {
        if ($LoadBalancerDistribution -eq "None")
        {
            # connections should be spread across dips
            if (($dip1connections -eq 0 -and $dip2connections -eq $connectionCount) -or ($dip1connections -eq $connectionCount -and $dip2connections -eq 0))
            {
                throw "Session affinity was not expected; however, all connections to $serviceVip $externalPort to $sourceContainer were handled by a single dip."
            }
        }
        else
        {
            # all connections should be on one dip
            if (-not($dip1connections -eq 0 -and $dip2connections -eq $connectionCount) -and -not($dip1connections -eq $connectionCount -and $dip2connections -eq 0))
            {
                throw "Session affinity was expected; however, not all connections to $serviceVip $externalPort to $sourceContainer were handled by a single dip."
            }
        }
    }

    Remove-Item c:\tmpConnections -r -fo

    Write-Verbose  -Verbose "$x"
}

function ExternalPingTest()
{
    param(
        [string] $containerId,
        [bool] $failureExpected = $false,
        [switch] $isIpv6
    )

    PingTest -containerId $containerId -destination "www.google.com" -failureExpected $failureExpected -isIpv6:$isIpv6.IsPresent
}

function PingTest()
{
    param(
        [string] $containerId,
        [string] $destination,
        [bool] $failureExpected = $false,
        [int] $packetSize = 32,
        [switch] $isIpv6
    )
    # DumpVfpPolicies -OutFileName "PingFrom_${containerId}_to_${destination}"
    $option = "-4"

    if($isIpv6.IsPresent -or $destination.Contains(":"))
    {
        $option = "-6"
    }

    try {
        $returnStr = Execute-ContainerCommand -command "exec $containerId ping $option $destination -n 4 -l $packetSize"
    } catch {
        $returnStr = $_.Exception.Message
        Write-WTTLogMessage $returnStr
    }

    # Be sure that ping failed
    if ($failureExpected -and $returnStr -match "\(100% loss\)")
    {
        Write-WTTLogMessage "Expected ping failure on $containerId for destination $destination ."
        return
    }
    # Check for Success case
    else
    {
        if ($returnStr -notmatch "\(100% loss\)")
        {
            Write-WTTLogMessage "Ping worked from $containerId to destination $destination ."
            return
        }
    }

    throw "PingTest failed on $containerId for destination $destination ."
}

function AttachOverlayEndpoint()
{
    param(
        [string] $containerName = $null,
        [string] $endpointName = "testendpoint",
        [string] $iPAddress = $Global:TestIPAddress,
        [switch] $enableOutboundNat,
        [HashTable][parameter(Mandatory=$false)] $OutboundNatPolicy, #  @ {"LocalRoutedVip" = true; "VIP" = ""; ExceptionList = ["", ""]}
        [HashTable][parameter(Mandatory=$false)] $InboundNatPolicy, #  @ {"InternalPort" = "80"; "ExternalPort" = "8080"}
        #[HashTable][parameter(Mandatory=$false)] $PAPolicy #  @ {"PA" = "1.2.3.4"; }
        [HashTable][parameter(Mandatory=$false)] $RoutePolicy #  @ {"PA" = "1.2.3.4"; }
    )
    $network = GetOverlayNetwork
    $managementIP = $network.ManagementIP

    $endpoint = New-HNSEndpoint `
                -Name $endpointName `
                -NetworkId $network.ID `
                -IPAddress $ipAddress `
                -EnableOutboundNat:$enableOutboundNat.IsPresent `
                -OutboundNatPolicy $OutboundNatPolicy `
                -InboundNatPolicy $InboundNatPolicy `
                -RoutePolicies @($RoutePolicy) `
                -GatewayAddress $Global:TestGateway `
                -DNSServerList (Get-HostDnsServers -IPAddress $managementIP) `
                -PAPolicy @{"PA" = $managementIP; } `
                -Verbose

    if ($containerName)
    {
        $out = HotAdd-NetworkEndpoint-HCSContainer -Id $(GetContainerId $containerName) -EndpointId $endpoint.ID -Verbose
    }
    return $($endpoint.ID)
}

function CleanupEndpoint($Endpoint)
{
    if ($Endpoint)
    {
        Remove-HNSEndpoint $Endpoint -Verbose
    }
}

function CleanupEndpointsById(
     [parameter(Mandatory = $true)] [Guid[]] $Endpoints
)
{
    try {
        if ($Endpoints -and ($Endpoints.Length -gt 0))
        {
            $cmdArgsList = New-Object System.Collections.ArrayList
            foreach ($endpoint in $Endpoints)
            {
                if ($endpoint)
                {
                    $epObj = Get-HnsEndpoint | Where-Object ID -eq $endpoint
                    if ($epObj)
                    {
                        $cmdArgs = @("hnsdiag" ,"delete", "endpoints", $endpoint)
                        $cmdArgsList.Add($cmdArgs)
                    }
                }
            }
            ExecuteParallelCmdsInRunSpace -CmdArgsList $cmdArgsList -workingDir $workingDir
        }
    }
    catch
    {
        # Ignore
        Write-Output "Ignoring exception"
    }
}

function GetManagementInterfaceIndex(
    [string] $managmentIP)
{
    $dhcpIPs = (Get-NetIPAddress -AddressFamily IPv4 -PrefixOrigin Dhcp)

    foreach ($dhcpIP in $dhcpIPs)
    {
        if ($dhcpIP.IPAddress -eq $managmentIP)
        {
            return $dhcpIP.InterfaceIndex
        }
    }

    throw "Management interface index not found!!"
}

function GetOverlayNetwork(
    [string] $networkName = "test"
)
{
    $networks = Get-HnsNetwork | Where-Object Type -EQ "overlay"

    foreach ($network in $networks)
    {
        $subnets = $network.Subnets

        foreach ($subnet in $subnets)
        {
            if($subnet.GatewayAddress -eq $Global:TestGateway)
            {
                # Get the /detailed view because we need the LayerResources.
                return Get-HnsNetwork -Detailed -Id $network.Id
            }
        }
    }

    throw "Overlay network for $Global:TestGateway not found"
}


#Use netsh instead of Get-NetAdapter as Get-NetAdapter is more portable.
#(Get-NetAdapter is not avaiable in nanoserver images.)
#Note: This function returns the index of the first adapter that matches $intefacename.
#In the future, we may want to make this more robust for containers with multiple adapters.
function GetNetAdapterFromContainer(
    [string] $container,
    [string] $interfaceName = "ethernet",
    [string] $hostName = $null
)
{
    $lines = Execute-ContainerCommand -command "exec $container netsh int ipv4 show int" -hostName $hostName -ignoreExceptionMessage "Access is denied"
    foreach ($line in $lines) {
        if ($line.ToLower().Contains($interfaceName)) {
            $netadapterIdx = $line.split(" ", [System.StringSplitOptions]::RemoveEmptyEntries) | Select-Object -First 1
            Write-WTTLogMessage "Using net adapter index $netadapterIdx"
            return $netadapterIdx
        }
    }

    throw "Unable to find the adapter [$interfaceName] in [$container]"
}


function CreateLoadBalancer
{
    param
    (
        [parameter(Mandatory = $false)] [Guid[]] $Endpoints = $null,
        [parameter(Mandatory = $true)] [int] $InternalPort,
        [parameter(Mandatory = $true)] [int] $ExternalPort,
        [parameter(Mandatory = $false)] [int] $Protocol = 6,
        [parameter(Mandatory = $false)] [string] $Vip,
        [parameter(Mandatory = $false)] [string] $SourceVip,
        [parameter(Mandatory = $false)] [switch] $ILB,
        [parameter(Mandatory = $false)] [switch] $LocalRoutedVip,
        [parameter(Mandatory = $false)] [switch] $DSR,
        [parameter(Mandatory = $false)] [switch] $PreserveDip,
        [parameter(Mandatory = $false)] [string] $LoadBalancerDistribution = "None",
        [parameter(Mandatory = $false)] [switch] $IPv6
    )

    if ($Global:HnsVersion -eq 2)
    {
        $lb = New-HnsLoadBalancer -Endpoints $Endpoints `
              -InternalPort $InternalPort -ExternalPort $ExternalPort -Protocol $Protocol `
              -Vip $Vip -SourceVip $SourceVip `
              -ILB:$ILB.IsPresent -LocalRoutedVip:$LocalRoutedVip.IsPresent -DSR:$DSR.IsPresent -PreserveDip:$PreserveDip.IsPresent`
              -LoadBalancerDistribution:$LoadBalancerDistribution -IPv6:$IPv6.IsPresent -Verbose
    }
    else
    {
        $lb = New-HnsLoadBalancer -Endpoints $Endpoints `
              -InternalPort $InternalPort -ExternalPort $ExternalPort -Protocol $Protocol `
              -Vip $Vip -SourceVip $SourceVip `
              -ILB:$ILB.IsPresent -LocalRoutedVip:$LocalRoutedVip.IsPresent -DSR:$DSR.IsPresent -PreserveDip:$PreserveDip.IsPresent `
              -IPv6:$IPv6.IsPresent -Verbose
    }

    if (-not $lb)
    {
        throw "failed in policylist creation!!"
    }

    Write-WTTLogMessage ($lb | ConvertTo-Json -Depth 10)

    return $lb
}

function BuildIISImage()
{
    if (!(docker images iis -q))
    {
        mkdir c:\dockerTest -ErrorAction SilentlyContinue
    $x=@"
FROM windowsservercore
EXPOSE 80
ENTRYPOINT [ "powershell",  "-Command",  "`$listener = New-Object System.Net.HttpListener ; `$listener.Prefixes.Add('http://*:80/') ; `$listener.Start() ; `$callerCounts = @{} ; Write-Host('Listening at http://*:80/') ; while (`$listener.IsListening) { ;`$context = `$listener.GetContext() ;`$requestUrl = `$context.Request.Url ;`$clientIP = `$context.Request.RemoteEndPoint.Address ;`$response = `$context.Response ;Write-Host '' ;Write-Host('> {0}' -f `$requestUrl) ;  ;`$count = 1 ;`$k=`$callerCounts.Get_Item(`$clientIP) ;if (`$k -ne `$null) { `$count += `$k } ;`$callerCounts.Set_Item(`$clientIP, `$count) ;`$ip=(Get-NetAdapter | Get-NetIpAddress); `$header='<html><body><H1>Windows Container Web Server</H1>' ;`$callerCountsString='' ;`$callerCounts.Keys | % { `$callerCountsString+='<p>IP {0} callerCount {1} ' -f `$ip[1].IPAddress,`$callerCounts.Item(`$_) } ;`$footer='</body></html>' ;`$content='{0}{1}{2}' -f `$header,`$callerCountsString,`$footer ;Write-Output `$content ;`$buffer = [System.Text.Encoding]::UTF8.GetBytes(`$content) ;`$response.ContentLength64 = `$buffer.Length ;`$response.OutputStream.Write(`$buffer, 0, `$buffer.Length) ;`$response.Close() ;`$responseStatus = `$response.StatusCode ;Write-Host('< {0}' -f `$responseStatus)  } ;" ]
"@
        Set-Content c:\dockerTest\DockerFile $x
        try {
            Execute-ContainerCommand -command "build -t iis c:\dockerTest"
        } finally {
            # Sometimes, Element Not Found is thrown for this.
            Restart-service docker
        }
    }
}

function CheckDockerService()
{
    param
    (
        [string] $HostName = $null
    )
    try {
        Execute-ContainerCommand -command "network ls" -hostName $HostName
    } catch {
        $node = $HostName
        if (!$node)
        {
            $node = (hostname)
        }
        Invoke-Command -ComputerName $node -ScriptBlock { Restart-Service Docker }
    }
}

function DumpVfpPolicies()
{
    param
    (
        [string] $HostName = $null, # Default is null, which would mean local host
        [parameter(Mandatory = $false)] [string] $SwitchName = $null,
        [parameter(Mandatory = $false)] [string] $OutDirectory = ${pwd},
        [parameter(Mandatory = $false)] [string] $OutFileName = [io.path]::GetRandomFileName()
    )
    if ($HostName)
    {
        $OutFileName += $HostName;
        $remoteHost = $HostName
    }
    else
    {
        $remoteHost = (hostname)
    }

    $outFile = [io.path]::Combine($OutDirectory, $OutFileName + "_vfprules.log")
    Write-WTTLogMessage "Outfile $outFile"
    Execute-Command -command "vfpctrl.exe" -arguments "/list-vmswitch-port" -outFile $outFile -ignoreFailure -hostName $HostName | Out-Null

    $switches = Get-CimInstance -Namespace root\virtualization\v2 -Class Msvm_VirtualEthernetSwitch -ComputerName $remoteHost
    foreach ($switch in $switches)
    {
        $vfpCtrlExe = "vfpctrl.exe"
        $ports = $switch | Get-CimAssociatedInstance -ResultClassName "Msvm_EthernetSwitchPort" -Association "Msvm_SystemDevice"
        foreach ($port in $ports)
        {
            $portGuid = $port.Name
            Write-Output "+++++++ Port $portGuid +++++++++" | Out-File -FilePath $outFile -Append
            Execute-Command -command "vfpctrl.exe" -arguments "/list-space  /port $portGuid" -outFile $outFile -ignoreFailure -hostName $HostName | Out-Null
            Execute-Command -command "vfpctrl.exe" -arguments "/list-mapping  /port $portGuid" -outFile $outFile -ignoreFailure -hostName $HostName | Out-Null
            Execute-Command -command "vfpctrl.exe" -arguments "/list-rule  /port $portGuid" -outFile $outFile -ignoreFailure -hostName $HostName | Out-Null
            Execute-Command -command "vfpctrl.exe" -arguments "/port $portGuid /get-port-state" -outFile $outFile -ignoreFailure -hostName $HostName | Out-Null
        }
    }
}

function SetForwarding(
    [string] $container,
    [switch] $disable,
    [string] $hostName = $null,
    [switch] $isIpv6
)
{
    $forwardingCmd = "en"
    if ($disable) {
        $forwardingCmd = "di"
    }

    $type = "ipv4"

    if($isIpv6.IsPresent)
    {
        $type = "ipv6"
    }

    $netadapter = GetNetAdapterFromContainer -container $container -hostName $hostName
    Execute-ContainerCommand -command "exec $container powershell netsh int $type set int $netadapter for=$forwardingCmd" -hostName $hostName -ignoreExceptionMessage "Access is denied"
}

function ValidateArp(
    [string] $nodeName = $null,
    [string] $containerName = $null,
    [string] $IpAddress,
    [string] $MacAddress,
    [switch] $ShouldFail
)
{
    $out = ""
    $isIpv6 = $IpAddress.Contains(":")

    if ($containerName)
    {
        Execute-ContainerCommand -Command "exec $containerName ping $IpAddress"  -hostName $nodeName -ignoreFailure | out-null
        $arpOut = Execute-ContainerCommand -Command "exec $containerName powershell Get-NetNeighbor -IPAddress $IpAddress -ErrorAction SilentlyContinue"  -hostName $nodeName
        #$arpOut = Execute-ContainerCommand -Command "exec $containerName arp -a"  -hostName $nodeName
    }
    else
    {
        Execute-Command -Command ping -arguments "$IpAddress" -hostName $nodeName -ignoreFailure | out-null
        $arpOut = Execute-Command -Command "powershell" -arguments "Get-NetNeighbor -IPAddress $IpAddress -ErrorAction SilentlyContinue"  -hostName $nodeName
        #$arpOut = Execute-Command -Command arp -arguments "-a" -hostName $nodeName
    }

    $ipMatch = $arpOut -match $IpAddress
    if ($ipMatch)
    {
        # Should have an IpMatch if Ping passed. If ping failed, it would have thrown
        if ($ipMatch -match $MacAddress)
        {
            return
        }
    }
    if ($ShouldFail.IsPresent)
    {
        return
    }
    throw "ARP resolution failed"
}
function SetupNodes(
    [string[]]$Nodes
)
{
    xcopy  /F /Y /D "$PSScriptRoot\*.psm1" c:\tools

    foreach ($node in $Nodes)
    {
        Write-Host "Setting up $node"
        mkdir \\$node\c$\tools -ErrorAction:SilentlyContinue

        if ($node -ne (hostname))
        {
            xcopy  /F /Y /D c:\tools\* \\$node\c$\tools
            xcopy /F /Y /D "$PSScriptRoot\*.dll" \\$node\c$\tools
        }
        Invoke-Command -ComputerName $node -ScriptBlock {  Import-Module c:\tools\SDNHelper.psm1  -DisableNameChecking; BuildIISImage } -Verbose
    }
}

function GetTestConfig(
    [string[]]
    [parameter(Mandatory=$false,HelpMessage="Array of L2 reachable nodes with VLan support")]
    $Nodes = $null,
    [int] $ContainersPerNodeCount = 1,
    [string] $TestAdapterName,
    [int] $Vlan = 0,

    [ValidateSet('process', 'hyperv')]
    [parameter(Mandatory=$false,HelpMessage="Isolation to be used for container creation")]
    [string] $isolation="process"
)
{
    $NodeInfo = @()
    foreach ($node in $Nodes) {
        $tmpNode = @{
            Name = $node;
            ContainersInfo = @();
            TestAdapterName = $TestAdapterName;
            Vlan = $Vlan;
        }

        for ($i = 0; $i -lt $ContainersPerNodeCount; $i++) {
            $contTem = @{
                Name = "Container_${node}_${i}";
                IpAddress = $Global:IpPrefix + "$i + 2";
                NodeName = $node;
                Isolation = $isolation;
                EndpointName = "Endpoint_${node}_${i}";
                MacAddress = "";
            }
            $tmpNode.ContainersInfo += $contTem;
        }
        $NodeInfo += $tmpNode;
    }
    return $NodeInfo
}

function SetupMultiNodeL2BridgeNetwork([array]$NodeInfo)
{
    foreach ($ninfo in $NodeInfo)
    {
        CreateL2BridgeNetwork -networkAdapterName $ninfo.TestAdapterName -HostName $ninfo.Name -Vlan $ninfo.Vlan
    }
}

function CleanupMultiNodeL2BridgeNetwork(
    [array]$NodeInfo
)
{
    foreach ($ninfo in $NodeInfo)
    {
        RemoveL2BridgeNetwork -HostName $ninfo.Name
    }
}

function SetupContainer (
    [HashTable]$ContainerInfo,
    [string] $Node = $null
)
{
    if ($Node)
    {
        Invoke-Command -ComputerName $Node `
        -ScriptBlock {
            param( [HashTable] $ContainerInfo )
            Import-Module c:\tools\SDNHelper.psm1 -DisableNameChecking
            SetupContainer -ContainerInfo $ContainerInfo
        } -ArgumentList $ContainerInfo
    }
    else
    {
        CreateContainerWithoutNetwork -containerName $ContainerInfo.Name -isolation $ContainerInfo.Isolation
        $endpoint = CreateL2BridgeEndpoint -enableOutboundNat -IPAddress $ContainerInfo.IpAddress -Name $ContainerInfo.EndpointName
        # Update the Mac Address
        $ContainerInfo.MacAddress = $endpoint.MacAddress
        HotAdd-NetworkEndpoint-HCSContainer -Id $(GetContainerId $ContainerInfo.Name) -EndpointId $endpoint.ID
    }
}

function CleanupL2BridgeEndpoints(
    [string] $endpointName = "testendpoint",
    [string] $Node = $null
)
{
    if ($Node)
    {
        Invoke-Command -ComputerName $Node `
        -ScriptBlock {
            param([string] $endpointName)

            $ep = Get-HnsEndpoint | Where-Object Name -EQ $endpointName
            if ($ep) {
                Remove-HnsEndpoint $ep
            }
        } -ArgumentList $endpointName
    }
    else
    {
        $ep = Get-HnsEndpoint | Where-Object Name -EQ $endpointName
        if ($ep) {
            Remove-HnsEndpoint $ep
        }
    }
}

function SetupMultiNodeContainers([array]$NodeInfo)
{
    foreach ($node in $NodeInfo) {
        foreach ($cifo in $node.ContainerInfo) {
            SetupContainer -Node $node.Name -ContainerInfo $cinfo
        }
    }
}

function CleanupMultiNodeContainers([array]$NodeInfo)
{
    foreach ($node in $NodeInfo) {
        foreach ($cifo in $node.ContainerInfo) {
            CleanupL2BridgeEndpoints -Node $node -endpointName $cinfo.EndpointName
            CleanupContainer -HostName $node.Name -ContainerName $cinfo.Name
        }
    }
}

function ParallelInboundNATTest {
     param(
        [string] $remoteHost,
        [string] $externalPort,
        [string] $localHostIP,
        [switch] $DisableTrace,
        $parallelcount,
        [parameter(Mandatory = $false)] [string] $username = $null,
        [parameter(Mandatory = $false)] [string] $password = $null
    )
    Start-Sleep 5
    if ($username)
    {
        $cmdArgs = @("TestInboundNat", "-remoteHost", $remoteHost, "-username", $username, "-password", $password, "-externalPort", $externalPort, "-localHostIP", $localHostIP, "-DisableTrace")
        ExecuteParallelTestInRunSpace -CmdArgs $cmdArgs -parallelcount $parallelcount -workingDir $workingDir
    }
    else
    {
        $cmdArgs = @("TestInboundNat", "-remoteHost", $remoteHost, "-externalPort", $externalPort, "-localHostIP", $localHostIP, "-DisableTrace")
        ExecuteParallelTestInRunSpace -CmdArgs $cmdArgs -parallelcount $parallelcount -workingDir $workingDir
    }
}

function ExternalConnectivityTest {
    param (
        $sourceContainer,
        $parallelcount,
        $isIpv6 = 0,
        $isContainerD = 0
    )

    if ($IsContainerD -eq $false)
    {
        $cmdArgs = @("TestExternalConnectivity", "-containerId", $sourceContainer, "-DisableTrace", "-isIpv6", $isIpv6)
    }
    else
    {
        $cmdArgs = @("TestExternalConnectivity", "-containerId", $sourceContainer, "-DisableTrace", "-isIpv6", $isIpv6, "-isContainerD", $isContainerD)
    }

    ExecuteParallelTestInRunSpace -CmdArgs $cmdArgs -parallelcount $parallelcount -workingDir $workingDir
}

function VipConnectivityTest {
    param (
        $sourceContainer,
        $externalPort,
        $vip,
        $parallelcount,
        $workingDir,
        $isContainerD = 0
    )
    Start-Sleep 5
    if ($isContainerD -eq $false)
    {
        $cmdArgs = @("TestServiceVipFromContainer", "-containerNameOrId", $sourceContainer, "-externalPort", $externalPort, "-serviceVip", $vip,  "-DisableTrace")
    }
    else
    {
        $cmdArgs = @("TestServiceVipFromContainer", "-containerNameOrId", $sourceContainer, "-externalPort", $externalPort, "-serviceVip", $vip,  "-DisableTrace", "-isContainerD", $isContainerD)
    }
    ExecuteParallelTestInRunSpace -CmdArgs $cmdArgs -parallelcount $parallelcount -workingDir $workingDir
}

function VipConnectivityTestUdp {
    param (
        [string] $sourceContainer,
        [int] $externalPort,
        [string] $vip,
        [int] $parallelcount,
        [string] $workingDir,
        [string] $dipContainer
    )
    Start-Sleep 5
    if($dipContainer)
    {
        $cmdArgs = @("TestServiceVipFromContainer", "-containerNameOrId", $sourceContainer, "-externalPort", $externalPort, "-serviceVip", $vip, "-protocol", 17, "-dipContainerNameOrId", $dipContainer,  "-DisableTrace")
    }
    ExecuteParallelTestInRunSpace -CmdArgs $cmdArgs -parallelcount $parallelcount -workingDir $workingDir
}

function VipConnectivityTestFromHost {
    param (
        $externalPort,
        $vip,
        $parallelcount,
        $workingDir
    )
    Start-Sleep 5
    $cmdArgs = @("TestServiceVipFromHost", "-externalPort", $externalPort, "-serviceVip", $vip,  "-DisableTrace")
    ExecuteParallelTestInRunSpace -CmdArgs $cmdArgs -parallelcount $parallelcount -workingDir $workingDir
}

function VipConnectivityTestFromHostMultiPorts {
    param (
        [string[]] $externalPort,
        [string] $vip,
        [int] $parallelcount,
        [string] $workingDir
    )
    Start-Sleep 5
    [string[][]]$cmdArgs = $null
    1..$parallelcount | ForEach-Object {
        #Add the elements to the table (the leading coma is the syntax used for multi dimentional arrays)
        $cmdArgs += ,@("TestServiceVipFromHost", "-externalPort", ($externalPort + ($_ - 1)), "-serviceVip", $vip,  "-DisableTrace")
    }
    ExecuteParallelTestInRunSpaceMultipleArgs -CmdArgsList $cmdArgs -parallelcount $parallelcount -workingDir $workingDir
}

function Switch-Endianness {
  Param([uint32]$number)
  $number = ((($number -band 0x000000FF) -shl 24) -bor
            (($number -band 0x0000FF00) -shl 8) -bor
            (($number -band 0x00FF0000) -shr 8) -bor
            (($number -band 0xFF000000) -shr 24))
  return $number
}

function VipConnectivityTestFromHostMultiVip {
    param (
        [string[]] $externalPort,
        [string] $vip,
        [int] $parallelcount,
        [string] $workingDir
    )
    Start-Sleep 5
    [string[][]]$cmdArgs = $null
    $vipIpAddress = [System.Net.IPAddress]::Parse($vip)

    1..$parallelcount | ForEach-Object {

        #IPAddress.Address is given in little endian, we need to convert it to big endian before doing math calculations
        $addressBigEndian = Switch-Endianness -Number $vipIpAddress.Address
        $vipIpAddress.Address = Switch-Endianness -Number ($addressBigEndian + ($_ - 1))

        #Add the elements to the table (the leading coma is the syntax used for multi dimentional arrays)
        $cmdArgs += ,@("TestServiceVipFromHost", "-externalPort", $externalPort, "-serviceVip", ($vipIpAddress.ToString()),  "-DisableTrace")
    }
    ExecuteParallelTestInRunSpaceMultipleArgs -CmdArgsList $cmdArgs -parallelcount $parallelcount -workingDir $workingDir
}

function CleanupPolicyList
{
    $pl = Get-HnsPolicyList
    if ($pl) {
        $pl | Remove-HnsPolicyList
    }
}

function CleanupOverlayEndpoints()
{
    $network =  GetOverlayNetwork
    $eps = Get-HnsEndpoint | Where-Object NetworkId -EQ $network.VirtualNetwork
    if ($eps)
    {
        $eps | ForEach-Object {
            CleanupEndpoint $_
        }
    }
    Write-WTTLogMessage "endpoints in overlay network removed. " + $network.Name
}

function CleanupEndpoints
{
    param(
        [string] $HostName = $null,
        [string] $networkName = "l2bridgenetwork"
    )

    if ($HostName)
    {
        Invoke-Command -ComputerName $HostName `
            -ScriptBlock {
                param(
                    [string] $networkName = "l2bridgenetwork"
                )
                Import-Module c:\tools\SDNHelper.psm1 -DisableNameChecking
                CleanupEndpoints -networkName $networkName
            } -ArgumentList $networkName
    }
    else
    {
        try {
            $network = GetL2BridgeNetwork -networkName $networkName
            $eps = Get-HnsEndpoint | Where-Object NetworkId -EQ $network.VirtualNetwork
            if ($eps)
            {
                $eps | Remove-hnsEndpoint
            }
        } catch {
            Write-Output "Ignoring exception"
        }
        Write-WTTLogMessage "endpoints in $networkName network removed."
    }
}

function Get-HostDnsServers
{
    param(
        [string] $IpAddress
    )

    $ip = Get-NetIpADdress -IPAddress $IpAddress
    return [string]::Join(",", (Get-DnsClientServerAddress -AddressFamily IPv4 -InterfaceIndex $ip.InterfaceIndex).ServerAddresses)
}

function AddLoopbackIpAddress
{
    param(
        [string] $ContainerName,
        [string] $IpAddress,
        [parameter(Mandatory = $false)] [switch] $IsContainerD = $false
    )

    $cmd = "`$ifIndex = (netsh int ipv4 sh int | findstr Loopback).Trim().Split(' ')[0];"
    $cmd += "`$ip=Get-NetIpAddress -IpAddress $IpAddress -InterfaceIndex `$ifIndex  -ErrorAction SilentlyContinue;"
    $cmd += "if (!`$ip) { New-NetIpAddress -IpAddress $IpAddress -InterfaceIndex `$ifIndex -ErrorAction SilentlyContinue}"

    if ($IsContainerD -eq $fale)
    {
        Execute-ContainerCommand -command "exec $ContainerName powershell $cmd" -ignoreExceptionMessage "Access is denied"
    }
    else
    {
        Execute-ContainerDCommand -command "exec $ContainerName powershell $cmd" -ignoreExceptionMessage "Access is denied"
    }
}

function RemoveLoopbackIpAddress
{
    param(
        [string] $ContainerName,
        [string] $IpAddress
    )
    $cmd = "`$ifIndex = (netsh int ipv4 sh int | findstr Loopback).Trim().Split(' ')[0];"
    $cmd += "`$ip=Get-NetIpAddress -IpAddress $IpAddress -InterfaceIndex `$ifIndex -ErrorAction SilentlyContinue;"
    $cmd += "if (`$ip) { `$ip | Remove-NetIpAddress -Confirm:`$false -Verbose -ErrorAction SilentlyContinue}"

    Execute-ContainerCommand -command "exec $ContainerName powershell $cmd" -ignoreExceptionMessage "Access is denied"
}

function SetupWeakHostSettings()
{
    param(
        [string] $ContainerName,
        [string] $AddressFamily="ipv4",
        [parameter(Mandatory = $false)] [switch] $IsContainerD = $false

    )

    $cmd = "`$ifIndex = (netsh int $AddressFamily sh int | findstr Loopback).Trim().Split(' ')[0];"
    $cmd += "netsh int $AddressFamily set int `$ifIndex weakhostsend=enabled weakhostreceive=enabled;"
    $cmd += "`$ifIndexEth = (netsh int $AddressFamily sh int | findstr Ethernet).Trim().Split(' ')[0];"
    $cmd += "netsh int $AddressFamily set int `$ifIndexEth weakhostreceive=enabled;"

    if ($IsDocker -eq $true)
    {
        Execute-ContainerCommand -command "exec $ContainerName powershell $cmd" -ignoreExceptionMessage "Access is denied"
    }
    else
    {
        Execute-ContainerDCommand -command "exec $ContainerName powershell $cmd" -ignoreExceptionMessage "Access is denied"
    }
}


function CleanupWeakHostSettings()
{
    param(
        [string] $ContainerName,
        [string] $AddressFamily="ipv4"
    )

    $cmd = "`$ifIndex = (netsh int $AddressFamily sh int | findstr Loopback).Trim().Split(' ')[0];"
    $cmd += "netsh int $AddressFamily set int `$ifIndex weakhostsend=disabled weakhostreceive=disabled;"
    $cmd += "`$ifIndexEth = (netsh int $AddressFamily sh int | findstr Ethernet).Trim().Split(' ')[0];"
    $cmd += "netsh int $AddressFamily set int `$ifIndexEth weakhostreceive=disabled;"

    Execute-ContainerCommand -command "exec $ContainerName powershell $cmd" -ignoreExceptionMessage "Access is denied"
}

function AddEndpointPolicy(
    [guid] $EndpointId,
    [HashTable][parameter(Mandatory=$false)] $Settings
)
{
    $requestType = [ModifyRequestType]::Add
    $resourceType = [EndpointResourceType]::Policy
    Modify-HnsEndpoint -Id $EndpointId -RequestType $requestType -ResourceType $resourceType -Settings $Settings
}

function RemoveEndpointPolicy(
    [guid] $EndpointId,
    [HashTable][parameter(Mandatory=$false)] $Settings
)
{
    $requestType = [ModifyRequestType]::Remove
    $resourceType = [EndpointResourceType]::Policy
    Modify-HnsEndpoint -Id $EndpointId -RequestType $requestType -ResourceType $resourceType -Settings $Settings
}

function
ModifyEndpointOutboundNat (
    [guid] $EndpointId,
    [string] $IpAddress,
    [switch] $Remove
)
{
    $Settings = @{
        Policies = @();
    }
    $Settings.Policies += @{
        Type = "OutBoundNAT";
        Settings = @{
            Destinations = @($IpAddress);
        }
    }
    if ($Remove.IsPresent) {
            RemoveEndpointPolicy -EndpointId $EndpointId -Settings $Settings
    } else {
            AddEndpointPolicy -EndpointId $EndpointId -Settings $Settings
    }
}

function ExecuteParallelTest {
    param (
        [string[]]$CmdArgs,
        $parallelcount,
        $workingDir
    )
    $startTime = Get-Date
    $jobs = @()
    foreach ($temp in 1..$parallelcount) {
        Write-WTTLogMessage "Testing iteration [$temp] "
        $jobs += Start-Job -ScriptBlock {
            param([string[]]$CmdArgs, [string] $workingDir)
                $method = $CmdArgs | Select-Object -First 1
                $arguments = $CmdArgs | Select-Object -Skip 1
                Import-Module $workingDir\SDNHelper.psm1 -DisableNameChecking
                Invoke-Expression "$method $arguments" -Verbose
        } -ArgumentList $CmdArgs,$ScriptPath
    }

    Wait-Job $jobs | Out-Null
    $failed = $false;
    foreach ($job in $jobs) {
        $result = Receive-Job $job
        if ($job.State -eq 'Failed')
        {
            Write-Host $result -ForegroundColor Red
            $failed = $true
        }
        else
        {
            Write-Host $result -ForegroundColor Green
        }
        Remove-Job $job
    }

    if ($failed)
    {
        throw "Failed to Execute " + $CmdArgs;
    }

    $elapsedTime = ($(Get-Date) - $startTime).TotalSeconds
    Write-WTTLogMessage "Total time [$elapsedTime]s "
}

function CleanupContainersParallel()
{
    param(
        [string] $HostName = $null
    )

    $allContainers = Execute-ContainerCommand -command "ps -aq" -hostName $HostName
    $cmdArgsList = New-Object System.Collections.ArrayList
    foreach ($container in $allContainers)
    {
        $cmdArgs = @("CleanupContainer", "-ContainerName", $container)
        $cmdArgsList.Add($cmdArgs)
    }
    ExecuteParallelCmdsInRunSpace -CmdArgsList $cmdArgsList -workingDir $workingDir
}

# https://blogs.technet.microsoft.com/heyscriptingguy/2015/11/28/beginning-use-of-powershell-runspaces-part-3/
function ExecuteParallelTestInRunSpaceMultipleArgs {
    param (
        [string[][]]$CmdArgsList,
        $parallelcount,
        $workingDir
    )
    $startTime = Get-Date

    $Parameters = @{
        CmdArgsList = $CmdArgsList;
        WorkingDir = $ScriptPath;
        HnsVersion = $Global:HnsVersion
    }

    $PowerShell = [powershell]::Create()
    $PowerShell.RunspacePool = $RunspacePool
    $jobs = New-Object System.Collections.ArrayList
    1..$parallelcount | ForEach-Object {
        $PowerShell = [powershell]::Create()
        $PowerShell.RunspacePool = $RunspacePool
        [void]$PowerShell.AddScript({
            param([string[][]]$CmdArgsList, [string] $workingDir, [int] $HnsVersion)

            $CmdArgs = $CmdArgsList[$_ % ($CmdArgsList.Length)]
            $Global:HnsVersion = $HnsVersion
            $ThreadID = [appdomain]::GetCurrentThreadId()
            Write-Host "++++++++++++++++++ThreadID: Begin $ThreadID+++++++++++++++++++++++"
            $method = $CmdArgs | Select-Object -First 1
            $arguments = $CmdArgs | Select-Object -Skip 1
            Import-Module $workingDir\SDNHelper.psm1 -DisableNameChecking
            Write-Verbose "Executing [$method $arguments]"
            Invoke-Expression "$method $arguments" -Verbose
            Write-Host "++++++++++++++++++ThreadID: End $ThreadID+++++++++++++++++++++++"
        })
        [void]$PowerShell.AddParameters($Parameters)
        $Handle = $PowerShell.BeginInvoke()
        $temp = '' | Select-Object PowerShell,Handle
        $temp.PowerShell = $PowerShell
        $temp.handle = $Handle
        [void]$jobs.Add($Temp)
    }

    $failed = $false;
    $return = $jobs | ForEach-Object {
        try {
            $_.powershell.EndInvoke($_.handle)
            if ($_.powershell.HadErrors)
            {
                $failed = $_.powershell.HadErrors
                Write-WttLogError ($_.powershell.Streams.Error | Out-String)
            }

            Write-WTTLogMessage ($_.powershell.Streams.Information | Out-String)
            #Write-WTTLogMessage $_.powershell.Streams.Debug
            #Write-WTTLogMessage $_.powershell.Streams.Verbose
            Write-WTTLogWarning ($_.powershell.Streams.Warning | Out-String)
        }
        catch
        {
            $failed = $true;
            Write-WttLogErrorRecord $_
        }
        $_.PowerShell.Dispose()
    }
    $jobs.clear()

    if ($failed)
    {
        throw "Failed to Execute " + $CmdArgs;
    }

    $elapsedTime = ($(Get-Date) - $startTime).TotalSeconds
    Write-WTTLogMessage "Total time [$elapsedTime]s "
}

function ExecuteParallelTestInRunSpace {
    param (
        [string[]]$CmdArgs,
        $parallelcount,
        $workingDir
    )

    ExecuteParallelTestInRunSpaceMultipleArgs -CmdArgsList (,$CmdArgs) -parallelcount $parallelcount -workingDir $workingDir
}

function ExecuteParallelCmdsInRunSpace {
    param (
        [System.Collections.ArrayList]$CmdArgsList,
        $workingDir
    )

    if (!$CmdArgsList -or $CmdArgsList.Count -EQ 0)
    {
        Write-Host "#########Nothing to Execute##############"
        return
    }

    $startTime = Get-Date

    $PowerShell = [powershell]::Create()
    $PowerShell.RunspacePool = $RunspacePool
    $jobs = New-Object System.Collections.ArrayList
    $CmdArgsList | ForEach-Object {
        $PowerShell = [powershell]::Create()
        $PowerShell.RunspacePool = $RunspacePool
        [void]$PowerShell.AddScript({
            param([string[]]$CmdArgs, [string] $workingDir, [int] $HnsVersion)

            $Global:HnsVersion = $HnsVersion
            $ThreadID = [appdomain]::GetCurrentThreadId()
            Write-Host "++++++++++++++++++ThreadID: Begin $ThreadID+++++++++++++++++++++++"
            $method = $CmdArgs | Select-Object -First 1
            $arguments = $CmdArgs | Select-Object -Skip 1
            Import-Module $workingDir\SDNHelper.psm1 -DisableNameChecking
            Invoke-Expression "$method $arguments" -Verbose
            Write-Host "++++++++++++++++++ThreadID: End $ThreadID+++++++++++++++++++++++"
        })
        $Parameters = @{
            CmdArgs = $_;
            WorkingDir = $ScriptPath;
            HnsVersion = $Global:HnsVersion
        }
        [void]$PowerShell.AddParameters($Parameters)
        $Handle = $PowerShell.BeginInvoke()
        $temp = '' | Select-Object PowerShell,Handle
        $temp.PowerShell = $PowerShell
        $temp.handle = $Handle
        [void]$jobs.Add($Temp)
    }

    $failed = $false;
    $return = $jobs | ForEach-Object {
        try {
            $_.powershell.EndInvoke($_.handle)
            $failed = $_.powershell.HadErrors
            if ($_.powershell.HadErrors)
            {
                Write-WttLogError ($_.powershell.Streams.Error | Out-String)
            }

            Write-WTTLogMessage ($_.powershell.Streams.Information | Out-String)
            #Write-WTTLogMessage $_.powershell.Streams.Debug
            #Write-WTTLogMessage $_.powershell.Streams.Verbose
            Write-WTTLogWarning ($_.powershell.Streams.Warning | Out-String)
        }
        catch
        {
            Write-WttLogErrorRecord $_
            $failed = $true;
        }
        $_.PowerShell.Dispose()
    }
    $jobs.clear()

    if ($failed)
    {
        throw "Failed to Execute " + ( $CmdArgsList | ForEach-Object { Out-String $_ } );
    }

    $elapsedTime = ($(Get-Date) - $startTime).TotalSeconds
    Write-WTTLogMessage "Total time [$elapsedTime]s "
}

function DisableAddressRandomization
{
    netsh interface ipv6 set global randomizeidentifiers=disabled store=active
    netsh interface ipv6 set global randomizeidentifiers=disabled store=persistent
    # Wait for the new non-randmon ip to get plumbed
    Start-Sleep 15
}