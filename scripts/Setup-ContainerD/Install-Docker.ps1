
############################################################
# Script assembled with makeps1.js from
# Install-ContainerHost-Source.ps1
# ..\common\ContainerHost-Common.ps1
# Install-ContainerHost-Main.ps1
############################################################

<#
    .NOTES
        Copyright (c) Microsoft Corporation.  All rights reserved.

        Use of this sample source code is subject to the terms of the Microsoft
        license agreement under which you licensed this sample source code. If
        you did not accept the terms of the license agreement, you are not
        authorized to use this sample source code. For the terms of the license,
        please see the license agreement between you and Microsoft or, if applicable,
        see the LICENSE.RTF on your install media or the root of your tools installation.
        THE SAMPLE SOURCE CODE IS PROVIDED "AS IS", WITH NO WARRANTIES.

    .SYNOPSIS
        Installs the prerequisites for creating Windows containers

    .DESCRIPTION
        Installs the prerequisites for creating Windows containers

    .PARAMETER DockerPath
        Path to Docker.exe, can be local or URI (if multiple paths are provided, the first accessible path will be used).

    .PARAMETER DockerDPath
        Path to DockerD.exe, can be local or URI (if multiple paths are provided, the first accessible path will be used).

    .PARAMETER ExternalNetAdapter
        Specify a specific network adapter to bind to a DHCP network

    .PARAMETER Stable
        If passed, install docker from stable docker release. Else, install from docker master branch.

    .PARAMETER Force
        If a restart is required, forces an immediate restart.

    .PARAMETER HyperV
        If passed, prepare the machine for Hyper-V containers

    .PARAMETER NATSubnet
        Use to override the default Docker NAT Subnet when in NAT mode.

    .PARAMETER NoRestart
        If a restart is required the script will terminate and will not reboot the machine

    .PARAMETER SkipImageImport
        Ignored.

    .PARAMETER TransparentNetwork
        If passed, use DHCP configuration.  Otherwise, will use default docker network (NAT). (alias -UseDHCP)

    .EXAMPLE
        .\Install-ContainerHost.ps1

#>
#Requires -Version 5.0

[CmdletBinding(DefaultParameterSetName="Standard")]
param(
    [string[]]
    [ValidateNotNullOrEmpty()]
    $DockerPath = @("https://master.mobyproject.org/windows/x86_64/docker.exe", "https://master.dockerproject.org/windows/x86_64/docker.exe"),

    [string[]]
    [ValidateNotNullOrEmpty()]
    $DockerDPath = @("https://master.mobyproject.org/windows/x86_64/dockerd.exe", "https://master.dockerproject.org/windows/x86_64/dockerd.exe"),

    [string]
    $ExternalNetAdapter,

    [switch]
    $Stable,

    [switch]
    $Force,

    [switch]
    $HyperV,

    [string]
    $NATSubnet,

    [switch]
    $NoRestart,

    [Parameter(DontShow)]
    [switch]
    $PSDirect,

    [switch]
    $SkipImageImport,

    [Parameter(ParameterSetName="Staging", Mandatory)]
    [switch]
    $Staging,

    [switch]
    [alias("UseDHCP")]
    $TransparentNetwork,

    [string]
    [ValidateNotNullOrEmpty()]
    $HyperVDevSourcePath = "\\sesdfs\1Windows\TestContent\CORE\Base\HYP\HAT\packages"
)

$global:RebootRequired = $false

$global:ErrorFile = "$pwd\Install-ContainerHost.err"

$global:BootstrapTask = "ContainerBootstrap"

$global:HyperVImage = "NanoServer"

$global:DockerDataPath = "$($env:ProgramData)\docker"

function
Restart-And-Run()
{
    Test-Admin

    Write-Output "Restart is required; restarting now..."

    $argList = $script:MyInvocation.Line.replace($script:MyInvocation.InvocationName, "")

    #
    # Update .\ to the invocation directory for the bootstrap
    #
    $scriptPath = $script:MyInvocation.MyCommand.Path

    $argList = $argList -replace "\.\\", "$pwd\"

    if ((Split-Path -Parent -Path $scriptPath) -ne $pwd)
    {
        $sourceScriptPath = $scriptPath
        $scriptPath = "$pwd\$($script:MyInvocation.MyCommand.Name)"

        Copy-Item $sourceScriptPath $scriptPath
    }

    Write-Output "Creating scheduled task action ($scriptPath $argList)..."
    $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoExit $scriptPath $argList"

    Write-Output "Creating scheduled task trigger..."
    $trigger = New-ScheduledTaskTrigger -AtLogOn

    Write-Output "Registering script to re-run at next user logon..."
    Register-ScheduledTask -TaskName $global:BootstrapTask -Action $action -Trigger $trigger -RunLevel Highest | Out-Null

    try
    {
        if ($Force)
        {
            Restart-Computer -Force
        }
        else
        {
            Restart-Computer
        }
    }
    catch
    {
        Write-Error $_

        Write-Output "Please restart your computer manually to continue script execution."
    }

    exit
}


function
Install-Feature
{
    [CmdletBinding()]
    param(
        [ValidateNotNullOrEmpty()]
        [string]
        $FeatureName
    )

    Write-Output "Querying status of Windows feature: $FeatureName..."
    if (Get-Command Get-WindowsFeature -ErrorAction SilentlyContinue)
    {
        if ((Get-WindowsFeature $FeatureName).Installed)
        {
            Write-Output "Feature $FeatureName is already enabled."
        }
        else
        {
            Test-Admin

            Write-Output "Enabling feature $FeatureName..."
        }

        $featureInstall = Add-WindowsFeature $FeatureName

        if ($featureInstall.RestartNeeded -eq "Yes")
        {
            $global:RebootRequired = $true;
        }
    }
    else
    {
        $featureState = (Get-WindowsOptionalFeature -Online -FeatureName $FeatureName).State
        if ($featureState -eq "Disabled")
        {
            if (Test-Nano)
            {
                throw "This NanoServer deployment does not include $FeatureName.  Please add the appropriate package"
            }

            Test-Admin

            Write-Output "Enabling feature $FeatureName..."
            $feature = Enable-WindowsOptionalFeature -Online -FeatureName $FeatureName -All -NoRestart

            if ($feature.RestartNeeded -eq "True")
            {
                $global:RebootRequired = $true;
            }
        }
        elseif ($featureState -ne $null)
        {
            Write-Output "Feature $FeatureName is already enabled."

            if (Test-Nano)
            {
                #
                # Get-WindowsEdition is not present on Nano.  On Nano, we assume reboot is not needed
                #
            }
            elseif ((Get-WindowsEdition -Online).RestartNeeded)
            {
                $global:RebootRequired = $true;
            }
        }
        else
        {
            Write-Warning "Feature $FeatureName does not exist!"
        }
    }
}


function
New-ContainerTransparentNetwork
{
    if ($ExternalNetAdapter)
    {
        $netAdapter = (Get-NetAdapter |? {$_.Name -eq "$ExternalNetAdapter"})[0]
    }
    else
    {
        $netAdapter = (Get-NetAdapter |? {($_.Status -eq 'Up') -and ($_.ConnectorPresent)})[0]
    }

    Write-Output "Creating container network (Transparent)..."
    docker network create -d transparent -o com.docker.network.windowsshim.interface="$($netAdapter.Name)" "Transparent"
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to create transparent network."
    }

    # Transparent networks are not picked up by docker until after a service restart.
    if (Test-Docker)
    {
        Restart-Service -Name $global:DockerServiceName
        Wait-Docker
    }
}


function
Install-ContainerHost
{
    "If this file exists when Install-ContainerHost.ps1 exits, the script failed!" | Out-File -FilePath $global:ErrorFile

    $HyperVFeatureName = "Hyper-V"

    if (Test-Client)
    {
        $HyperVFeatureName = "Microsoft-Hyper-V"

        if (-not $HyperV)
        {
            Write-Output "Enabling Hyper-V containers by default for Client SKU"
            $HyperV = $true
        }
    }
    #
    # Validate required Windows features
    #
    Install-Feature -FeatureName Containers

    if ($HyperV)
    {
        Install-Feature -FeatureName $HyperVFeatureName
    }

    if ($global:RebootRequired)
    {
        if ($NoRestart)
        {
            Write-Warning "A reboot is required; stopping script execution"
            exit
        }

        Restart-And-Run
    }

    #
    # Unregister the bootstrap task, if it was previously created
    #
    if ((Get-ScheduledTask -TaskName $global:BootstrapTask -ErrorAction SilentlyContinue) -ne $null)
    {
        Unregister-ScheduledTask -TaskName $global:BootstrapTask -Confirm:$false
    }

    #
    # Install, register, and start Docker
    #
    if (Test-Docker)
    {
        Write-Output "Docker is already installed."
    }
    else
    {
        if ($Stable)
        {
            Download-Docker
            $DockerPath = "$global:DockerDataPath\docker.exe"
            $DockerDPath = "$global:DockerDataPath\dockerd.exe"
        }
        if ($NATSubnet)
        {
            Install-Docker -DockerPath $DockerPath -DockerDPath $DockerDPath -NATSubnet $NATSubnet
        }
        else
        {
            Install-Docker -DockerPath $DockerPath -DockerDPath $DockerDPath
        }
    }

    Install-DockerPowerShell
    Install-ContainersLayersModule -HyperVDevSourcePath $HyperVDevSourcePath

    #
    # Configure networking
    #
    if ($($PSCmdlet.ParameterSetName) -ne "Staging")
    {
        if ($TransparentNetwork)
        {
            Write-Output "Waiting for Hyper-V Management..."

            $networksNames = (docker network ls --filter driver=transparent --format "{{.Name}}")
            if ($networksNames.Count -eq 0)
            {
                Write-Output "Enabling container networking..."
                New-ContainerTransparentNetwork
            }
            else
            {
                Write-Output "Networking is already configured.  Confirming configuration..."

                if ($ExternalNetAdapter)
                {
                    $netAdapters = (Get-NetAdapter |? {$_.Name -eq "$ExternalNetAdapter"})

                    if ($netAdapters.Count -eq 0)
                    {
                        throw "No adapters found that match the name $ExternalNetAdapter"
                    }

                    $netAdapter = $netAdapters[0]
                    $transparentNetwork = $networksNames |? { "vEthernet ($_)" -eq $netAdapter.Name }

                    if ($transparentNetwork -eq $null)
                    {
                        throw "One or more external networks are configured, but not on the requested adapter ($ExternalNetAdapter)"
                    }

                    Write-Output "Configured transparent network found: $($transparentNetwork)"
                }
                else
                {
                    Write-Output "Configured transparent networks found:"
                    Write-Output $networksNames
                }
            }
        }
    }

    Remove-Item $global:ErrorFile

    Write-Output "Script complete!"
}
$global:AdminPriviledges = $false
$global:DockerDataPath = "$($env:ProgramData)\docker"
$global:DockerServiceName = "docker"

function
Copy-File
{
    [CmdletBinding()]
    param(
        [string[]]
        $SourcePath,
        
        [string]
        $DestinationPath
    )

    foreach ($currentSourcePath in @($SourcePath))
    {
        try
        {
            if ($currentSourcePath -eq $DestinationPath)
            {
                return
            }
                
            if (Test-Path $currentSourcePath)
            {
                Copy-Item -Path $currentSourcePath -Destination $DestinationPath
            }
            elseif (($currentSourcePath -as [System.URI]).AbsoluteURI -ne $null)
            {
                if (Test-Nano)
                {
                    $handler = New-Object System.Net.Http.HttpClientHandler
                    $client = New-Object System.Net.Http.HttpClient($handler)
                    $client.Timeout = New-Object System.TimeSpan(0, 30, 0)
                    $cancelTokenSource = [System.Threading.CancellationTokenSource]::new() 
                    $responseMsg = $client.GetAsync([System.Uri]::new($currentSourcePath), $cancelTokenSource.Token)
                    $responseMsg.Wait()

                    if (!$responseMsg.IsCanceled)
                    {
                        $response = $responseMsg.Result
                        if ($response.IsSuccessStatusCode)
                        {
                            $downloadedFileStream = [System.IO.FileStream]::new($DestinationPath, [System.IO.FileMode]::Create, [System.IO.FileAccess]::Write)
                            $copyStreamOp = $response.Content.CopyToAsync($downloadedFileStream)
                            $copyStreamOp.Wait()
                            $downloadedFileStream.Close()
                            if ($copyStreamOp.Exception -ne $null)
                            {
                                throw $copyStreamOp.Exception
                            }      
                        }
                    }  
                }
                else
                {
                    # Ensure that all secure protocols are enabled (TLS 1.2 is not by default in some cases).
                    $secureProtocols = @()
                    $insecureProtocols = @([System.Net.SecurityProtocolType]::SystemDefault, [System.Net.SecurityProtocolType]::Ssl3)

                    foreach ($protocol in [System.Enum]::GetValues([System.Net.SecurityProtocolType]))
                    {
                        if ($insecureProtocols -notcontains $protocol)
                        {
                            $secureProtocols += $protocol
                        }
                    }

                    [System.Net.ServicePointManager]::SecurityProtocol = $secureProtocols

                    if ($PSVersionTable.PSVersion.Major -ge 5)
                    {
                        #
                        # We disable progress display because it kills performance for large downloads (at least on 64-bit PowerShell)
                        #
                        $ProgressPreference = 'SilentlyContinue'
                        Invoke-WebRequest -Uri $currentSourcePath -OutFile $DestinationPath -UseBasicParsing
                        $ProgressPreference = 'Continue'
                    }
                    else
                    {
                        $webClient = New-Object System.Net.WebClient
                        $webClient.DownloadFile($currentSourcePath, $DestinationPath)
                    }
                }
            }
            else
            {
                throw "Cannot copy from $currentSourcePath"
            }

            # If we get here, we've successfuly copied a file.
            return
        }
        catch
        {
            $innerException = $_
        }
    }

    throw $innerException
}


function 
Test-Admin()
{
    # Get the ID and security principal of the current user account
    $myWindowsID=[System.Security.Principal.WindowsIdentity]::GetCurrent()
    $myWindowsPrincipal=new-object System.Security.Principal.WindowsPrincipal($myWindowsID)
  
    # Get the security principal for the Administrator role
    $adminRole=[System.Security.Principal.WindowsBuiltInRole]::Administrator
  
    # Check to see if we are currently running "as Administrator"
    if ($myWindowsPrincipal.IsInRole($adminRole))
    {
        $global:AdminPriviledges = $true
        return
    }
    else
    {
        #
        # We are not running "as Administrator"
        # Exit from the current, unelevated, process
        #
        throw "You must run this script as administrator"   
    }
}


function 
Test-Client()
{
    return (-not ((Get-Command Get-WindowsFeature -ErrorAction SilentlyContinue) -or (Test-Nano)))
}


function 
Test-Nano()
{
    $EditionId = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -Name 'EditionID').EditionId

    return (($EditionId -eq "ServerStandardNano") -or 
            ($EditionId -eq "ServerDataCenterNano") -or 
            ($EditionId -eq "NanoServer") -or 
            ($EditionId -eq "ServerTuva"))
}


function 
Wait-Network()
{
    $connectedAdapter = Get-NetAdapter |? ConnectorPresent

    if ($connectedAdapter -eq $null)
    {
        throw "No connected network"
    }
       
    $startTime = Get-Date
    $timeElapsed = $(Get-Date) - $startTime

    while ($($timeElapsed).TotalMinutes -lt 5)
    {
        $readyNetAdapter = $connectedAdapter |? Status -eq 'Up'

        if ($readyNetAdapter -ne $null)
        {
            return;
        }

        Write-Output "Waiting for network connectivity..."
        Start-Sleep -sec 5

        $timeElapsed = $(Get-Date) - $startTime
    }

    throw "Network not connected after 5 minutes"
}

function
Download-Docker()
{
    [CmdletBinding()]
    param(
        [string]
        [ValidateNotNullOrEmpty()]
        $DockerDownloadUrl = "https://download.docker.com/win/static/stable/x86_64"
    )

    $web = Invoke-WebRequest $DockerDownloadUrl -UseBasicParsing
    $DockerZipName = (($web.tostring() -split "[`r`n]" | select-string "docker")[-1] -split '"')[1]
    $DockerZipPath = $DockerDownloadUrl + '/' + $DockerZipName

    Write-Output "Downloading $DockerZipPath"
    if (!(Test-path $global:DockerDataPath))
    {
        md -Path $global:DockerDataPath | Out-Null
    }
    Copy-File -SourcePath $DockerZipPath -DestinationPath $global:DockerDataPath\docker.zip
    Expand-Archive -LiteralPath $global:DockerDataPath\docker.zip -DestinationPath $global:DockerDataPath -Force

    Copy-File -SourcePath $global:DockerDataPath\docker\docker.exe -DestinationPath $global:DockerDataPath\docker.exe
    Copy-File -SourcePath $global:DockerDataPath\docker\dockerd.exe -DestinationPath $global:DockerDataPath\dockerd.exe
}

function 
Install-Docker()
{
    [CmdletBinding()]
    param(
        [string[]]
        [ValidateNotNullOrEmpty()]
        $DockerPath = @("https://master.mobyproject.org/windows/x86_64/docker.exe", "https://master.dockerproject.org/windows/x86_64/docker.exe"),

        [string[]]
        [ValidateNotNullOrEmpty()]
        $DockerDPath = @("https://master.mobyproject.org/windows/x86_64/dockerd.exe", "https://master.dockerproject.org/windows/x86_64/dockerd.exe"),
                
        [string]
        [ValidateNotNullOrEmpty()]
        $NATSubnet
    )

    Test-Admin

    Write-Output "Installing Docker..."
    Copy-File -SourcePath $DockerPath -DestinationPath $env:windir\System32\docker.exe
        
    Write-Output "Installing Docker daemon..."
    Copy-File -SourcePath $DockerDPath -DestinationPath $env:windir\System32\dockerd.exe
    
    $dockerConfigPath = Join-Path $global:DockerDataPath "config"
    
    if (!(Test-Path $dockerConfigPath))
    {
        md -Path $dockerConfigPath | Out-Null
    }

    #
    # Register the docker service.
    # Configuration options should be placed at %programdata%\docker\config\daemon.json
    #
    $daemonSettings = New-Object PSObject
        
    $certsPath = Join-Path $global:DockerDataPath "certs.d"

    if (Test-Path $certsPath)
    {
        $daemonSettings | Add-Member NoteProperty hosts @("npipe://", "0.0.0.0:2376")
        $daemonSettings | Add-Member NoteProperty tlsverify true
        $daemonSettings | Add-Member NoteProperty tlscacert (Join-Path $certsPath "ca.pem")
        $daemonSettings | Add-Member NoteProperty tlscert (Join-Path $certsPath "server-cert.pem")
        $daemonSettings | Add-Member NoteProperty tlskey (Join-Path $certsPath "server-key.pem")
    }
    else
    {
        # Default local host
        $daemonSettings | Add-Member NoteProperty hosts @("npipe://")
    }

    if ($NATSubnet -ne "")
    {
        $daemonSettings | Add-Member NoteProperty fixed-cidr $NATSubnet
    }

    $daemonSettingsFile = Join-Path $dockerConfigPath "daemon.json"

    $daemonSettings | ConvertTo-Json | Out-File -FilePath $daemonSettingsFile -Encoding ASCII
    
    & dockerd --register-service --service-name $global:DockerServiceName

    Start-Docker

    #
    # Waiting for docker to come to steady state
    #
    Wait-Docker

    Write-Output "The following images are present on this machine:"
    
    docker images -a | Write-Output

    Write-Output ""
}


function
Install-NuGetPackageProvider()
{
    $source = Get-PackageProvider -Name NuGet -Force -ErrorAction SilentlyContinue
    if ($source -eq $null)
    {
        Write-Output "Installing dependent package provider 'NuGet'."
        Install-PackageProvider -Name NuGet -Force | Out-Null
    }
}


function
Install-DockerPowerShell()
{
    Install-NuGetPackageProvider

    mkdir "$env:temp\dockerpkg" -Force -ErrorAction SilentlyContinue
    Invoke-WebRequest https://github.com/Microsoft/Docker-PowerShell/releases/download/v0.1.0/Docker.0.1.0.nupkg -OutFile "$env:temp\dockerpkg\docker.nupkg"
    Find-Package docker -source "$env:temp\dockerpkg\" | Install-Package -Destination "$Env:ProgramFiles\WindowsPowerShell\Modules\"
    mv -Force "C:\Program Files\WindowsPowerShell\Modules\Docker.0.1.0\" "C:\Program Files\WindowsPowerShell\Modules\Docker"
}


function 
Start-Docker()
{
    Start-Service -Name $global:DockerServiceName
}


function 
Stop-Docker()
{
    Stop-Service -Name $global:DockerServiceName
}


function 
Test-Docker()
{
    $service = Get-Service -Name $global:DockerServiceName -ErrorAction SilentlyContinue

    return ($service -ne $null)
}


function 
Wait-Docker()
{
    Write-Output "Waiting for Docker daemon..."
    $dockerReady = $false
    $startTime = Get-Date

    while (-not $dockerReady)
    {
        try
        {
            docker version | Out-Null

            if (-not $?)
            {
                throw "Docker daemon is not running yet"
            }

            $dockerReady = $true
        }
        catch 
        {
            $timeElapsed = $(Get-Date) - $startTime

            if ($($timeElapsed).TotalMinutes -ge 1)
            {
                throw "Docker Daemon did not start successfully within 1 minute."
            } 

            # Swallow error and try again
            Start-Sleep -sec 1
        }
    }
    Write-Output "Successfully connected to Docker Daemon."
}


function
Install-ContainersLayersModule
{
    [CmdletBinding()]
    param(
        [string]
        [ValidateNotNullOrEmpty()]
        $HyperVDevSourcePath = "\\sesdfs\1Windows\TestContent\CORE\Base\HYP\HAT\packages"
    )

    Install-NuGetPackageProvider

    $source = Get-PSRepository -Name HyperVDev -ErrorAction SilentlyContinue
    if ($source -eq $null)
    {
        Write-Output "Registering the HyperVDev feed."
        Register-PackageSource -Name HyperVDev -Provider PowerShellGet -Location $HyperVDevSourcePath -Trusted -Force | Out-Null
    }

    $module = Get-InstalledModule -Name Containers.Layers -ErrorAction SilentlyContinue
    if ($module -eq $null)
    {
        Write-Output "Installing the Containers.Layers module."
        Install-Module -Name Containers.Layers -Repository HyperVDev | Out-Null
    }
}
try
{
    Install-ContainerHost
}
catch 
{
    Write-Error $_
}
