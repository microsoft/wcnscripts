$Version="1.6.8"
$CrictlVersion="1.25.0"
$SdnBridgeVersion = "v0.3.0"
$dualStack = $true
$WinBuilds = "\\winbuilds\release\rs_onecore_liof1"
$containerRepoPath = "docker.io/princepereira/tcp-client-server:WS2022CONTAINERD"
$pauseContainerRepoPath = "k8s.gcr.io/pause:3.6"
$copyHnsBinaries = $true
$downloadSdnCni = $true

$curLoc = Get-Location
$hnsPath = "$curLoc\hns"

$test = (docker images)
if($null -eq $test) {
    Write-Error "Docker not installed. Install using script 'Install-ContainerHost.ps1' ..." -ForegroundColor Red
    return
}

if($copyHnsBinaries) {

    Write-Host "Setting up hns directory ..." -ForegroundColor Green

    $fileExists = Test-Path "$WinBuilds"
    if($fileExists -ne $true) {
        Write-Host "Unable to access $WinBuilds. Access the $WinBuilds one time using Windows Run ..." -ForegroundColor Red
        return
    }

    $versions = ls $WinBuilds | sort LastWriteTime -Descending | Select -First 10 | select Name
    $winBuildVersion = ""

    foreach($v in $versions){ 

        $name = $v.Name 

        $fileExists = Test-Path "$WinBuilds\$name\amd64fre\bin\vm\hns\hnsapilib.dll"
        if($fileExists -ne $true) {
            continue
        }

        $fileExists = Test-Path "$WinBuilds\$name\amd64fre\bin\wtt\Components\Logger\2.1\Signed.URT4.5\Microsoft.Wtt.Log.dll"
        if($fileExists -ne $true) {
            continue
        }

        $winBuildVersion = $name

    }

    if($winBuildVersion -eq "") {
        Write-Host "Unable to find a valid build in $WinBuilds ..." -ForegroundColor Red
        return
    }

    $BuildPath = "$WinBuilds\$winBuildVersion\amd64fre"

    Write-Host "Build Path : $BuildPath" -ForegroundColor Green

    mkdir $hnsPath
    Copy-Item -Path "$BuildPath\bin\vm\hns\powershell\*" -Destination "$hnsPath\." -Recurse -Force
    Copy-Item -Path "$BuildPath\bin\vm\hns\testscripts\*" -Destination "$hnsPath\." -Recurse -Force
    Copy-Item -Path "$BuildPath\bin\vm\hns\hnsapilib.dll" -Destination "$hnsPath\." -Recurse -Force
    Copy-Item -Path "$BuildPath\bin\wtt\Components\Logger\2.1\Signed.URT4.5\Microsoft.Wtt.Log.dll" -Destination "$hnsPath\." -Recurse -Force

    Copy-Item -Path ".\HnsContainerdApis.psm1" -Destination "$hnsPath\." -Recurse -Force
    Copy-Item -Path ".\pod.template.json" -Destination "$hnsPath\." -Recurse -Force
    Copy-Item -Path ".\wcow-container.template.json" -Destination "$hnsPath\." -Recurse -Force
    Copy-Item -Path ".\newsdnhelper.psm1" -Destination "$hnsPath\." -Recurse -Force

    Start-Sleep -Seconds 2
}

if($downloadSdnCni) {
    Write-Host "Downloading sdnbridge package ..." -ForegroundColor Green
    Invoke-WebRequest https://github.com/microsoft/windows-container-networking/releases/download/$SdnBridgeVersion/windows-container-networking-cni-amd64-$SdnBridgeVersion.zip -OutFile SdnBridge.zip
    Start-Sleep -Seconds 5
    Expand-Archive -Path .\SdnBridge.zip -DestinationPath . -Force
}

# Downloading containerd package
Write-Host "Downloading containerd package ..." -ForegroundColor Green
wget https://github.com/containerd/containerd/releases/download/v$Version/cri-containerd-$Version-windows-amd64.tar.gz -o containerd-windows-amd64.tar.gz

# Extracting containerd package
Write-Host "Extracting containerd package ..." -ForegroundColor Green
mkdir containerd
tar.exe -C containerd -xvf .\containerd-windows-amd64.tar.gz 

Write-Host "Extracting containerd items to path : $Env:ProgramFiles\containerd ..." -ForegroundColor Green
Copy-Item -Path ".\containerd\*" -Destination "$Env:ProgramFiles\containerd\." -Recurse -Force
Set-Location $Env:ProgramFiles\containerd\
Copy-Item -Recurse -Force "C:\Program Files\containerd\bin" "C:\Program Files\containerd\cni\."
.\containerd.exe config default | Out-File config.toml -Encoding ascii

Get-Content config.toml

# Register and start service
Write-Host "Registering containerd service ..." -ForegroundColor Green
.\containerd.exe --register-service
Start-Service containerd

# ctr comes with containerd, we additionally install crictl
Write-Host "Downloading crictl package ..." -ForegroundColor Green
wget https://github.com/kubernetes-sigs/cri-tools/releases/download/v$CrictlVersion/crictl-v$CrictlVersion-windows-amd64.tar.gz -o crictl.tgz
Write-Host "Extracting crictl package ..." -ForegroundColor Green
tar -xvf crictl.tgz -C "C:\Program Files\containerd"

# Set path for crictl
Write-Host "Configuring crictl package ..." -ForegroundColor Green
$env:CONTAINER_RUNTIME_ENDPOINT="npipe:////./pipe/containerd-containerd"
[Environment]::SetEnvironmentVariable("Path", "$($env:path);C:\Program Files\containerd", [System.EnvironmentVariableTarget]::Machine)
$env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine")

# Setting crictl configuration
# TODO: Change sandbox image
crictl config --set runtime-endpoint="npipe:////./pipe/containerd-containerd"
crictl config --set image-endpoint="npipe:////./pipe/containerd-containerd"
crictl config --set timeout=60
crictl config --set debug=false
crictl config --set pull-image-on-create=false

Write-Host "Copying configuration files to containerd directory ..." -ForegroundColor Green

if($dualStack -eq $true) {
    Copy-Item -Path "$curLoc\l2bridgenetwork_cni_dualstack.conf" -Destination "$Env:ProgramFiles\containerd\cni\conf\l2bridgenetwork_cni.conf" -Force
} else {
    Copy-Item -Path "$curLoc\l2bridgenetwork_cni_ipv4.conf" -Destination "$Env:ProgramFiles\containerd\cni\conf\l2bridgenetwork_cni.conf" -Force
}

Copy-Item -Path "$curLoc\wcow-container.template.json" -Destination "$Env:ProgramFiles\containerd" -Force
Copy-Item -Path "$curLoc\pod.template.json" -Destination "$Env:ProgramFiles\containerd" -Force
Remove-Item -Recurse -Force "$Env:ProgramFiles\containerd\cni\bin" -ErrorAction Ignore
mkdir "$Env:ProgramFiles\containerd\cni\bin"
Copy-Item -Path "$curLoc\sdnbridge.exe" -Destination "$Env:ProgramFiles\containerd\cni\bin\." -Force
Copy-Item -Path "$curLoc\config.toml" -Destination "$Env:ProgramFiles\containerd\." -Force

Start-Sleep -Seconds 5

Restart-Service -f hns
Restart-Service -f containerd

# Pulling image
Write-Host "Pulling docker image from $containerRepoPath ..." -ForegroundColor Green
crictl pull $containerRepoPath
Write-Host "Pulling docker image from $pauseContainerRepoPath ..." -ForegroundColor Green
docker pull $pauseContainerRepoPath
docker save $pauseContainerRepoPath -o pause.tar
ctr -n="k8s.io" images import .\pause.tar

Set-Location $hnsPath
Import-Module -Force .\HnsContainerdApis.psm1
Write-Host "Containerd setup completed ..." -ForegroundColor Green