Param(
    [parameter(Mandatory = $false)] [ValidateSet(1,2)] [int] $HnsSchemaVersion = 2
)

$GithubSDNRepository = 'Microsoft/wcnscripts'
if ((Test-Path env:GITHUB_SDN_REPOSITORY) -and ($env:GITHUB_SDN_REPOSITORY -ne ''))
{
    $GithubSDNRepository = $env:GITHUB_SDN_REPOSITORY
}

$BaseDir = (Get-Location).Path
mkdir $BaseDir -ErrorAction Ignore

$helper = "$BaseDir\helper.psm1"
if (!(Test-Path $helper))
{
    Invoke-WebRequest -UseBasicParsing "https://raw.githubusercontent.com/$GithubSDNRepository/main/scripts/helper/helper.psm1" -OutFile $BaseDir\helper.psm1
}
Import-Module $helper -Function DownloadFile

DownloadFile -Url  "https://raw.githubusercontent.com/$GithubSDNRepository/main/scripts/collectlogs/collectlogs.ps1" -Destination $BaseDir\collectlogs.ps1
DownloadFile -Url  "https://raw.githubusercontent.com/$GithubSDNRepository/main/scripts/helper/dumpVfpPolicies.ps1" -Destination $BaseDir\dumpVfpPolicies.ps1
DownloadFile -Url "https://raw.githubusercontent.com/$GithubSDNRepository/master/scripts/helper/VFP.psm1" -Destination $BaseDir\VFP.psm1
DownloadFile -Url "https://raw.githubusercontent.com/$GithubSDNRepository/main/scripts/HNS/hns.v2.psm1" -Destination $BaseDir\hns.v2.psm1
DownloadFile -Url "https://raw.githubusercontent.com/$GithubSDNRepository/main/scripts/starthnstrace/starthnstrace.ps1" -Destination $BaseDir\starthnstrace.ps1
DownloadFile -Url "https://raw.githubusercontent.com/$GithubSDNRepository/main/scripts/startpacketcapture/startpacketcapture.ps1" -Destination $BaseDir\startpacketcapture.ps1
DownloadFile -Url  "https://raw.githubusercontent.com/$GithubSDNRepository/main/scripts/portReservationTest/portReservationTest.ps1" -Destination $BaseDir\portReservationTest.ps1
