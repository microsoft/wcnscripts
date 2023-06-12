# startpacketcapture.ps1
A script to capture all packets on the system from a variety of providers.

## Usage
```
.\startpacketcapture.ps1
```
Will start a trace to capture all packets and write output into `C:\server.etl`. Press 'q' after desired packets are collected to stop the capture.

## Parameters
```
    # Path with filename where the ETL file will be saved. Format: <path>\<filename>.etl
    [string]
    $EtlFile = "C:\server.etl",

    # How many bytes of the packet to collect. Default is 256 bytes to collect encapsulated headers.
    [int]
    $snapLen = 256,

    # Maximum file size in megabytes. 0 means that there is no maximum
    [int]
    $maxFileSize = 250,

    # Does not prompt/pause execution and wait on user input.
    [switch]
    $NoPrompt,

    # Does not collect network packets.
    [switch]
    $NoPackets,

    # Collects logs after user presses q to stop tracing. Ignored when -NoPrompt set.
    [switch]
    $CollectLogs
```