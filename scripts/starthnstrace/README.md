# starthnstrace
A script to capture all container network management activity on the system from a variety of providers (HNS and others).


## Usage

```
.\starthnstrace.ps1
```
Will start a trace to capture all activity and write output into `C:\server.etl`. Press 'q' after desired event occured to stop the trace.


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
    $GetPackets,

    # Collects logs after user presses q to stop tracing. Ignored when -NoPrompt set.
    [switch]
    $CollectLogs
```