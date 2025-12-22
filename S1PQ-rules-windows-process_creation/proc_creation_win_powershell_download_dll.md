```sql
// Translated content (automatically translated on 22-12-2025 02:21:40):
event.type="Process Creation" and (endpoint.os="windows" and ((tgt.process.cmdline contains "Invoke-RestMethod " or tgt.process.cmdline contains "Invoke-WebRequest " or tgt.process.cmdline contains "IRM " or tgt.process.cmdline contains "IWR ") and (tgt.process.cmdline contains "http" and tgt.process.cmdline contains "OutFile" and tgt.process.cmdline contains ".dll")))
```


# Original Sigma Rule:
```yaml
title: Potential DLL File Download Via PowerShell Invoke-WebRequest
id: 0f0450f3-8b47-441e-a31b-15a91dc243e2
status: test
description: Detects potential DLL files being downloaded using the PowerShell Invoke-WebRequest or Invoke-RestMethod cmdlets.
references:
    - https://www.zscaler.com/blogs/security-research/onenote-growing-threat-malware-distribution
author: Florian Roth (Nextron Systems), Hieu Tran
date: 2023-03-13
modified: 2025-07-18
tags:
    - attack.command-and-control
    - attack.execution
    - attack.t1059.001
    - attack.t1105
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        CommandLine|contains:
            - 'Invoke-RestMethod '
            - 'Invoke-WebRequest '
            - 'IRM '
            - 'IWR '
        CommandLine|contains|all:
            - 'http'
            - 'OutFile'
            - '.dll'
    condition: selection
falsepositives:
    - Unknown
level: medium
```
