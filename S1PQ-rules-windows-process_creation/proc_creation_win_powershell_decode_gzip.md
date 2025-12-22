```sql
// Translated content (automatically translated on 22-12-2025 02:21:40):
event.type="Process Creation" and (endpoint.os="windows" and (tgt.process.cmdline contains "GZipStream" and tgt.process.cmdline contains "::Decompress"))
```


# Original Sigma Rule:
```yaml
title: Gzip Archive Decode Via PowerShell
id: 98767d61-b2e8-4d71-b661-e36783ee24c1
status: test
description: Detects attempts of decoding encoded Gzip archives via PowerShell.
references:
    - https://www.zscaler.com/blogs/security-research/onenote-growing-threat-malware-distribution
author: Hieu Tran
date: 2023-03-13
tags:
    - attack.command-and-control
    - attack.t1132.001
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        CommandLine|contains|all:
            - 'GZipStream'
            - '::Decompress'
    condition: selection
falsepositives:
    - Legitimate administrative scripts may use this functionality. Use "ParentImage" in combination with the script names and allowed users and applications to filter legitimate executions
level: medium
```
