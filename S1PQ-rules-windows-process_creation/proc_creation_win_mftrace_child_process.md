```sql
// Translated content (automatically translated on 22-12-2025 02:21:40):
event.type="Process Creation" and (endpoint.os="windows" and src.process.image.path contains "\\mftrace.exe")
```


# Original Sigma Rule:
```yaml
title: Potential Mftrace.EXE Abuse
id: 3d48c9d3-1aa6-418d-98d3-8fd3c01a564e
status: test
description: Detects child processes of the "Trace log generation tool for Media Foundation Tools" (Mftrace.exe) which can abused to execute arbitrary binaries.
references:
    - https://lolbas-project.github.io/lolbas/OtherMSBinaries/Mftrace/
author: Nasreddine Bencherchali (Nextron Systems)
date: 2022-06-09
modified: 2023-08-03
tags:
    - attack.defense-evasion
    - attack.t1127
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        ParentImage|endswith: '\mftrace.exe'
    condition: selection
falsepositives:
    - Legitimate use for tracing purposes
level: medium
```
