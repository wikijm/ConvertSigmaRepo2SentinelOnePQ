```sql
// Translated content (automatically translated on 22-12-2025 00:58:15):
event.type="Process Creation" and (endpoint.os="windows" and ((src.process.image.path contains "rpcnet.exe" or src.process.image.path contains "ctes.exe" or src.process.image.path contains "ctespersitence.exe" or src.process.image.path contains "cteshostsvc.exe" or src.process.image.path contains "rpcld.exe") or (tgt.process.image.path contains "rpcnet.exe" or tgt.process.image.path contains "ctes.exe" or tgt.process.image.path contains "ctespersitence.exe" or tgt.process.image.path contains "cteshostsvc.exe" or tgt.process.image.path contains "rpcld.exe")))
```


# Original Sigma Rule:
```yaml
title: Potential Absolute (Computrace) RMM Tool Process Activity
id: 6633e0fe-00b0-4441-a635-35318721392f
status: experimental
description: |
    Detects potential processes activity of Absolute (Computrace) RMM tool
references:
    - https://github.com/magicsword-io/LOLRMM
author: LOLRMM Project
date: 2025-12-01
tags:
    - attack.execution
    - attack.t1219
logsource:
    product: windows
    category: process_creation
detection:
    selection_parent:
        ParentImage|endswith:
            - rpcnet.exe
            - ctes.exe
            - ctespersitence.exe
            - cteshostsvc.exe
            - rpcld.exe
    selection_image:
        Image|endswith:
            - rpcnet.exe
            - ctes.exe
            - ctespersitence.exe
            - cteshostsvc.exe
            - rpcld.exe
    condition: 1 of selection_*
falsepositives:
    - Legitimate use of Absolute (Computrace)
level: medium
```
