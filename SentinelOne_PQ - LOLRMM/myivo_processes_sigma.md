```sql
// Translated content (automatically translated on 22-12-2025 00:58:15):
event.type="Process Creation" and (endpoint.os="windows" and ((src.process.image.path contains "myivomgr.exe" or src.process.image.path contains "myivomanager.exe") or (tgt.process.image.path contains "myivomgr.exe" or tgt.process.image.path contains "myivomanager.exe")))
```


# Original Sigma Rule:
```yaml
title: Potential MyIVO RMM Tool Process Activity
id: 4af16164-365b-47f0-9b15-37ad38073d3a
status: experimental
description: |
    Detects potential processes activity of MyIVO RMM tool
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
            - myivomgr.exe
            - myivomanager.exe
    selection_image:
        Image|endswith:
            - myivomgr.exe
            - myivomanager.exe
    condition: 1 of selection_*
falsepositives:
    - Legitimate use of MyIVO
level: medium
```
