```sql
// Translated content (automatically translated on 22-12-2025 00:58:15):
event.type="Process Creation" and (endpoint.os="windows" and ((src.process.image.path contains "remobo.exe" or src.process.image.path contains "remobo_client.exe" or src.process.image.path contains "remobo_tracker.exe") or (tgt.process.image.path contains "remobo.exe" or tgt.process.image.path contains "remobo_client.exe" or tgt.process.image.path contains "remobo_tracker.exe")))
```


# Original Sigma Rule:
```yaml
title: Potential Remobo RMM Tool Process Activity
id: d9e4fe5b-446f-4ae5-9852-d3ccb4ef1b59
status: experimental
description: |
    Detects potential processes activity of Remobo RMM tool
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
            - remobo.exe
            - remobo_client.exe
            - remobo_tracker.exe
    selection_image:
        Image|endswith:
            - remobo.exe
            - remobo_client.exe
            - remobo_tracker.exe
    condition: 1 of selection_*
falsepositives:
    - Legitimate use of Remobo
level: medium
```
