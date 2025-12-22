```sql
// Translated content (automatically translated on 22-12-2025 00:58:15):
event.type="Process Creation" and (endpoint.os="windows" and ((src.process.image.path contains "islalwaysonmonitor.exe" or src.process.image.path contains "isllight.exe" or src.process.image.path contains "isllightservice.exe") or (tgt.process.image.path contains "islalwaysonmonitor.exe" or tgt.process.image.path contains "isllight.exe" or tgt.process.image.path contains "isllightservice.exe")))
```


# Original Sigma Rule:
```yaml
title: Potential ISL Light RMM Tool Process Activity
id: e825422e-f5da-4849-b0d1-47698c45ee7a
status: experimental
description: |
    Detects potential processes activity of ISL Light RMM tool
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
            - islalwaysonmonitor.exe
            - isllight.exe
            - isllightservice.exe
    selection_image:
        Image|endswith:
            - islalwaysonmonitor.exe
            - isllight.exe
            - isllightservice.exe
    condition: 1 of selection_*
falsepositives:
    - Legitimate use of ISL Light
level: medium
```
