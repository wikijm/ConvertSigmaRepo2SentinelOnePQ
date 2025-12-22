```sql
// Translated content (automatically translated on 22-12-2025 00:58:15):
event.type="Process Creation" and (endpoint.os="windows" and ((src.process.image.path contains "islalwaysonmonitor.exe" or src.process.image.path contains "isllight.exe" or src.process.image.path contains "isllightservice.exe" or src.process.image.path contains "ISLLightClient.exe" or src.process.image.path contains "ISLLight.exe") or (tgt.process.image.path contains "islalwaysonmonitor.exe" or tgt.process.image.path contains "isllight.exe" or tgt.process.image.path contains "isllightservice.exe" or tgt.process.image.path contains "ISLLightClient.exe" or tgt.process.image.path contains "ISLLight.exe")))
```


# Original Sigma Rule:
```yaml
title: Potential ISL Online RMM Tool Process Activity
id: eb9d5ff4-9478-4edd-b83f-daa9eb04d756
status: experimental
description: |
    Detects potential processes activity of ISL Online RMM tool
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
            - ISLLightClient.exe
            - ISLLight.exe
    selection_image:
        Image|endswith:
            - islalwaysonmonitor.exe
            - isllight.exe
            - isllightservice.exe
            - ISLLightClient.exe
            - ISLLight.exe
    condition: 1 of selection_*
falsepositives:
    - Legitimate use of ISL Online
level: medium
```
