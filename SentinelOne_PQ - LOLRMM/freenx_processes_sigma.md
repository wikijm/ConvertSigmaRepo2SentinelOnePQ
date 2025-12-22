```sql
// Translated content (automatically translated on 22-12-2025 00:58:15):
event.type="Process Creation" and (endpoint.os="windows" and ((src.process.image.path contains "nxplayer.exe" or src.process.image.path contains "nxplayer.exe") or (tgt.process.image.path contains "nxplayer.exe" or tgt.process.image.path contains "nxplayer.exe")))
```


# Original Sigma Rule:
```yaml
title: Potential FreeNX RMM Tool Process Activity
id: 4c8f7191-0e4f-4083-9de9-b710c879543a
status: experimental
description: |
    Detects potential processes activity of FreeNX RMM tool
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
            - nxplayer.exe
            - nxplayer.exe
    selection_image:
        Image|endswith:
            - nxplayer.exe
            - nxplayer.exe
    condition: 1 of selection_*
falsepositives:
    - Legitimate use of FreeNX
level: medium
```
