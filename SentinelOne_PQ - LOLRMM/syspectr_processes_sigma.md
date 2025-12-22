```sql
// Translated content (automatically translated on 22-12-2025 00:58:15):
event.type="Process Creation" and (endpoint.os="windows" and ((src.process.image.path="*oo-syspectr*.exe" or src.process.image.path contains "OOSysAgent.exe") or (tgt.process.image.path="*oo-syspectr*.exe" or tgt.process.image.path contains "OOSysAgent.exe")))
```


# Original Sigma Rule:
```yaml
title: Potential Syspectr RMM Tool Process Activity
id: 791169bf-9cc5-4962-a177-a4dd9d5efd07
status: experimental
description: |
    Detects potential processes activity of Syspectr RMM tool
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
            - oo-syspectr*.exe
            - OOSysAgent.exe
    selection_image:
        Image|endswith:
            - oo-syspectr*.exe
            - OOSysAgent.exe
    condition: 1 of selection_*
falsepositives:
    - Legitimate use of Syspectr
level: medium
```
