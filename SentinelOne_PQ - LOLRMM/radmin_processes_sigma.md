```sql
// Translated content (automatically translated on 22-12-2025 00:58:15):
event.type="Process Creation" and (endpoint.os="windows" and ((src.process.image.path contains "Radmin.exe" or src.process.image.path contains "rserver3.exe") or (tgt.process.image.path contains "Radmin.exe" or tgt.process.image.path contains "rserver3.exe")))
```


# Original Sigma Rule:
```yaml
title: Potential RAdmin RMM Tool Process Activity
id: c1830a71-6799-4206-98f6-225a833a569c
status: experimental
description: |
    Detects potential processes activity of RAdmin RMM tool
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
            - Radmin.exe
            - rserver3.exe
    selection_image:
        Image|endswith:
            - Radmin.exe
            - rserver3.exe
    condition: 1 of selection_*
falsepositives:
    - Legitimate use of RAdmin
level: medium
```
