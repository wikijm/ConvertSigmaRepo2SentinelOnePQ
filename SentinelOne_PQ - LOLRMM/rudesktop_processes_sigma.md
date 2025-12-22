```sql
// Translated content (automatically translated on 22-12-2025 00:58:15):
event.type="Process Creation" and (endpoint.os="windows" and ((src.process.image.path contains "rd.exe" or src.process.image.path="*rudesktop*.exe") or (tgt.process.image.path contains "rd.exe" or tgt.process.image.path="*rudesktop*.exe")))
```


# Original Sigma Rule:
```yaml
title: Potential RuDesktop RMM Tool Process Activity
id: e515e095-e65b-420e-9843-e2a3528233bb
status: experimental
description: |
    Detects potential processes activity of RuDesktop RMM tool
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
            - rd.exe
            - rudesktop*.exe
    selection_image:
        Image|endswith:
            - rd.exe
            - rudesktop*.exe
    condition: 1 of selection_*
falsepositives:
    - Legitimate use of RuDesktop
level: medium
```
