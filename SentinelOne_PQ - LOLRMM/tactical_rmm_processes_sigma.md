```sql
// Translated content (automatically translated on 22-12-2025 00:58:15):
event.type="Process Creation" and (endpoint.os="windows" and ((src.process.image.path contains "tacticalrmm.exe" or src.process.image.path contains "tacticalrmm.exe") or (tgt.process.image.path contains "tacticalrmm.exe" or tgt.process.image.path contains "tacticalrmm.exe")))
```


# Original Sigma Rule:
```yaml
title: Potential Tactical RMM RMM Tool Process Activity
id: 77e5402e-b561-43ea-9203-963763b5609e
status: experimental
description: |
    Detects potential processes activity of Tactical RMM RMM tool
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
            - tacticalrmm.exe
            - tacticalrmm.exe
    selection_image:
        Image|endswith:
            - tacticalrmm.exe
            - tacticalrmm.exe
    condition: 1 of selection_*
falsepositives:
    - Legitimate use of Tactical RMM
level: medium
```
