```sql
// Translated content (automatically translated on 22-12-2025 00:58:15):
event.type="Process Creation" and (endpoint.os="windows" and ((src.process.image.path contains "itsmagent.exe" or src.process.image.path contains "rviewer.exe") or (tgt.process.image.path contains "itsmagent.exe" or tgt.process.image.path contains "rviewer.exe")))
```


# Original Sigma Rule:
```yaml
title: Potential Comodo RMM RMM Tool Process Activity
id: 92cb2669-b3c5-4664-a253-ca98a906a085
status: experimental
description: |
    Detects potential processes activity of Comodo RMM RMM tool
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
            - itsmagent.exe
            - rviewer.exe
    selection_image:
        Image|endswith:
            - itsmagent.exe
            - rviewer.exe
    condition: 1 of selection_*
falsepositives:
    - Legitimate use of Comodo RMM
level: medium
```
