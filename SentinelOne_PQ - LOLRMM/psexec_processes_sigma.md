```sql
// Translated content (automatically translated on 22-12-2025 00:58:15):
event.type="Process Creation" and (endpoint.os="windows" and ((src.process.image.path contains "psexec.exe" or src.process.image.path contains "psexecsvc.exe") or (tgt.process.image.path contains "psexec.exe" or tgt.process.image.path contains "psexecsvc.exe")))
```


# Original Sigma Rule:
```yaml
title: Potential PSEXEC RMM Tool Process Activity
id: 411e84d4-b1af-418c-b1b0-83b09e8ada35
status: experimental
description: |
    Detects potential processes activity of PSEXEC RMM tool
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
            - psexec.exe
            - psexecsvc.exe
    selection_image:
        Image|endswith:
            - psexec.exe
            - psexecsvc.exe
    condition: 1 of selection_*
falsepositives:
    - Legitimate use of PSEXEC
level: medium
```
