```sql
// Translated content (automatically translated on 22-12-2025 00:58:15):
event.type="Process Creation" and (endpoint.os="windows" and ((src.process.image.path="*nomachine*.exe" or src.process.image.path contains "nxd.exe") or (tgt.process.image.path="*nomachine*.exe" or tgt.process.image.path contains "nxd.exe")))
```


# Original Sigma Rule:
```yaml
title: Potential NoMachine RMM Tool Process Activity
id: 7b453f55-095c-4729-94f7-1739c63eca61
status: experimental
description: |
    Detects potential processes activity of NoMachine RMM tool
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
            - nomachine*.exe
            - nxd.exe
    selection_image:
        Image|endswith:
            - nomachine*.exe
            - nxd.exe
    condition: 1 of selection_*
falsepositives:
    - Legitimate use of NoMachine
level: medium
```
