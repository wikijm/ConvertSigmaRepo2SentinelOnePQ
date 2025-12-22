```sql
// Translated content (automatically translated on 22-12-2025 00:58:15):
event.type="Process Creation" and (endpoint.os="windows" and ((src.process.image.path contains "royalserver.exe" or src.process.image.path contains "royalts.exe") or (tgt.process.image.path contains "royalserver.exe" or tgt.process.image.path contains "royalts.exe")))
```


# Original Sigma Rule:
```yaml
title: Potential Royal Apps RMM Tool Process Activity
id: 11d5df2c-21ac-4493-9ee7-d3b851c792bd
status: experimental
description: |
    Detects potential processes activity of Royal Apps RMM tool
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
            - royalserver.exe
            - royalts.exe
    selection_image:
        Image|endswith:
            - royalserver.exe
            - royalts.exe
    condition: 1 of selection_*
falsepositives:
    - Legitimate use of Royal Apps
level: medium
```
