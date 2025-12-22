```sql
// Translated content (automatically translated on 22-12-2025 00:58:15):
event.type="Process Creation" and (endpoint.os="windows" and ((src.process.image.path contains "rutview.exe" or src.process.image.path contains "rutserv.exe") or (tgt.process.image.path contains "rutview.exe" or tgt.process.image.path contains "rutserv.exe")))
```


# Original Sigma Rule:
```yaml
title: Potential Remote Utilities RMM Tool Process Activity
id: 2fb25913-43b1-485e-99ee-da7ca21fd75f
status: experimental
description: |
    Detects potential processes activity of Remote Utilities RMM tool
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
            - rutview.exe
            - rutserv.exe
    selection_image:
        Image|endswith:
            - rutview.exe
            - rutserv.exe
    condition: 1 of selection_*
falsepositives:
    - Legitimate use of Remote Utilities
level: medium
```
