```sql
// Translated content (automatically translated on 22-12-2025 00:58:15):
event.type="Process Creation" and (endpoint.os="windows" and ((src.process.image.path contains "termsrv.exe" or src.process.image.path contains "mstsc.exe") or (tgt.process.image.path contains "termsrv.exe" or tgt.process.image.path contains "mstsc.exe")))
```


# Original Sigma Rule:
```yaml
title: Potential Microsoft TSC RMM Tool Process Activity
id: ea9f6f7d-1757-460a-906d-53d0ba6e422a
status: experimental
description: |
    Detects potential processes activity of Microsoft TSC RMM tool
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
            - termsrv.exe
            - mstsc.exe
    selection_image:
        Image|endswith:
            - termsrv.exe
            - mstsc.exe
    condition: 1 of selection_*
falsepositives:
    - Legitimate use of Microsoft TSC
level: medium
```
