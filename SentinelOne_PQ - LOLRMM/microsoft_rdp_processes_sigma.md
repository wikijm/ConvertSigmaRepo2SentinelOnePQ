```sql
// Translated content (automatically translated on 22-12-2025 00:58:15):
event.type="Process Creation" and (endpoint.os="windows" and ((src.process.image.path contains "termsrv.exe" or src.process.image.path contains "mstsc.exe") or (tgt.process.image.path contains "termsrv.exe" or tgt.process.image.path contains "mstsc.exe")))
```


# Original Sigma Rule:
```yaml
title: Potential Microsoft RDP RMM Tool Process Activity
id: 4122da1c-0f56-4d24-bcb4-afc2dc3f82b3
status: experimental
description: |
    Detects potential processes activity of Microsoft RDP RMM tool
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
    - Legitimate use of Microsoft RDP
level: medium
```
