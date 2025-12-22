```sql
// Translated content (automatically translated on 22-12-2025 00:58:15):
event.type="Process Creation" and (endpoint.os="windows" and ((src.process.image.path contains "OrayRemoteShell.exe" or src.process.image.path contains "OrayRemoteService.exe" or src.process.image.path="*sunlogin*.exe") or (tgt.process.image.path contains "OrayRemoteShell.exe" or tgt.process.image.path contains "OrayRemoteService.exe" or tgt.process.image.path="*sunlogin*.exe")))
```


# Original Sigma Rule:
```yaml
title: Potential SunLogin RMM Tool Process Activity
id: e3facbfa-0474-406e-a800-91a4ddf1b08e
status: experimental
description: |
    Detects potential processes activity of SunLogin RMM tool
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
            - OrayRemoteShell.exe
            - OrayRemoteService.exe
            - sunlogin*.exe
    selection_image:
        Image|endswith:
            - OrayRemoteShell.exe
            - OrayRemoteService.exe
            - sunlogin*.exe
    condition: 1 of selection_*
falsepositives:
    - Legitimate use of SunLogin
level: medium
```
