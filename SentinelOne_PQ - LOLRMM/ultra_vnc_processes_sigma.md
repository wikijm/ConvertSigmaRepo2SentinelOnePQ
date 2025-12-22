```sql
// Translated content (automatically translated on 22-12-2025 00:58:15):
event.type="Process Creation" and (endpoint.os="windows" and ((src.process.image.path contains "UVNC_Launch.exe" or src.process.image.path contains "winvnc.exe" or src.process.image.path contains "vncviewer.exe") or (tgt.process.image.path contains "UVNC_Launch.exe" or tgt.process.image.path contains "winvnc.exe" or tgt.process.image.path contains "vncviewer.exe")))
```


# Original Sigma Rule:
```yaml
title: Potential Ultra VNC RMM Tool Process Activity
id: d43e0555-49c5-4a10-bdda-7ed790de78e8
status: experimental
description: |
    Detects potential processes activity of Ultra VNC RMM tool
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
            - UVNC_Launch.exe
            - winvnc.exe
            - vncviewer.exe
    selection_image:
        Image|endswith:
            - UVNC_Launch.exe
            - winvnc.exe
            - vncviewer.exe
    condition: 1 of selection_*
falsepositives:
    - Legitimate use of Ultra VNC
level: medium
```
