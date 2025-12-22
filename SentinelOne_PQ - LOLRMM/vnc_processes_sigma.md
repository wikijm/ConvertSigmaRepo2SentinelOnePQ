```sql
// Translated content (automatically translated on 22-12-2025 00:58:15):
event.type="Process Creation" and (endpoint.os="windows" and ((src.process.image.path="*winvnc*.exe" or src.process.image.path contains "vncserver.exe" or src.process.image.path contains "winwvc.exe" or src.process.image.path contains "winvncsc.exe" or src.process.image.path contains "vncserverui.exe" or src.process.image.path contains "vncviewer.exe" or src.process.image.path contains "winvnc.exe") or (tgt.process.image.path="*winvnc*.exe" or tgt.process.image.path contains "vncserver.exe" or tgt.process.image.path contains "winwvc.exe" or tgt.process.image.path contains "winvncsc.exe" or tgt.process.image.path contains "vncserverui.exe" or tgt.process.image.path contains "vncviewer.exe" or tgt.process.image.path contains "winvnc.exe")))
```


# Original Sigma Rule:
```yaml
title: Potential VNC RMM Tool Process Activity
id: 09723726-df0c-4154-bb05-7b810b6c6c40
status: experimental
description: |
    Detects potential processes activity of VNC RMM tool
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
            - winvnc*.exe
            - vncserver.exe
            - winwvc.exe
            - winvncsc.exe
            - vncserverui.exe
            - vncviewer.exe
            - winvnc.exe
    selection_image:
        Image|endswith:
            - winvnc*.exe
            - vncserver.exe
            - winwvc.exe
            - winvncsc.exe
            - vncserverui.exe
            - vncviewer.exe
            - winvnc.exe
    condition: 1 of selection_*
falsepositives:
    - Legitimate use of VNC
level: medium
```
