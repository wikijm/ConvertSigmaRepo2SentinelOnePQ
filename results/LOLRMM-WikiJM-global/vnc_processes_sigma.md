```sql
// Translated content (automatically translated on 22-12-2025 01:49:27):
event.type="Process Creation" and (endpoint.os="windows" and (src.process.image.path="*winvnc*.exe" or src.process.image.path contains "vncserver.exe" or src.process.image.path contains "winwvc.exe" or src.process.image.path contains "winvncsc.exe" or src.process.image.path contains "vncserverui.exe" or src.process.image.path contains "vncviewer.exe" or src.process.image.path contains "winvnc.exe"))
```


# Original Sigma Rule:
```yaml
title: Potential VNC RMM Tool Process Activity
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    ParentImage|endswith:
    - winvnc*.exe
    - vncserver.exe
    - winwvc.exe
    - winvncsc.exe
    - vncserverui.exe
    - vncviewer.exe
    - winvnc.exe
  condition: selection
id: 3a2aba3d-58ca-43c5-b15c-9b7bc17d3257
status: experimental
description: Detects potential processes activity of VNC RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of VNC
level: medium
```
