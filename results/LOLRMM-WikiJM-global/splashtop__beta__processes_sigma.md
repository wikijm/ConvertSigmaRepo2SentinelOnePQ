```sql
// Translated content (automatically translated on 22-12-2025 01:49:27):
event.type="Process Creation" and (endpoint.os="windows" and (src.process.image.path contains "SRServer.exe" or src.process.image.path contains "SplashtopSOS.exe" or src.process.image.path="*Splashtop_Streamer_Windows*.exe" or src.process.image.path contains "SRManager.exe"))
```


# Original Sigma Rule:
```yaml
title: Potential Splashtop (Beta) RMM Tool Process Activity
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    ParentImage|endswith:
    - SRServer.exe
    - SplashtopSOS.exe
    - Splashtop_Streamer_Windows*.exe
    - SRManager.exe
  condition: selection
id: e6c17068-b536-42b3-836e-23bb280bc9ed
status: experimental
description: Detects potential processes activity of Splashtop (Beta) RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of Splashtop (Beta)
level: medium
```
