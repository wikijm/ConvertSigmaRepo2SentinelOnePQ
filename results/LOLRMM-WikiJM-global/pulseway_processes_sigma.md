```sql
// Translated content (automatically translated on 22-12-2025 01:49:27):
event.type="Process Creation" and (endpoint.os="windows" and (src.process.image.path contains "PCMonitorManager.exe" or src.process.image.path contains "pcmonitorsrv.exe"))
```


# Original Sigma Rule:
```yaml
title: Potential Pulseway RMM Tool Process Activity
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    ParentImage|endswith:
    - PCMonitorManager.exe
    - pcmonitorsrv.exe
  condition: selection
id: 930a0b94-5ff4-4d7d-a8cc-dfd1d4f9c489
status: experimental
description: Detects potential processes activity of Pulseway RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of Pulseway
level: medium
```
