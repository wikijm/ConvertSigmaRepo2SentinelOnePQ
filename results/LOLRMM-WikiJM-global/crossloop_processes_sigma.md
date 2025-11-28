```sql
// Translated content (automatically translated on 28-11-2025 01:37:18):
event.type="Process Creation" and (endpoint.os="windows" and (src.process.image.path contains "crossloopservice.exe" or src.process.image.path contains "CrossLoopConnect.exe" or src.process.image.path contains "WinVNCStub.exe"))
```


# Original Sigma Rule:
```yaml
title: Potential CrossLoop RMM Tool Process Activity
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    ParentImage|endswith:
    - crossloopservice.exe
    - CrossLoopConnect.exe
    - WinVNCStub.exe
  condition: selection
id: 22118921-1c0d-4211-a037-538710fa0107
status: experimental
description: Detects potential processes activity of CrossLoop RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of CrossLoop
level: medium
```
