```sql
// Translated content (automatically translated on 21-02-2026 02:02:28):
event.type="Process Creation" and (endpoint.os="windows" and (src.process.image.path contains "PCIVIDEO.EXE" or src.process.image.path contains "supporttool.exe"))
```


# Original Sigma Rule:
```yaml
title: Potential CrossTec Remote Control RMM Tool Process Activity
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    ParentImage|endswith:
    - PCIVIDEO.EXE
    - supporttool.exe
  condition: selection
id: 97b2d8e4-652c-4722-b268-c21395609fbc
status: experimental
description: Detects potential processes activity of CrossTec Remote Control RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of CrossTec Remote Control
level: medium
```
