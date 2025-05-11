```sql
// Translated content (automatically translated on 11-05-2025 00:54:56):
event.type="Process Creation" and (endpoint.os="windows" and (src.process.image.path contains "myivomgr.exe" or src.process.image.path contains "myivomanager.exe"))
```


# Original Sigma Rule:
```yaml
title: Potential MyIVO RMM Tool Process Activity
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    ParentImage|endswith:
    - myivomgr.exe
    - myivomanager.exe
  condition: selection
id: ebbf3afb-cee4-4024-8da8-48e156b003d1
status: experimental
description: Detects potential processes activity of MyIVO RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of MyIVO
level: medium
```
