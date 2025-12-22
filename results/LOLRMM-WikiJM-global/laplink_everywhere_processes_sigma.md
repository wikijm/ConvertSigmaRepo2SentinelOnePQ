```sql
// Translated content (automatically translated on 22-12-2025 01:49:27):
event.type="Process Creation" and (endpoint.os="windows" and (src.process.image.path contains "laplink.exe" or src.process.image.path="*laplink-everywhere-setup*.exe" or src.process.image.path contains "laplinkeverywhere.exe" or src.process.image.path contains "llrcservice.exe" or src.process.image.path contains "serverproxyservice.exe" or src.process.image.path contains "OOSysAgent.exe"))
```


# Original Sigma Rule:
```yaml
title: Potential Laplink Everywhere RMM Tool Process Activity
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    ParentImage|endswith:
    - laplink.exe
    - laplink-everywhere-setup*.exe
    - laplinkeverywhere.exe
    - llrcservice.exe
    - serverproxyservice.exe
    - OOSysAgent.exe
  condition: selection
id: 556a0418-03d1-42de-b217-68bf2856e15d
status: experimental
description: Detects potential processes activity of Laplink Everywhere RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of Laplink Everywhere
level: medium
```
