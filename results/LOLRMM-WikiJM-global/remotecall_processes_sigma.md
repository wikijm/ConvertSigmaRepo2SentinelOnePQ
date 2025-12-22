```sql
// Translated content (automatically translated on 22-12-2025 01:49:27):
event.type="Process Creation" and (endpoint.os="windows" and (src.process.image.path contains "rcengmgru.exe" or src.process.image.path contains "rcmgrsvc.exe" or src.process.image.path contains "rxstartsupport.exe" or src.process.image.path contains "rcstartsupport.exe" or src.process.image.path contains "raautoup.exe" or src.process.image.path contains "agentu.exe" or src.process.image.path contains "remotesupportplayeru.exe"))
```


# Original Sigma Rule:
```yaml
title: Potential RemoteCall RMM Tool Process Activity
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    ParentImage|endswith:
    - rcengmgru.exe
    - rcmgrsvc.exe
    - rxstartsupport.exe
    - rcstartsupport.exe
    - raautoup.exe
    - agentu.exe
    - remotesupportplayeru.exe
  condition: selection
id: 31a0b59a-c838-485a-8e60-c8d428f1c812
status: experimental
description: Detects potential processes activity of RemoteCall RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of RemoteCall
level: medium
```
