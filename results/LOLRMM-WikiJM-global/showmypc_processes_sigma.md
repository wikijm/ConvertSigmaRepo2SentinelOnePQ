```sql
// Translated content (automatically translated on 22-12-2025 01:49:27):
event.type="Process Creation" and (endpoint.os="windows" and (src.process.image.path contains "SMPCSetup.exe" or src.process.image.path="*showmypc*.exe" or src.process.image.path contains "showmypc.exe" or src.process.image.path contains "smpcsetup.exe"))
```


# Original Sigma Rule:
```yaml
title: Potential ShowMyPC RMM Tool Process Activity
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    ParentImage|endswith:
    - SMPCSetup.exe
    - showmypc*.exe
    - showmypc.exe
    - smpcsetup.exe
  condition: selection
id: d4ccc591-a330-4be4-bbf1-f2168cdfb166
status: experimental
description: Detects potential processes activity of ShowMyPC RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of ShowMyPC
level: medium
```
