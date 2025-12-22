```sql
// Translated content (automatically translated on 22-12-2025 01:49:27):
event.type="Process Creation" and (endpoint.os="windows" and (src.process.image.path contains "hoptodesk.exe" or src.process.image.path contains "HopToDesk.exe"))
```


# Original Sigma Rule:
```yaml
title: Potential HopToDesk RMM Tool Process Activity
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    ParentImage|endswith:
    - hoptodesk.exe
    - HopToDesk.exe
  condition: selection
status: experimental
description: Detects potential processes activity of HopToDesk RMM tool
author: LOLRMM Project
date: 2024/09/19
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of HopToDesk
level: medium```
