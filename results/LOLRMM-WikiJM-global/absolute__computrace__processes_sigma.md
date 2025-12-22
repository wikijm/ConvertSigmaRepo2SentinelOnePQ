```sql
// Translated content (automatically translated on 22-12-2025 01:49:27):
event.type="Process Creation" and (endpoint.os="windows" and (src.process.image.path contains "rpcnet.exe" or src.process.image.path contains "ctes.exe" or src.process.image.path contains "ctespersitence.exe" or src.process.image.path contains "cteshostsvc.exe" or src.process.image.path contains "rpcld.exe"))
```


# Original Sigma Rule:
```yaml
title: Potential Absolute (Computrace) RMM Tool Process Activity
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    ParentImage|endswith:
    - rpcnet.exe
    - ctes.exe
    - ctespersitence.exe
    - cteshostsvc.exe
    - rpcld.exe
  condition: selection
id: f263b53c-1907-43ec-b69a-d81d3abeeb7e
status: experimental
description: Detects potential processes activity of Absolute (Computrace) RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of Absolute (Computrace)
level: medium
```
