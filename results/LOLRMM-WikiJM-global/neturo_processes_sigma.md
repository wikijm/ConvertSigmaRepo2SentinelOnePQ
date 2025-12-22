```sql
// Translated content (automatically translated on 22-12-2025 01:49:27):
event.type="Process Creation" and (endpoint.os="windows" and (src.process.image.path="*neturo*.exe" or src.process.image.path contains "ntrntservice.exe" or src.process.image.path contains "neturo.exe"))
```


# Original Sigma Rule:
```yaml
title: Potential Neturo RMM Tool Process Activity
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    ParentImage|endswith:
    - neturo*.exe
    - ntrntservice.exe
    - neturo.exe
  condition: selection
id: 229b9923-a34d-4c65-b024-2160ed14557e
status: experimental
description: Detects potential processes activity of Neturo RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of Neturo
level: medium
```
