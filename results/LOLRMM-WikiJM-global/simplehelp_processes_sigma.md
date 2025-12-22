```sql
// Translated content (automatically translated on 22-12-2025 01:49:27):
event.type="Process Creation" and (endpoint.os="windows" and (src.process.image.path contains "simplehelpcustomer.exe" or src.process.image.path contains "simpleservice.exe" or src.process.image.path contains "simplegatewayservice.exe" or src.process.image.path contains "remote access.exe" or src.process.image.path contains "windowslauncher.exe"))
```


# Original Sigma Rule:
```yaml
title: Potential SimpleHelp RMM Tool Process Activity
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    ParentImage|endswith:
    - simplehelpcustomer.exe
    - simpleservice.exe
    - simplegatewayservice.exe
    - remote access.exe
    - windowslauncher.exe
  condition: selection
id: a9f963f8-d1f7-482e-a72d-d61ba2a8cfd5
status: experimental
description: Detects potential processes activity of SimpleHelp RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of SimpleHelp
level: medium
```
