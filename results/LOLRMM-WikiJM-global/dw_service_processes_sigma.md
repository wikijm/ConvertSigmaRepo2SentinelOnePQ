```sql
// Translated content (automatically translated on 22-12-2025 01:49:27):
event.type="Process Creation" and (endpoint.os="windows" and (src.process.image.path contains "dwagsvc.exe" or src.process.image.path contains "dwagent.exe"))
```


# Original Sigma Rule:
```yaml
title: Potential DW Service RMM Tool Process Activity
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    ParentImage|endswith:
    - dwagsvc.exe
    - dwagent.exe
  condition: selection
id: 5652feeb-de11-4703-a3fb-1d43fc633ebc
status: experimental
description: Detects potential processes activity of DW Service RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of DW Service
level: medium
```
