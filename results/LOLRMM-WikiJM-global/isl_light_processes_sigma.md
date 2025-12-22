```sql
// Translated content (automatically translated on 22-12-2025 01:49:27):
event.type="Process Creation" and (endpoint.os="windows" and (src.process.image.path contains "islalwaysonmonitor.exe" or src.process.image.path contains "isllight.exe" or src.process.image.path contains "isllightservice.exe"))
```


# Original Sigma Rule:
```yaml
title: Potential ISL Light RMM Tool Process Activity
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    ParentImage|endswith:
    - islalwaysonmonitor.exe
    - isllight.exe
    - isllightservice.exe
  condition: selection
id: 28dff07b-24d9-454b-a219-d096ed081c61
status: experimental
description: Detects potential processes activity of ISL Light RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of ISL Light
level: medium
```
