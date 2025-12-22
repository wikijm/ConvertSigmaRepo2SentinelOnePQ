```sql
// Translated content (automatically translated on 22-12-2025 00:58:15):
event.type="Process Creation" and (endpoint.os="windows" and (src.process.image.path contains "C:\*\\DriveMaker.exe" or src.process.image.path contains "\\DriveMaker.exe"))
```


# Original Sigma Rule:
```yaml
title: Potential DriveMaker RMM Tool Process Activity
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    ParentImage|endswith:
    - C:\*\DriveMaker.exe
    - '*\DriveMaker.exe'
  condition: selection
id: 51338b36-de22-4824-9de4-04ef3d67da26
status: experimental
description: Detects potential processes activity of DriveMaker RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of DriveMaker
level: medium
```
