```sql
// Translated content (automatically translated on 22-12-2025 01:49:27):
event.type="Process Creation" and (endpoint.os="windows" and (src.process.image.path contains "islalwaysonmonitor.exe" or src.process.image.path contains "isllight.exe" or src.process.image.path contains "isllightservice.exe" or src.process.image.path contains "ISLLightClient.exe" or src.process.image.path contains "\\ISLLight.exe"))
```


# Original Sigma Rule:
```yaml
title: Potential ISL Online RMM Tool Process Activity
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    ParentImage|endswith:
    - islalwaysonmonitor.exe
    - isllight.exe
    - isllightservice.exe
    - ISLLightClient.exe
    - '*\ISLLight.exe'
  condition: selection
id: 377c9711-2892-4ed8-b90e-ebcb8bc0cfdd
status: experimental
description: Detects potential processes activity of ISL Online RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of ISL Online
level: medium
```
