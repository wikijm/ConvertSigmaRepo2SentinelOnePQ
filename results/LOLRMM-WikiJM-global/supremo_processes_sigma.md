```sql
// Translated content (automatically translated on 22-12-2025 01:49:27):
event.type="Process Creation" and (endpoint.os="windows" and (src.process.image.path contains "supremo.exe" or src.process.image.path contains "supremoservice.exe" or src.process.image.path contains "supremosystem.exe" or src.process.image.path contains "supremohelper.exe"))
```


# Original Sigma Rule:
```yaml
title: Potential Supremo RMM Tool Process Activity
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    ParentImage|endswith:
    - supremo.exe
    - supremoservice.exe
    - supremosystem.exe
    - supremohelper.exe
  condition: selection
id: d00d2571-88c6-459e-a2e1-6c928b6be5e5
status: experimental
description: Detects potential processes activity of Supremo RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of Supremo
level: medium
```
