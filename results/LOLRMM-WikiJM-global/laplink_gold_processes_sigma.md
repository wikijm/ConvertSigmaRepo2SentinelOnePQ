```sql
// Translated content (automatically translated on 02-08-2025 01:45:23):
event.type="Process Creation" and (endpoint.os="windows" and (src.process.image.path contains "tsircusr.exe" or src.process.image.path contains "laplink.exe"))
```


# Original Sigma Rule:
```yaml
title: Potential Laplink Gold RMM Tool Process Activity
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    ParentImage|endswith:
    - tsircusr.exe
    - laplink.exe
  condition: selection
id: 2cc6e670-7511-4bf0-b36f-b1079e7f8a24
status: experimental
description: Detects potential processes activity of Laplink Gold RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of Laplink Gold
level: medium
```
