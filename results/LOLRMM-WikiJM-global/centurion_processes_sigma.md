```sql
// Translated content (automatically translated on 02-08-2025 01:45:23):
event.type="Process Creation" and (endpoint.os="windows" and src.process.image.path contains "ctiserv.exe")
```


# Original Sigma Rule:
```yaml
title: Potential Centurion RMM Tool Process Activity
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    ParentImage|endswith:
    - ctiserv.exe
  condition: selection
id: 34de100b-becb-4364-9a9d-a325dae08231
status: experimental
description: Detects potential processes activity of Centurion RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of Centurion
level: medium
```
