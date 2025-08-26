```sql
// Translated content (automatically translated on 26-08-2025 00:50:57):
event.type="Process Creation" and (endpoint.os="windows" and src.process.image.path contains "rdp.exe")
```


# Original Sigma Rule:
```yaml
title: Potential Remote Desktop Plus RMM Tool Process Activity
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    ParentImage|endswith:
    - rdp.exe
  condition: selection
id: 628b038a-8b36-481f-be3d-4ca385aea7be
status: experimental
description: Detects potential processes activity of Remote Desktop Plus RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of Remote Desktop Plus
level: medium
```
